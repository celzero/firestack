// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//	MIT License
//
//	Copyright (c) 2018 eycorsican
//
//	Permission is hereby granted, free of charge, to any person obtaining a copy
//	of this software and associated documentation files (the "Software"), to deal
//	in the Software without restriction, including without limitation the rights
//	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//	copies of the Software, and to permit persons to whom the Software is
//	furnished to do so, subject to the following conditions:
//
//	The above copyright notice and this permission notice shall be included in all
//	copies or substantial portions of the Software.
//
//	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//	SOFTWARE.

package log

import (
	"context"
	"fmt"
	golog "log"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"
)

type Logger interface {
	SetLevel(level LogLevel)
	SetConsoleLevel(level LogLevel)
	SetConsole(c Console)
	Usr(msg string)
	Printf(msg string, args ...any)
	VeryVerbosef(at int, msg string, args ...any)
	Verbosef(at int, msg string, args ...any)
	Debugf(at int, msg string, args ...any)
	Piif(at int, msg string, args ...any)
	Infof(at int, msg string, args ...any)
	Warnf(at int, msg string, args ...any)
	Errorf(at int, msg string, args ...any)
	Fatalf(at int, msg string, args ...any)
	Stack(at int, msg string, scratch []byte)
}

const pcbuckets = 512

// based on github.com/eycorsican/go-tun2socks/blob/301549c43/common/log/simple/logger.go
type simpleLogger struct {
	tag string

	level LogLevel // golog (internal log) level

	c      Console
	clevel LogLevel      // may be different from level
	cmsgC  chan *conMsg  // never closed
	cskips atomic.Uint32 // number of dropped console msgs

	stmu    sync.Mutex        // guards stcount
	stcount map[string]uint32 // stack trace counter for identical traces

	o *golog.Logger
	e *golog.Logger
	q *ring[string] // todo: use []byte instead of string for gc?

	clock
	skips
}

// a clock-like spam rate limiter
// maps level+pc to its age in ticks
type clock struct {
	sync.Mutex
	l2 [NONE + 1][pcbuckets]uint8 // level+pc clock
	l1 [NONE + 1]uint8            // level clock
}

// number of per-level dropped (spammy) logs
type skips [NONE + 1]atomic.Uint32

var _ Logger = (*simpleLogger)(nil)

// based on: github.com/eycorsican/go-tun2socks/blob/301549c43/common/log/logger.go
type LogLevel uint32

const (
	VVERBOSE   LogLevel = iota // VVERBOSE is the most verbose log level.
	VERBOSE                    // VERBOSE is the verbose log level.
	DEBUG                      // DEBUG is the debug log level.
	INFO                       // INFO is the informational log level.
	WARN                       // WARN is the warning log level.
	ERROR                      // ERROR is the error log level.
	STACKTRACE                 // STACKTRACE is the stack trace log level.
	USR                        // USR is interactive log (e.g. as user prompt).
	NONE                       // NONE no-ops the logger.
)

const defaultLevel = INFO
const defaultClevel = STACKTRACE

var _ Logger = (*simpleLogger)(nil)

// github.com/golang/mobile/blob/fa72addaaa/internal/mobileinit/mobileinit_android.go#L52
// const logcatLineSize = 1024

// qSize is the number of recent log msgs to keep in the ring buffer.
const qSize = 256

// consoleChSize is the size of the console channel.
const consoleChSize = 256

// similarTraceThreshold is the no. of similar stacktraces to report before suppressing.
const similarTraceThreshold = 8

// similarUsrMsgThreshold is the no. of similar user msgs to report before suppressing.
const similarUsrMsgThreshold = 3

const defaultFlags = 0 // no flags

var _ = RegisterLogger(defaultLogger())

func defaultLogger() *simpleLogger {
	l := &simpleLogger{
		level:   defaultLevel,
		clevel:  defaultClevel,
		cmsgC:   make(chan *conMsg, consoleChSize),
		stcount: make(map[string]uint32),
		// gomobile redirects stderr and stdout to logcat
		// github.com/golang/mobile/blob/fa72addaaa/internal/mobileinit/mobileinit_android.go#L74-L92
		e: golog.New(os.Stderr, "", defaultFlags),
		o: golog.New(os.Stdout, "", defaultFlags),
		q: newRing[string](context.TODO(), qSize),
	}
	go l.consoleDispatcher()
	return l
}

// NewLogger creates a new Glogger with the given tag.
func NewLogger(tag string) *simpleLogger {
	l := defaultLogger()
	if len(tag) <= 0 { // if tag is empty, leave it as is
		return l
	}
	if !strings.HasSuffix(tag, "/") {
		tag += "/ " // does not end with a /, add a / + space
	} else if !strings.HasSuffix(tag, " ") {
		tag += " " // does not end with a space, add space
	}
	l.tag = tag
	return l
}

// SetLevel sets the log level.
func (l *simpleLogger) SetLevel(n LogLevel) {
	l.level = n
}

// SetLevel sets the log level.
func (l *simpleLogger) SetConsoleLevel(n LogLevel) {
	l.clearStCounts()
	l.clevel = n
}

// SetConsole sets the external log console.
func (l *simpleLogger) SetConsole(c Console) {
	l.clearStCounts()

	l.c = c
}

func (l *simpleLogger) clearStCounts() {
	l.stmu.Lock()
	defer l.stmu.Unlock()
	clear(l.stcount)
}

func (l *simpleLogger) incrStCount(id string) (c uint32) {
	l.stmu.Lock()
	defer l.stmu.Unlock()

	c = l.stcount[id]
	l.stcount[id]++
	return c
}

// consoleDispatcher sends msgs from l.msgC to external log console.
// It may drop logs on high load (50% for conNorm, 80% for conErr).
// Must be called once from a goroutine.
func (l *simpleLogger) consoleDispatcher() {
	for m := range l.cmsgC {
		if m == nil || len(m.m) <= 0 { // no msg
			continue
		}
		load := (len(l.cmsgC) / cap(l.cmsgC) * 100) // load percentage
		if c := l.c; c != nil {                     // look for l.c on every msg
			switch m.t {
			case NONE:
				// drop
			case VVERBOSE, VERBOSE, DEBUG, INFO:
				if load < 50 {
					c.Log(int32(m.t), m.m)
					continue
				} // drop
			case WARN, ERROR:
				if load < 5 {
					if d := l.cskips.Swap(0); d > 0 {
						c.Log(int32(WARN), l.msgstr("backpressure... dropped %d msgs", d))
					}
				}
				if load < 80 {
					c.Log(int32(m.t), m.m)
					continue
				} // drop
			case STACKTRACE:
				c.Log(int32(m.t), m.m)
				continue
			case USR:
				c.Log(int32(m.t), m.m)
				continue
			}
		} // dropped
		l.cskips.Add(1)
	}
}

// consoleQueue sends msg m to l.msgC, dropping if full.
func (l *simpleLogger) consoleQueue(m *conMsg) {
	select {
	case l.cmsgC <- m:
	default: // drop
	}
}

func (l *simpleLogger) Usr(msg string) {
	if l.level <= USR {
		if count := l.incrStCount(msg); count > similarUsrMsgThreshold {
			return
		}
		l.consoleQueue(&conMsg{msg, USR})
	}
}

// Printf exists to satisfy rnet/http's Logger interface
func (l *simpleLogger) Printf(msg string, args ...any) {
	l.Debugf(callerat, msg, args...)
}

func (l *simpleLogger) VeryVerbosef(at int, msg string, args ...any) {
	l.writelog(VVERBOSE, at+callerat, msg, args...)
}

func (l *simpleLogger) Verbosef(at int, msg string, args ...any) {
	l.writelog(VERBOSE, at+callerat, msg, args...)
}

func (l *simpleLogger) Debugf(at int, msg string, args ...any) {
	l.writelog(DEBUG, at+callerat, msg, args...)
}

func (l *simpleLogger) Piif(at int, msg string, args ...any) {
	l.writelog(INFO, at+callerat, msg, args...)
}

func (l *simpleLogger) Infof(at int, msg string, args ...any) {
	l.writelog(INFO, at+callerat, msg, args...)
}

func (l *simpleLogger) Warnf(at int, msg string, args ...any) {
	l.writelog(WARN, at+callerat, msg, args...)
}

func (l *simpleLogger) Errorf(at int, msg string, args ...any) {
	l.writelog(ERROR, at+callerat, msg, args...)
}

func (l *simpleLogger) Fatalf(at int, msg string, args ...any) {
	// todo: log to console?
	l.err(at+callerat, l.msgstr(msg, args...))
	os.Exit(1)
}

// emitStack sends stacktrace to console or log.
// Empty msgs are ignored.
func (l *simpleLogger) emitStack(at int, msgs ...string) {
	sendtoconsole := at == callerat

	c := l.c
	for _, msg := range msgs {
		if len(msg) <= 0 {
			continue
		}
		if !sendtoconsole {
			l.err(at+callerat, msg)
		} else if c != nil {
			// c.Stack() on the same go routine, since
			// the caller (ex: core.Recover) may exit
			// immediately once simpleLogger.Stack() returns
			c.Log(int32(STACKTRACE), msg)
		} else {
			// msg, which is unsafely type-coerced from []byte,
			// is pooled; but the caller owns []byte and so it
			// cannot be used asynchronously (ex: over channels).
			// l.toConsole(&conMsg{msg, STACKTRACE})
			l.cskips.Add(1)
		}
	}
}

func (l *simpleLogger) Stack(at int, msg string, scratch []byte) {
	at += callerat
	if len(l.tag) > 0 {
		msg = l.tag + msg
	}

	if l.level > STACKTRACE {
		l.emitStack(at, msg, "stacktrace disabled")
		return
	} else if len(scratch) <= 0 {
		l.emitStack(at, msg, "stacktrace no scratch")
		return
	}

	count := l.incrStCount(msg)
	msg = msg + fmt.Sprintf(" (#%d)", count)
	if count > similarTraceThreshold {
		l.emitStack(at, msg, "stacktrace suppressed")
		return
	}

	i := 0
	// todo: interned strings github.com/golang/go/issues/62483
	lines := make([]string, qSize)
	for recent := range l.q.Iter() {
		lines[i] = recent
		i++
		if i >= len(lines) {
			break
		}
	}
	var appendix string
	if i > 0 {
		appendix = strings.Join(lines[:i], "\n")
	}

	// full stacktrace iff large enough scratch
	full := len(scratch) > 16384 // 16KB
	n := runtime.Stack(scratch, full)

	if n == len(scratch) {
		msg += "[trunc]"
	}
	// byt2str accepted proposal: github.com/golang/go/issues/19367
	// previous discussion: github.com/golang/go/issues/25484
	l.emitStack(at, appendix, msg, unsafe.String(&scratch[0], n))
}

func (l *simpleLogger) msgstr(f string, args ...any) string {
	msg := fmt.Sprintf(f, args...)
	if len(l.tag) > 0 {
		msg = l.tag + msg
	}
	return msg
}

// out logs to stdout and pushes msg into ring buffer.
// ref: github.com/golang/mobile/blob/c713f31d/internal/mobileinit/mobileinit_android.go#L51
func (l *simpleLogger) out(msg string) {
	_ = l.o.Output(0 /*not used*/, msg) // may error
	l.q.Push(msg)
}

// err logs to stderr and pushes msg into ring buffer.
func (l *simpleLogger) err(at int, msg string) {
	_, file := caller(at + callerat)
	msg = file + msg
	_ = l.e.Output(0 /*unused*/, msg) // may error
	l.q.Push(msg)
}

func caller(at int) (pc uintptr, who string) {
	pc, file, line, _ := runtime.Caller(at + callerat)
	if len(file) <= 0 {
		file = "???"
	} else {
		file = shortfile(file) + ":" + fmt.Sprint(line) + ": "
	}
	return pc, file
}

func shortfile(file string) string {
	if i := strings.LastIndexByte(file, '/'); i >= 0 {
		file = file[i+1:]
	}
	return file
}

func (l *simpleLogger) writelog(lvl LogLevel, at int, msg string, args ...any) {
	ll := l.level <= lvl
	cc := l.clevel <= lvl

	pc, file := caller(at + callerat)

	if l.spammy(lvl, pc) {
		l.skips[lvl].Add(1)
		return
	} else if n := l.skips[lvl].Swap(0); n > 0 && (cc || ll) {
		spammsg := file + l.msgstr("spammy... dropped %d msgs", n)
		if ll {
			l.out(spammsg)
		}
		if cc {
			l.consoleQueue(&conMsg{spammsg, lvl})
		}
	}

	if ll || cc {
		msg = file + l.msgstr(msg, args...)
		if ll {
			l.out(msg)
		}
		if cc {
			l.consoleQueue(&conMsg{msg, lvl})
		}
	}
}

// not thread-safe for performance reasons
// go.dev/play/p/6CkoACJ1bYz
func (l *simpleLogger) spammy(lvl LogLevel, pc uintptr) (y bool) {
	// expensive, but golog's internal logger also grabs a mutex before every write
	l.clock.Lock()
	defer l.clock.Unlock()

	l.clock.l1[lvl]++ // tick the level clock
	t := l.clock.l1[lvl]

	if pc == 0 {
		return false
	}
	// won't work:  l2 := l.clock.l2[lvl]
	// go.dev/play/p/QgqEdE7KIAZ
	bkt := pc % pcbuckets

	defer func() {
		if !y { // age bkt when not spammy
			l.clock.l2[lvl][bkt]++
		}
	}()

	// reset if pc clock (l2) out ticks level clock (l1);
	// ie, t has probably overflowed to next generation
	// and in that generation, bkt has not yet born.
	// and so reset bkt to 0 or any value < t
	if resync := l.clock.l2[lvl][bkt] > t; resync {
		l.clock.l2[lvl][bkt] = t / 2 // set to 0?
		return false                 // not spammy
	}

	tt := uint16(t)
	v := l.clock.l2[lvl][bkt]
	if t < 256>>4 { // for upto 16 ticks
		tt = tt * 70 / 100 // allow upto 70% of ticks
	} else if t < 256>>3 { // for upto 32 ticks
		tt = tt * 60 / 100 // allow upto 60% of ticks
	} else if t < 256>>2 { // for upto 64 ticks
		tt = tt * 50 / 100 // allow upto 50% of ticks
	} else if t < 256>>1 { // for upto 128 ticks
		tt = tt * 40 / 100 // allow upto 40% of ticks
	} else { // for upto 256 ticks
		tt = tt * 30 / 100 // allow upto 30% of ticks
	}
	return uint16(v) > tt
}
