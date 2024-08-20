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
	"reflect"
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

// based on github.com/eycorsican/go-tun2socks/blob/301549c43/common/log/simple/logger.go
type simpleLogger struct {
	sync.Mutex // guards stcount
	level      LogLevel
	tag        string
	c          atomic.Value      // Console
	clevel     LogLevel          // may be different from level
	msgC       chan *conMsg      // never closed
	stcount    map[string]uint32 // stack trace counter for identical traces
	drops      atomic.Uint32     // number of dropped logs
	e          *golog.Logger
	o          *golog.Logger
	q          *ring[string] // todo: use []byte instead of string for gc?
}

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
const qSize = 128

// similarTraceThreshold is the no. of similar stacktraces to report before suppressing.
const similarTraceThreshold = 8

// similarUsrMsgThreshold is the no. of similar user msgs to report before suppressing.
const similarUsrMsgThreshold = 3

var defaultFlags = golog.Lshortfile
var defaultCallerDepth = 2
var _ = RegisterLogger(defaultLogger())

func defaultLogger() *simpleLogger {
	l := &simpleLogger{
		level:   defaultLevel,
		clevel:  defaultClevel,
		msgC:    make(chan *conMsg, consoleChSize),
		stcount: make(map[string]uint32),
		// gomobile redirects stderr and stdout to logcat
		// github.com/golang/mobile/blob/fa72addaaa/internal/mobileinit/mobileinit_android.go#L74-L92
		e: golog.New(os.Stderr, "", defaultFlags),
		o: golog.New(os.Stdout, "", defaultFlags),
		q: newRing[string](context.TODO(), qSize),
	}
	go l.fromConsole()
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

	if c == nil || isNil(c) {
		l.c = atomic.Value{}
	} else {
		l.c.Store(c)
	}
}

func (l *simpleLogger) clearStCounts() {
	l.Lock()
	defer l.Unlock()
	clear(l.stcount)
}

func (l *simpleLogger) incrStCount(id string) (c uint32) {
	l.Lock()
	defer l.Unlock()

	c = l.stcount[id]
	c++
	l.stcount[id] = c
	return c
}

// fromConsole sends msgs from l.msgC to external log console.
// It may drop logs on high load (50% for conNorm, 80% for conErr).
// Must be called once from a goroutine.
func (l *simpleLogger) fromConsole() {
	for m := range l.msgC {
		if m == nil || len(m.m) <= 0 { // no msg
			continue
		}
		load := (len(l.msgC) / cap(l.msgC) * 100) // load percentage
		if c := l.getConsole(); c != nil {        // look for l.c on every msg
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
					d := l.drops.Swap(0)
					if d > 0 {
						c.Log(int32(WARN), l.msgstr("dropped %d msgs", d))
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
		l.drops.Add(1)
	}
}

// toConsole sends msg m to l.msgC, dropping if full.
func (l *simpleLogger) toConsole(m *conMsg) {
	select {
	case l.msgC <- m:
	default: // drop
	}
}

func (l *simpleLogger) Usr(msg string) {
	if l.level <= USR {
		if count := l.incrStCount(msg); count > similarUsrMsgThreshold {
			return
		}
		l.toConsole(&conMsg{msg, USR})
	}
}

// Printf exists to satisfy rnet/http's Logger interface
func (l *simpleLogger) Printf(msg string, args ...any) {
	l.Debugf(defaultCallerDepth, msg, args...)
}

func (l *simpleLogger) VeryVerbosef(at int, msg string, args ...any) {
	msg = l.msgstr(msg, args...)
	if l.level <= VVERBOSE {
		l.out(at, msg)
	}
	if l.clevel <= VVERBOSE {
		l.toConsole(&conMsg{msg, VVERBOSE})
	}
}

func (l *simpleLogger) Verbosef(at int, msg string, args ...any) {
	msg = l.msgstr(msg, args...)
	if l.level <= VERBOSE {
		l.out(at, msg)
	}
	if l.clevel <= VERBOSE {
		l.toConsole(&conMsg{msg, VERBOSE})
	}
}

func (l *simpleLogger) Debugf(at int, msg string, args ...any) {
	msg = l.msgstr(msg, args...)
	if l.level <= DEBUG {
		l.out(at, msg)
	}
	if l.clevel <= DEBUG {
		l.toConsole(&conMsg{msg, DEBUG})
	}
}

func (l *simpleLogger) Piif(at int, msg string, args ...any) {
	msg = l.msgstr(msg, args...)
	if l.level <= VVERBOSE {
		l.out(at, msg)
	}
	if l.clevel <= VVERBOSE {
		l.toConsole(&conMsg{msg, DEBUG})
	}
}

func (l *simpleLogger) Infof(at int, msg string, args ...any) {
	msg = l.msgstr(msg, args...)
	if l.level <= INFO {
		l.out(at, msg)
	}
	if l.clevel <= INFO {
		l.toConsole(&conMsg{msg, INFO})
	}
}

func (l *simpleLogger) Warnf(at int, msg string, args ...any) {
	msg = l.msgstr(msg, args...)
	if l.level <= WARN {
		l.err(at, msg)
	}
	if l.clevel <= WARN {
		l.toConsole(&conMsg{msg, WARN})
	}
}

func (l *simpleLogger) Errorf(at int, msg string, args ...any) {
	msg = l.msgstr(msg, args...)
	if l.level <= ERROR {
		l.err(at, msg)
	}
	if l.clevel <= ERROR {
		l.toConsole(&conMsg{msg, ERROR})
	}
}

func (l *simpleLogger) Fatalf(at int, msg string, args ...any) {
	// todo: log to console?
	l.err(at, l.msgstr(msg, args...))
	os.Exit(1)
}

// emitStack sends stacktrace to console or log.
// Empty msgs are ignored.
func (l *simpleLogger) emitStack(at int, msgs ...string) {
	sendtoconsole := at == 0

	c := l.getConsole()
	for _, msg := range msgs {
		if len(msg) <= 0 {
			continue
		}
		if !sendtoconsole {
			l.err(at+1, msg)
		} else if c != nil {
			// c.Stack() on the same go routine, since
			// the caller (ex: core.Recover) may exit
			// immediately once simpleLogger.Stack() returns
			c.Log(int32(STACKTRACE), msg)
		} else {
			// msg, which is unsafely type-coerced from []byte,
			// is pooled; but the caller owns []byte and so it
			// cannot be used asynchrously (ex: over channels).
			// l.toConsole(&conMsg{msg, STACKTRACE})
			l.drops.Add(1)
		}
	}
}

// getConsole returns the external log console, if any; else nil.
func (l *simpleLogger) getConsole() Console {
	v := l.c.Load()
	if c, ok := v.(Console); ok && c != nil && isNotNil(c) {
		return c
	}
	return nil
}

func (l *simpleLogger) Stack(at int, msg string, scratch []byte) {
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

	n := runtime.Stack(scratch, false)

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
func (l *simpleLogger) out(at int, msg string) {
	_ = l.o.Output(at, msg) // may error
	l.q.Push(msg)
}

// err logs to stderr and pushes msg into ring buffer.
func (l *simpleLogger) err(at int, msg string) {
	_ = l.e.Output(at, msg) // may error
	l.q.Push(msg)
}

// from: core/closer.go

func isNotNil(x any) bool {
	return !isNil(x)
}

// isNil reports whether x is nil if its Chan, Func, Map,
// Pointer, UnsafePointer, Interface, and Slice;
// may panic if x is not addressable
func isNil(x any) bool {
	// from: stackoverflow.com/a/76595928
	if x == nil {
		return true
	}
	v := reflect.ValueOf(x)
	k := v.Kind()
	switch k {
	case reflect.Pointer, reflect.UnsafePointer, reflect.Interface, reflect.Chan, reflect.Func, reflect.Map, reflect.Slice:
		return v.IsNil()
	}
	return false
}
