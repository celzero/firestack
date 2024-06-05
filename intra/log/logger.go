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
	"fmt"
	golog "log"
	"os"
	"runtime"
	"strings"
	"sync"
	"unsafe"
)

type Logger interface {
	SetLevel(level LogLevel)
	SetConsoleLevel(level LogLevel)
	SetConsole(c Console)
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
	c          Console           // may be nil
	clevel     LogLevel          // may be different from level
	msgC       chan *conMsg      // never closed
	stcount    map[string]uint32 // stack trace counter for identical traces
	e          *golog.Logger
	o          *golog.Logger
	q          *ring[string] // todo: use []byte instead of string for gc?
}

var _ Logger = (*simpleLogger)(nil)

// based on: github.com/eycorsican/go-tun2socks/blob/301549c43/common/log/logger.go
type LogLevel uint32

const (
	VVERBOSE LogLevel = iota
	VERBOSE
	DEBUG
	INFO
	WARN
	ERROR
	STACKTRACE
	NONE
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
		q: newRing[string](qSize),
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
	l.c = c
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
func (l *simpleLogger) fromConsole() {
	for m := range l.msgC {
		load := (len(l.msgC) / cap(l.msgC) * 100)           // load percentage
		if c := l.c; c != nil && m != nil && len(m.m) > 0 { // look for l.c on every msg
			switch m.t {
			case conNorm:
				if load < 50 {
					c.Log(m.m)
				} // drop
			case conStack:
				c.Stack(m.m)
			case conErr:
				if load < 80 {
					c.Err(m.m)
				} // drop
			}
		} // dropped
	}
}

// toConsole sends msg m to l.msgC, dropping if full.
func (l *simpleLogger) toConsole(m *conMsg) {
	select {
	case l.msgC <- m:
	default: // drop
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
		l.toConsole(&conMsg{msg, conNorm})
	}
}

func (l *simpleLogger) Verbosef(at int, msg string, args ...any) {
	msg = l.msgstr(msg, args...)
	if l.level <= VERBOSE {
		l.out(at, msg)
	}
	if l.clevel <= VERBOSE {
		l.toConsole(&conMsg{msg, conNorm})
	}
}

func (l *simpleLogger) Debugf(at int, msg string, args ...any) {
	msg = l.msgstr(msg, args...)
	if l.level <= DEBUG {
		l.out(at, msg)
	}
	if l.clevel <= DEBUG {
		l.toConsole(&conMsg{msg, conNorm})
	}
}

func (l *simpleLogger) Piif(at int, msg string, args ...any) {
	msg = l.msgstr(msg, args...)
	if l.level <= DEBUG {
		l.out(at, msg)
	}
	if l.clevel <= DEBUG {
		l.toConsole(&conMsg{msg, conNorm})
	}
}

func (l *simpleLogger) Infof(at int, msg string, args ...any) {
	msg = l.msgstr(msg, args...)
	if l.level <= INFO {
		l.out(at, msg)
	}
	if l.clevel <= INFO {
		l.toConsole(&conMsg{msg, conNorm})
	}
}

func (l *simpleLogger) Warnf(at int, msg string, args ...any) {
	msg = l.msgstr(msg, args...)
	if l.level <= WARN {
		l.err(at, msg)
	}
	if l.clevel <= WARN {
		l.toConsole(&conMsg{msg, conErr})
	}
}

func (l *simpleLogger) Errorf(at int, msg string, args ...any) {
	msg = l.msgstr(msg, args...)
	if l.level <= ERROR {
		l.err(at, msg)
	}
	if l.clevel <= ERROR {
		l.toConsole(&conMsg{msg, conErr})
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

	for _, msg := range msgs {
		if len(msg) <= 0 {
			continue
		}
		if !sendtoconsole {
			l.err(at+1, msg)
		} else if c := l.c; c != nil {
			// c.Stack() on the same go routine, since
			// the caller (ex: core.Recover) may exit
			// immediately once simpleLogger.Stack() returns
			c.Stack(msg)
		} else {
			l.toConsole(&conMsg{msg, conStack})
		}
	}
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
