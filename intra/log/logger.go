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
)

type Logger interface {
	SetLevel(level LogLevel)
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
	Stack(at int, msg string)
}

// based on github.com/eycorsican/go-tun2socks/blob/301549c43/common/log/simple/logger.go
type simpleLogger struct {
	Logger
	level LogLevel
	tag   string
	c     Console      // may be nil
	msgC  chan *conMsg // never closed
	e     *golog.Logger
	o     *golog.Logger
}

// based on: github.com/eycorsican/go-tun2socks/blob/301549c43/common/log/logger.go
type LogLevel uint8

const (
	VVERBOSE LogLevel = iota
	VERBOSE
	DEBUG
	INFO
	WARN
	ERROR
	NONE
)

const defaultLevel = INFO

var _ Logger = (*simpleLogger)(nil)

// github.com/golang/mobile/blob/fa72addaaa1/internal/mobileinit/mobileinit_android.go#L52
const logcatLineSize = 1024

var defaultFlags = golog.Lshortfile
var defaultCallerDepth = 2
var _ = RegisterLogger(defaultLogger())

func defaultLogger() *simpleLogger {
	l := &simpleLogger{
		level: defaultLevel,
		msgC:  make(chan *conMsg, consoleChSize),
		e:     golog.New(os.Stderr, "", defaultFlags),
		o:     golog.New(os.Stdout, "", defaultFlags),
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
func (l *simpleLogger) SetLevel(level LogLevel) {
	l.level = level
}

// SetConsole sets the external log console.
func (l *simpleLogger) SetConsole(c Console) {
	l.c = c
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
	if l.level <= VVERBOSE {
		l.out(at, msg, args...)
	}
}

func (l *simpleLogger) Verbosef(at int, msg string, args ...any) {
	if l.level <= VERBOSE {
		l.out(at, msg, args...)
	}
}

func (l *simpleLogger) Debugf(at int, msg string, args ...any) {
	if l.level <= DEBUG {
		l.out(at, msg, args...)
	}
}

func (l *simpleLogger) Piif(at int, msg string, args ...any) {
	if l.level <= DEBUG {
		l.out(at, msg, args...)
	}
}

func (l *simpleLogger) Infof(at int, msg string, args ...any) {
	if l.level <= INFO {
		l.out(at, msg, args...)
	}
}

func (l *simpleLogger) Warnf(at int, msg string, args ...any) {
	if l.level <= WARN {
		l.err(at, msg, args...)
	}
}

func (l *simpleLogger) Errorf(at int, msg string, args ...any) {
	if l.level <= ERROR {
		l.err(at, msg, args...)
	}
}

func (l *simpleLogger) Fatalf(at int, msg string, args ...any) {
	l.err(at, msg, args...)
	os.Exit(1)
}

func (l *simpleLogger) Stack(at int, msg string) {
	dump := make([]byte, 2*logcatLineSize) // matches android/log.h.
	for {
		n := runtime.Stack(dump, false)
		if n < len(dump) {
			msg = msg + "\n\t" + string(dump[:n])
			if len(l.tag) > 0 {
				msg = l.tag + msg
			}
			if at > 0 { // skip l.err if at is 0
				_ = l.e.Output(at, msg) // may error
			} else if c := l.c; c != nil {
				// c.Stack() on the same go routine, since
				// the caller (ex: core.Recover) may exit
				// immediately once simpleLogger.Stack() returns
				c.Stack(msg)
			} else {
				l.toConsole(&conMsg{msg, conStack})
			}
			break
		} // make more space for dump
		dump = make([]byte, 2*len(dump))
	}
}

// ref: github.com/golang/mobile/blob/c713f31d/internal/mobileinit/mobileinit_android.go#L51
func (l *simpleLogger) out(at int, f string, args ...any) {
	msg := fmt.Sprintf(f, args...)
	if len(l.tag) > 0 {
		msg = l.tag + msg
	}
	l.toConsole(&conMsg{msg, conNorm})
	_ = l.o.Output(at, msg) // may error
}

func (l *simpleLogger) err(at int, f string, args ...any) {
	msg := fmt.Sprintf(f, args...)
	if len(l.tag) > 0 {
		msg = l.tag + msg
	}
	l.toConsole(&conMsg{msg, conErr})
	_ = l.e.Output(at, msg) // may error
}
