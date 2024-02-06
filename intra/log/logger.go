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
	golog "log"
	"os"
	"strings"
)

// based on: github.com/eycorsican/go-tun2socks/blob/301549c43/common/log/logger.go
type LogLevel uint8

const (
	VERBOSE LogLevel = iota
	DEBUG
	INFO
	WARN
	ERROR
	NONE
)

const defaultLevel = INFO

type Logger interface {
	SetLevel(level LogLevel)
	Printf(msg string, args ...any)
	Verbosef(msg string, args ...any)
	Debugf(msg string, args ...any)
	Piif(msg string, args ...any)
	Infof(msg string, args ...any)
	Warnf(msg string, args ...any)
	Errorf(msg string, args ...any)
	Fatalf(msg string, args ...any)
}

// based on github.com/eycorsican/go-tun2socks/blob/301549c43/common/log/simple/logger.go
type simpleLogger struct {
	Logger
	level LogLevel
	tag   string
	e     *golog.Logger
	o     *golog.Logger
}

var _ = RegisterLogger(defaultLogger())

var defaultFlags = golog.Ldate | golog.Ltime | golog.Lshortfile

func defaultLogger() *simpleLogger {
	return &simpleLogger{
		level: defaultLevel,
		e:     golog.New(os.Stderr, "", defaultFlags),
		o:     golog.New(os.Stdout, "", defaultFlags),
	}
}

func NewLogger(tag string) Logger {
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

func (l *simpleLogger) SetLevel(level LogLevel) {
	l.level = level
}

func (l *simpleLogger) Printf(msg string, args ...any) {
	l.Debugf(msg, args...)
}

func (l *simpleLogger) Verbosef(msg string, args ...any) {
	if l.level <= VERBOSE {
		l.out(msg, args...)
	}
}

func (l *simpleLogger) Debugf(msg string, args ...any) {
	if l.level <= DEBUG {
		l.out(msg, args...)
	}
}

func (l *simpleLogger) Piif(msg string, args ...any) {
	if l.level <= DEBUG {
		l.out(msg, args...)
	}
}

func (l *simpleLogger) Infof(msg string, args ...any) {
	if l.level <= INFO {
		l.out(msg, args...)
	}
}

func (l *simpleLogger) Warnf(msg string, args ...any) {
	if l.level <= WARN {
		l.err(msg, args...)
	}
}

func (l *simpleLogger) Errorf(msg string, args ...any) {
	if l.level <= ERROR {
		l.err(msg, args...)
	}
}

func (l *simpleLogger) Fatalf(msg string, args ...any) {
	l.e.Fatalf(msg, args...)
}

// ref: github.com/golang/mobile/blob/c713f31d/internal/mobileinit/mobileinit_android.go#L51
func (l *simpleLogger) out(msg string, args ...any) {
	if len(l.tag) <= 0 {
		l.o.Printf(msg, args...)
	} else {
		l.o.Printf(l.tag+msg, args...)
	}
}

func (l *simpleLogger) err(msg string, args ...any) {
	if len(l.tag) <= 0 {
		l.e.Printf(msg, args...)
	} else {
		l.e.Printf(l.tag+msg, args...)
	}
}
