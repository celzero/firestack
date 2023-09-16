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
	Verbosef(msg string, args ...any)
	Debugf(msg string, args ...any)
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
}

var _ = RegisterLogger(NewSimpleLogger())

func NewSimpleLogger() Logger {
	return &simpleLogger{
		level: defaultLevel,
	}
}

func NewLogger(tag string) Logger {
	if len(tag) <= 0 {
		return NewSimpleLogger()
	}
	if !strings.HasSuffix(tag, "/") {
		tag += "/"
	}
	if !strings.HasSuffix(tag, " ") {
		tag += " "
	}
	return &simpleLogger{
		level: defaultLevel,
		tag:   tag,
	}
}

func (l *simpleLogger) SetLevel(level LogLevel) {
	l.level = level
}

func (l *simpleLogger) Verbosef(msg string, args ...any) {
	if l.level <= VERBOSE {
		l.output(msg, args...)
	}
}

func (l *simpleLogger) Debugf(msg string, args ...any) {
	if l.level <= DEBUG {
		l.output(msg, args...)
	}
}

func (l *simpleLogger) Infof(msg string, args ...any) {
	if l.level <= INFO {
		l.output(msg, args...)
	}
}

func (l *simpleLogger) Warnf(msg string, args ...any) {
	if l.level <= WARN {
		l.output(msg, args...)
	}
}

func (l *simpleLogger) Errorf(msg string, args ...any) {
	if l.level <= ERROR {
		l.output(msg, args...)
	}
}

func (l *simpleLogger) Fatalf(msg string, args ...any) {
	golog.Fatalf(msg, args...)
}

func (l *simpleLogger) output(msg string, args ...any) {
	if len(l.tag) <= 0 {
		golog.Printf(msg, args...)
	} else {
		golog.Printf(l.tag+msg, args...)
	}
}
