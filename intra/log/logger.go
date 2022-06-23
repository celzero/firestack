// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//    MIT License
//
//    Copyright (c) 2018 eycorsican
//
//    Permission is hereby granted, free of charge, to any person obtaining a copy
//    of this software and associated documentation files (the "Software"), to deal
//    in the Software without restriction, including without limitation the rights
//    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//    copies of the Software, and to permit persons to whom the Software is
//    furnished to do so, subject to the following conditions:
//
//    The above copyright notice and this permission notice shall be included in all
//    copies or substantial portions of the Software.
//
//    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//    SOFTWARE.
package log

import (
	golog "log"
)

// based on: github.com/eycorsican/go-tun2socks/blob/301549c43/common/log/logger.go
type LogLevel uint8

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	NONE
)

const defaultLevel = WARN

type Logger interface {
	SetLevel(level LogLevel)
	Debugf(msg string, args ...interface{})
	Infof(msg string, args ...interface{})
	Warnf(msg string, args ...interface{})
	Errorf(msg string, args ...interface{})
	Fatalf(msg string, args ...interface{})
}

// based on github.com/eycorsican/go-tun2socks/blob/301549c43/common/log/simple/logger.go
type simpleLogger struct {
	Logger
	level LogLevel
}

var _ = RegisterLogger(NewSimpleLogger())

func NewSimpleLogger() Logger {
	return &simpleLogger{
		level: defaultLevel,
	}
}

func (l *simpleLogger) SetLevel(level LogLevel) {
	l.level = level
}

func (l *simpleLogger) Debugf(msg string, args ...interface{}) {
	if l.level <= DEBUG {
		l.output(msg, args...)
	}
}

func (l *simpleLogger) Infof(msg string, args ...interface{}) {
	if l.level <= INFO {
		l.output(msg, args...)
	}
}

func (l *simpleLogger) Warnf(msg string, args ...interface{}) {
	if l.level <= WARN {
		l.output(msg, args...)
	}
}

func (l *simpleLogger) Errorf(msg string, args ...interface{}) {
	if l.level <= ERROR {
		l.output(msg, args...)
	}
}

func (l *simpleLogger) Fatalf(msg string, args ...interface{}) {
	golog.Fatalf(msg, args...)
}

func (l *simpleLogger) output(msg string, args ...interface{}) {
	golog.Printf(msg, args...)
}
