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
	"sync/atomic"
)

// based on: github.com/eycorsican/go-tun2socks/blob/301549c43/common/log/log.go#L5
var Glogger Logger

// caller -> intra/log.go (this file) -> intra/logger.go -> golang/log.go
var CallerDepth = 4

// caller -> LogFn -> intra/log.go (this file) -> intra/logger.go -> golang/log.go
var LogFnCallerDepth = CallerDepth + 1

var consoleLogLevel = atomic.Int32{}

// Console logs messages.
type Console interface {
	// Log logs a multi-line log message.
	Log(s string)
	// Err logs a multi-line error message.
	Err(s string)
	// Stack logs a multi-line stack trace.
	Stack(s string)
}

// console msg priority
type conpri int32

const (
	// conNorm is normal priority console message.
	conNorm conpri = iota
	// conErr is error priority console message.
	conErr
	// conStack is stacktrace priority console message.
	conStack
)

type conMsg struct {
	m string
	t conpri
}

var consoleChSize = 128

type LogFn func(string, ...any)
type LogFn2 func(int, string, ...any)

func RegisterLogger(l Logger) bool {
	Glogger = l
	l.SetLevel(INFO)
	l.SetConsoleLevel(STACKTRACE)
	return true
}

func SetLevel(level LogLevel) {
	if Glogger != nil {
		Glogger.SetLevel(level)
	}
}

func SetConsoleLevel(level LogLevel) {
	if Glogger != nil {
		Glogger.SetConsoleLevel(level)
	}
}

func SetConsole(c Console) {
	if Glogger != nil {
		Glogger.SetConsole(c)
	}
}

func Of(tag string, l LogFn2) LogFn {
	if l != nil {
		return func(msg string, args ...any) {
			l(LogFnCallerDepth, tag+" "+msg, args...)
		}
	}
	return N
}

func N(string, ...any)       {}
func N2(int, string, ...any) {}

func V(msg string, args ...any) {
	V2(LogFnCallerDepth, msg, args...)
}

func VV(msg string, args ...any) {
	VV2(LogFnCallerDepth, msg, args...)
}

func D(msg string, args ...any) {
	D2(LogFnCallerDepth, msg, args...)
}

func I(msg string, args ...any) {
	I2(LogFnCallerDepth, msg, args...)
}

func W(msg string, args ...any) {
	W2(LogFnCallerDepth, msg, args...)
}

func E(msg string, args ...any) {
	E2(LogFnCallerDepth, msg, args...)
}

func P(msg string, args ...any) {
	if Glogger != nil {
		Glogger.Piif(CallerDepth, "P "+msg, args...)
	}
}

func Wtf(msg string, args ...any) {
	if Glogger != nil {
		Glogger.Fatalf(CallerDepth, "F "+msg, args...)
	}
}

// C logs the stack trace of the current goroutine to Console.
func C(msg string) {
	if Glogger != nil {
		E2(LogFnCallerDepth, "----START----")
		Glogger.Stack( /*console-only*/ 0, "F "+msg)
		E2(LogFnCallerDepth, "----STOPP----")
	}
}

// T logs the stack trace of the current goroutine.
func T(msg string) {
	if Glogger != nil {
		E2(LogFnCallerDepth, "----START----")
		Glogger.Stack(LogFnCallerDepth, "F "+msg)
		E2(LogFnCallerDepth, "----STOPP----")
	}
}

func VV2(at int, msg string, args ...any) {
	if Glogger != nil {
		Glogger.VeryVerbosef(at, "VV "+msg, args...)
	}
}

func V2(at int, msg string, args ...any) {
	if Glogger != nil {
		Glogger.Verbosef(at, "V "+msg, args...)
	}
}

func D2(at int, msg string, args ...any) {
	if Glogger != nil {
		Glogger.Debugf(at, "D "+msg, args...)
	}
}

func I2(at int, msg string, args ...any) {
	if Glogger != nil {
		Glogger.Infof(at, "I "+msg, args...)
	}
}

func W2(at int, msg string, args ...any) {
	if Glogger != nil {
		Glogger.Warnf(at, "W "+msg, args...)
	}
}

func E2(at int, msg string, args ...any) {
	if Glogger != nil {
		Glogger.Errorf(at, "E "+msg, args...)
	}
}

func LevelOf(level int) LogLevel {
	dlvl := WARN
	switch l := LogLevel(level); l {
	case VVERBOSE:
		dlvl = VVERBOSE
	case VERBOSE:
		dlvl = VERBOSE
	case DEBUG:
		dlvl = DEBUG
	case INFO:
		dlvl = INFO
	case WARN:
		dlvl = WARN
	case ERROR:
		dlvl = ERROR
	case STACKTRACE:
		dlvl = STACKTRACE
	case NONE:
		dlvl = NONE
	default:
	}
	return dlvl
}
