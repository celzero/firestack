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

import "fmt"

// based on: github.com/eycorsican/go-tun2socks/blob/301549c43/common/log/log.go#L5
var Glogger Logger = defaultLogger()

// caller -> intra/log.go*2 (this file) -> intra/logger.go -> golang/log.go
const (
	nextframe = 1
	// see: pkg.go.dev/log#Output
	callerat = 2
)

type Logmsg string

// Console is an external logger.
type Console interface {
	// Log logs a multi-line msg.
	Log(level LogLevel, msg Logmsg)
}

type conMsg struct {
	m Logmsg
	t LogLevel
}

type LogFn func(string, ...any)
type LogFn2 func(int, string, ...any)

func init() {
	Glogger.SetLevel(INFO)
	Glogger.SetConsoleLevel(STACKTRACE)
}

func SetLevel(level LogLevel) {
	Glogger.SetLevel(level)
}

func SetConsoleLevel(level LogLevel) {
	Glogger.SetConsoleLevel(level)
}

// SetConsole sets external console to redirect log output to.
func SetConsole(c Console) {
	Glogger.SetConsole(c)

}

func Of(tag string, l LogFn2) LogFn {
	if l != nil {
		return func(msg string, args ...any) {
			// caller -> LogFn (parent fn) -> intra/log.go*2(this file) -> intra/logger.go -> golang/log.go
			l(callerat, tag+" "+msg, args...)
		}
	}
	return N
}

// N is a no-op logger.
func N(string, ...any) {}

// N2 is a no-op logger.
func N2(int, string, ...any) {}

// V logs a verbose message.
func V(msg string, args ...any) {
	V2(callerat, msg, args...)
}

// VV logs a very verbose message.
func VV(msg string, args ...any) {
	VV2(callerat, msg, args...)
}

// D logs a debug message.
func D(msg string, args ...any) {
	D2(callerat, msg, args...)
}

// I logs an info message.
func I(msg string, args ...any) {
	I2(callerat, msg, args...)
}

// W logs a warning message.
func W(msg string, args ...any) {
	W2(callerat, msg, args...)
}

// E logs an error message.
func E(msg string, args ...any) {
	E2(callerat, msg, args...)
}

// P logs a private message.
func P(msg string, args ...any) {
	Glogger.Piif(callerat, msg, args...)
}

// Wtf logs a fatal message.
func Wtf(msg string, args ...any) {
	Glogger.Fatalf(callerat, msg, args...)
}

// C logs the stack trace of the current goroutine to Console.
func C(msg string, scratch []byte) {
	E2(callerat, "----START----")
	Glogger.Stack( /*console-only*/ 0, msg, scratch)
	E2(callerat, "----STOPP----")

}

// U logs a user message (notifies the user).
func U(msg string) {
	Glogger.Usr(msg)
}

// T logs the stack trace of the current goroutine.
func T(msg string, args ...any) {
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	E2(callerat, "----START----")
	Glogger.Stack(callerat, msg, make([]byte, 4096))
	E2(callerat, "----STOPP----")
}

// TALL logs the stack trace of all active goroutines.
func TALL(msg string, scratch64k []byte) {
	E2(callerat, "----START----")
	Glogger.Stack(callerat, msg, scratch64k)
	E2(callerat, "----STOPP----")
}

func VV2(at int, msg string, args ...any) {
	Glogger.VeryVerbosef(at+nextframe, msg, args...)
}

func V2(at int, msg string, args ...any) {
	Glogger.Verbosef(at+nextframe, msg, args...)
}

func D2(at int, msg string, args ...any) {
	Glogger.Debugf(at+nextframe, msg, args...)
}

func I2(at int, msg string, args ...any) {
	Glogger.Infof(at+nextframe, msg, args...)
}

func W2(at int, msg string, args ...any) {
	Glogger.Warnf(at+nextframe, msg, args...)
}

func E2(at int, msg string, args ...any) {
	Glogger.Errorf(at+nextframe, msg, args...)
}

func LevelOf(level int32) LogLevel {
	dlvl := NONE
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
