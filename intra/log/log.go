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

// based on: github.com/eycorsican/go-tun2socks/blob/301549c43/common/log/log.go#L5
var Glogger Logger

// caller -> intra/log.go (this file) -> intra/logger.go -> golang/log.go
var callerDepth = 4

// caller -> LogFn -> intra/log.go (this file) -> intra/logger.go -> golang/log.go
var logFnCallerDepth = 5

type LogFn func(string, ...any)
type LogFn2 func(int, string, ...any)

func RegisterLogger(l Logger) bool {
	Glogger = l
	l.SetLevel(INFO)
	return true
}

func SetLevel(level LogLevel) {
	if Glogger != nil {
		Glogger.SetLevel(level)
	}
}

func Of(tag string, l LogFn2) LogFn {
	if l != nil {
		return func(msg string, args ...any) {
			l(logFnCallerDepth, tag+" "+msg, args...)
		}
	}
	return N
}

func N(string, ...any)       {}
func N2(int, string, ...any) {}

func V2(at int, msg string, args ...any) {
	if Glogger != nil {
		Glogger.Verbosef(at, "V "+msg, args...)
	}
}

func V(msg string, args ...any) {
	if Glogger != nil {
		Glogger.Verbosef(callerDepth, "V "+msg, args...)
	}
}

func D(msg string, args ...any) {
	if Glogger != nil {
		Glogger.Debugf(callerDepth, "D "+msg, args...)
	}
}

func P(msg string, args ...any) {
	if Glogger != nil {
		Glogger.Piif(callerDepth, "P "+msg, args...)
	}
}

func I(msg string, args ...any) {
	if Glogger != nil {
		Glogger.Infof(callerDepth, "I "+msg, args...)
	}
}

func W(msg string, args ...any) {
	if Glogger != nil {
		Glogger.Warnf(callerDepth, "W "+msg, args...)
	}
}

func E2(at int, msg string, args ...any) {
	if Glogger != nil {
		Glogger.Errorf(at, "E "+msg, args...)
	}
}

func E(msg string, args ...any) {
	if Glogger != nil {
		Glogger.Errorf(callerDepth, "E "+msg, args...)
	}
}

func Wtf(msg string, args ...any) {
	if Glogger != nil {
		Glogger.Fatalf(callerDepth, "F "+msg, args...)
	}
}
