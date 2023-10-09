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

type LogFn func(string, ...any)

func RegisterLogger(l Logger) bool {
	Glogger = l
	return true
}

func SetLevel(level LogLevel) {
	if Glogger != nil {
		Glogger.SetLevel(level)
	}
}

func Of(tag string, l LogFn) LogFn {
	if l != nil {
		return func(msg string, args ...any) {
			l(tag+" "+msg, args...)
		}
	}
	return N
}

func N(_ string, _ ...any) {}

func V(msg string, args ...any) {
	if Glogger != nil {
		Glogger.Verbosef("V "+msg, args...)
	}
}

func D(msg string, args ...any) {
	if Glogger != nil {
		Glogger.Debugf("D "+msg, args...)
	}
}

func P(msg string, args ...any) {
	if Glogger != nil {
		Glogger.Piif("P "+msg, args...)
	}
}

func I(msg string, args ...any) {
	if Glogger != nil {
		Glogger.Infof("I "+msg, args...)
	}
}

func W(msg string, args ...any) {
	if Glogger != nil {
		Glogger.Warnf("W "+msg, args...)
	}
}

func E(msg string, args ...any) {
	if Glogger != nil {
		Glogger.Errorf("E "+msg, args...)
	}
}

func Wtf(msg string, args ...any) {
	if Glogger != nil {
		Glogger.Fatalf("F "+msg, args...)
	}
}
