// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//    Copyright 2014 The Go Authors. All rights reserved.
//    Use of this source code is governed by a BSD-style
//    license that can be found in the LICENSE file.

//go:build android && cgo

package log

// adb logcat Firestack:D Firestack:I Firestack:W Firestack:E *:S

/*
#cgo LDFLAGS: -landroid -llog

#include <stdarg.h>
#include <stdlib.h>
#include <android/log.h>
*/
import "C"

import (
	"io"
	"strings"
	"unsafe"
)

// ctag is the logcat tag used for all log output.
var ctag = C.CString("Firestack")

// xlog is a Console implementation that routes log entries to Android logcat
// using the appropriate log priority for each LogLevel:
//
//   - VVERBOSE / VERBOSE / DEBUG = ANDROID_LOG_DEBUG
//   - INFO                       = ANDROID_LOG_INFO
//   - WARN                       = ANDROID_LOG_WARN
//   - ERROR / STACKTRACE         = ANDROID_LOG_ERROR
//   - USR                        = ANDROID_LOG_INFO
type xlog struct{}

var _ Console = (*xlog)(nil)
var _ io.Writer = (*xlog)(nil)

// NewAndroidConsole returns a Console that writes to Android logcat.
func NewAndroidConsole() Console {
	return &xlog{}
}

// Log implements Console.
func (a *xlog) Log(level LogLevel, msg Logmsg) {
	if len(msg) <= 0 {
		return
	}
	cstr := C.CString(string(msg))
	C.__android_log_write(androidPriority(level), ctag, cstr)
	C.free(unsafe.Pointer(cstr))
}

func (a *xlog) Write(p []byte) (n int, err error) {
	s := strings.TrimRight(string(p), "\n\r")
	for line := range strings.SplitSeq(s, "\n") {
		lvl, msg := splitmsg([]byte(line))
		if len(msg) > 0 {
			a.Log(lvl, msg)
		}
	}
	return len(p), nil
}

// androidPriority maps a LogLevel to the corresponding Android log priority.
func androidPriority(level LogLevel) C.int {
	switch level {
	case VVERBOSE, VERBOSE, DEBUG:
		return C.ANDROID_LOG_DEBUG
	case INFO, USR:
		return C.ANDROID_LOG_INFO
	case WARN:
		return C.ANDROID_LOG_WARN
	case ERROR, STACKTRACE:
		return C.ANDROID_LOG_ERROR
	default:
		return C.ANDROID_LOG_DEBUG
	}
}
