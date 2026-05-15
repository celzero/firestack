// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build !(android && cgo)

package log

import (
	"fmt"
	"io"
	"strings"
)

// xlog pipes logs to logcat on Android; to fmt.Print otherwise.
type xlog struct{}

var _ Console = (*xlog)(nil)
var _ io.Writer = (*xlog)(nil)

// Log implements Console.
func (a *xlog) Log(level LogLevel, msg Logmsg) {
	fmt.Printf("%s\n", msg)
}

// Write implements io.Writer.
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
