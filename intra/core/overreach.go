// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"runtime/debug"
	"syscall"
	_ "unsafe" // for go:linkname
)

// RuntimeEnviron returns the Go runtime's cached environment slice.
func RuntimeEnviron() []string {
	return syscall.Environ()
}

// github.com/golang/go/issues/69868
// Unfortunately, Android apps have AT_SECURE set
// (read bytes in /proc/self/auxv on non-rooted Androids).
// This means, on Go runtime fatal / throws and a few kinds of panics,
// only one line is output to logcat (Android's stderr) which makes it
// hard to tell just what went wrong. Android, does use unwinder for
// native apps, and the Android RunTime has its own unwinder;
// both of which traceback seemingly oblivious to AT_SECURE.
// Perhaps, there's security benefits to the Go runtime being this rigid
// about GOTRACEBACK, but for goos.IsAndroid (and for apps with uid > 10000),
// using AT_SECURE to determine "setuid-like" protections appears pointless.
func init() {
	// override runtime.secureMode
	// to make GOTRACEBACK work as expected on Android
	debug.SetTraceback("all")
	secureMode = false
}

func SecureMode(new bool) (prev bool) {
	prev = secureMode
	secureMode = new
	return prev
}

// RuntimeSecureMode reports whether the Go runtime is in secure mode.
func RuntimeSecureMode() (them, us bool) {
	return runtime_isSecureMode(), secureMode
}

func RuntimeGotraceback() (l int32, all, crash bool) {
	return runtime_gotraceback()
}

//go:linkname runtime_isSecureMode runtime.isSecureMode
func runtime_isSecureMode() bool

//go:linkname runtime_gotraceback runtime.gotraceback
func runtime_gotraceback() (int32, bool, bool)

// pushing func symbols does not work on go1.24+
// but pushing vars apparently still works provided
// -ldflags="checklinkname=0"

//go:linkname secureMode runtime.secureMode
var secureMode bool
