// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"syscall"
	_ "unsafe"
) // required for go:linkname

//go:linkname runtimeGoTraceback gotraceback
func runtimeGoTraceback() (level int32, all, crash bool)

// GoTraceback returns the Go runtime's current traceback settings.
func GoTraceback() (level int32, all, crash bool) {
	return runtimeGoTraceback()
}

// RuntimeEnviron returns the Go runtime's cached environment slice.
//
// Warning: building with this file enabled requires disabling the linker's
// linkname checks: `-ldflags=-checklinkname=0`.
func RuntimeEnviron() []string {
	return syscall.Environ()
}
