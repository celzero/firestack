// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"syscall"
)

// RuntimeEnviron returns the Go runtime's cached environment slice.
func RuntimeEnviron() []string {
	return syscall.Environ()
}
