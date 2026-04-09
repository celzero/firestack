// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build !linux

package log

import "errors"

// Memconsole is an unsupported stub on non-Linux platforms.
type Memconsole struct{}

// NewMemoryBased is not supported on non-Linux platforms.
func NewMemoryBased() (*Memconsole, error) {
	return nil, errors.ErrUnsupported
}

// SetReader is a no-op stub on non-Linux platforms.
func (mc *Memconsole) SetReader(MemReader) {}

// BufSize is a no-op stub on non-Linux platforms.
func (mc *Memconsole) BufSize() int { return 0 }

// FDs is a no-op stub on non-Linux platforms.
func (mc *Memconsole) FDs() (mfd1, mfd2 int) { return -1, -1 }
