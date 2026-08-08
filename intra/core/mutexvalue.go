// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//	  Copyright (c) Tailscale Inc & contributors
//	  SPDX-License-Identifier: BSD-3-Clause

package core

import "sync"

// MutexValue is a value protected by a mutex.
// from: github.com/tailscale/tailscale/blob/8bebdca90/syncs/syncs.go#L110
type MutexValue[T any] struct {
	mu sync.Mutex
	v  T
}

func NewMutexValue[T any](v T) *MutexValue[T] {
	return &MutexValue[T]{v: v}
}

// WithLock calls f with a pointer to the value while holding the lock.
// The pointer must not leak beyond the call.
func (m *MutexValue[T]) WithLock(f func(p *T)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f(&m.v)
}

// Load returns a shallow copy of the underlying value.
func (m *MutexValue[T]) Load() T {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.v
}

// Store stores a shallow copy of the provided value.
func (m *MutexValue[T]) Store(v T) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.v = v
}

// Swap stores new into m and returns the previous value.
func (m *MutexValue[T]) Swap(new T) (old T) {
	m.mu.Lock()
	defer m.mu.Unlock()
	old, m.v = m.v, new
	return old
}
