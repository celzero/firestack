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

import "sync/atomic"

// Volatile is a concurrency-safe holder for a value of type T.
// It never panics on inconsistent dynamic types, unlike sync/atomic.Value.
// github.com/tailscale/tailscaleblob/8bebdca90/syncs/syncs.go#L29
// cs.opensource.google/go/go/+/refs/tags/go1.22.2:src/sync/atomic/value.go;l=78
type Volatile[T any] struct {
	v atomic.Value // wrappedValue
}

// wrappedValue boxes T in a single concrete type for atomic.Value.
type wrappedValue[T any] struct{ v T }

// NewVolatile returns a new Volatile with the value t.
func NewVolatile[T any](t T) *Volatile[T] {
	v := &Volatile[T]{}
	v.Store(t)
	return v
}

// Load returns the value set by the most recent Store.
// Returns zero value if empty or if receiver is nil.
func (a *Volatile[T]) Load() T {
	v, _ := a.LoadOk()
	return v
}

// LoadOk is like Load but reports whether a value was present.
func (a *Volatile[T]) LoadOk() (T, bool) {
	if a == nil {
		var zz T
		return zz, false
	}
	if x := a.v.Load(); x != nil {
		return x.(wrappedValue[T]).v, true
	}
	var zz T
	return zz, false
}

// Store sets the value. Never panics on type mismatch.
func (a *Volatile[T]) Store(t T) {
	if a == nil {
		return
	}
	a.v.Store(wrappedValue[T]{t})
}

// Swap stores new and returns the previous value.
// Returns zero if empty or receiver is nil.
func (a *Volatile[T]) Swap(new T) (old T) {
	if a == nil {
		return
	}
	if ov := a.v.Swap(wrappedValue[T]{new}); ov != nil {
		return ov.(wrappedValue[T]).v
	}
	var zz T
	return zz
}

// Tango is an alias for Swap.
func (a *Volatile[T]) Tango(new T) (old T) {
	if a == nil {
		return
	}
	return a.Swap(new)
}

// Cas executes compare-and-swap. Never panics: returns false if T is not comparable.
func (a *Volatile[T]) Cas(old, new T) (ok bool) {
	if a == nil {
		return false
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				ok = false
			}
		}()
		if a.v.CompareAndSwap(wrappedValue[T]{old}, wrappedValue[T]{new}) {
			ok = true
			return
		}
		var zero T
		if any(old) == any(zero) && a.v.CompareAndSwap(nil, wrappedValue[T]{new}) {
			ok = true
		}
	}()
	return ok
}

// CompareAndSwap is an alias for Cas.
func (a *Volatile[T]) CompareAndSwap(old, new T) bool {
	return a.Cas(old, new)
}
