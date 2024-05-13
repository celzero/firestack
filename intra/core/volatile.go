// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package core

import "sync/atomic"

type Volatile[T any] atomic.Value

// NewVolatile returns a new Volatile with the value t.
// Panics if t is nil.
func NewVolatile[T any](t T) *Volatile[T] {
	v := new(Volatile[T])
	v.Store(t)
	return v
}

// Load returns the value of a. May return nil.
func (a *Volatile[T]) Load() (t T) {
	aa := (*atomic.Value)(a)
	t, _ = aa.Load().(T)
	return
}

// Store stores the value t, panics if t is nil.
func (a *Volatile[T]) Store(t T) {
	aa := (*atomic.Value)(a)
	aa.Store(t)
}

// Cas compares and swaps the value of a with new, returns true if the value was swapped.
// Panics if new is nil.
func (a *Volatile[T]) Cas(old, new T) bool {
	aa := (*atomic.Value)(a)
	return aa.CompareAndSwap(old, new)
}

// Swap swaps the value of a with new, returns the old value.
// Panics if new is nil.
func (a *Volatile[T]) Swap(new T) (old T) {
	aa := (*atomic.Value)(a)
	old, _ = aa.Swap(new).(T)
	return old
}
