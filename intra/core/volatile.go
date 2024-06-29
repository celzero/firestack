// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package core

import "sync/atomic"

// go.dev/play/p/hHKxNa8PD5v

// Volatile is a generic, non-panicking atomic.Value.
type Volatile[T any] atomic.Value

// NewVolatile returns a new Volatile with the value t.
// Panics if t is nil.
func NewVolatile[T any](t T) *Volatile[T] {
	v := NewZeroVolatile[T]()
	v.Store(t)
	return v
}

// NewVolatile returns a new uninitialized Volatile.
func NewZeroVolatile[T any]() *Volatile[T] {
	return new(Volatile[T])
}

// Load returns the value of a. May return zero value.
func (a *Volatile[T]) Load() (t T) {
	if a == nil {
		return
	}
	aa := (*atomic.Value)(a)
	t, _ = aa.Load().(T)
	return
}

// Store stores the value t; creates a new Volatile[T] if t is nil.
// If a is nil, does nothing.
func (a *Volatile[T]) Store(t T) {
	if a == nil {
		return
	}
	if IsNil(t) {
		*a = *NewZeroVolatile[T]()
		return
	}
	aa := (*atomic.Value)(a)
	aa.Store(t)
}

// Cas compares and swaps the value of a with new, returns true if the value was swapped.
// If new is nil, returns true; and sets a to NewZeroVolatile[T].
// If a is nil or old & new are not of same concrete type, returns false.
func (a *Volatile[T]) Cas(old, new T) (ok bool) {
	if a == nil || !TypeEq(old, new) {
		return
	}
	if IsNil(new) {
		*a = *NewZeroVolatile[T]()
		return true
	}

	aa := (*atomic.Value)(a)
	return aa.CompareAndSwap(old, new)
}

// Swap swaps the value of a with new, returns the old value.
// If a is nil, returns zero value.
// If new is nil, returns old value; and sets a to NewZeroVolatile[T].
// If old & new are not of the same concrete type, it panics.
func (a *Volatile[T]) Swap(new T) (old T) {
	if a == nil {
		return
	}
	if IsNil(new) {
		aa := (*atomic.Value)(a)
		old = aa.Load().(T)

		*a = *NewZeroVolatile[T]()
		return
	}
	aa := (*atomic.Value)(a)
	old, _ = aa.Swap(new).(T)
	return old
}

// Tango retrieves old value and loads in new non-atomically.
// If a is nil, returns zero value.
// If new is nil, returns zero value; and sets a to NewZeroVolatile[T].
// old & new need not be the same concrete type.
func (a *Volatile[T]) Tango(new T) (old T) {
	if a == nil {
		return
	}

	aa := (*atomic.Value)(a)
	old = aa.Load().(T)
	if IsNil(new) {
		*a = *NewZeroVolatile[T]()
		return
	}
	aa.Store(new)
	return
}
