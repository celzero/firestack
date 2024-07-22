// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package core

import "sync/atomic"

// go.dev/play/p/hHKxNa8PD5v

// Volatile is a non-panicking, non-atomic atomic.Value.
type Volatile[T any] atomic.Value

// NewVolatile returns a new Volatile with the value t.
// Panics if t is nil.
func NewVolatile[T any](t T) *Volatile[T] {
	v := NewZeroVolatile[T]()
	// safe to call Store but not any other func on v from this ctor.
	v.Store(t)
	return v
}

// NewVolatile returns a new uninitialized Volatile.
func NewZeroVolatile[T any]() *Volatile[T] {
	// do not call into any func on the returned instance from this ctor.
	return new(Volatile[T])
}

// Load returns the value of a. May return zero value.
// This func is atomic.
func (a *Volatile[T]) Load() (t T) {
	if a == nil {
		return
	}
	aa := (*atomic.Value)(a)
	t, _ = aa.Load().(T)
	return
}

// Store stores the value t; creates a new Volatile[T] if t is nil.
// If a is nil, does nothing. This func is not atomic.
func (a *Volatile[T]) Store(t T) {
	if a == nil {
		return
	}
	a.safeStore(a.Load(), t)
}

// safeStore stores new in a, iff old & new are of the same concrete type.
// If old & new are not of the same concrete type, it creates a Volatile with new.
// If new is nil, sets a to NewZeroVolatile[T].
// If a is nil, does nothing. This func is not atomic.
func (a *Volatile[T]) safeStore(old, new T) {
	if a == nil {
		return
	}
	if IsNil(new) {
		*a = *NewZeroVolatile[T]()
		return
	}
	if IsNil(old) || TypeEq(old, new) {
		aa := (*atomic.Value)(a)
		aa.Store(new)
		return
	}
	// old is of a different concrete type
	*a = *NewZeroVolatile[T]()
	aa := (*atomic.Value)(a)
	aa.Store(new)
}

// Cas compares and swaps the value of a with new, returns true if the value was swapped.
// If new is nil, returns true; and sets a to NewZeroVolatile[T] non-atomically.
// If a is nil or old & new are not of same concrete type, returns false.
func (a *Volatile[T]) Cas(old, new T) (ok bool) {
	if a == nil {
		return
	}
	if IsNil(new) {
		*a = *NewZeroVolatile[T]()
		return true
	}
	if !TypeEq(old, new) {
		return
	}

	aa := (*atomic.Value)(a)
	return aa.CompareAndSwap(old, new)
}

// Swap assigns new and returns the old value, atomically.
// If a is nil, it returns zero value.
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
// old & new need not be the same concrete type. This func is not atomic.
func (a *Volatile[T]) Tango(new T) (old T) {
	if a == nil {
		return
	}

	defer a.safeStore(old, new)

	aa := (*atomic.Value)(a)
	return aa.Load().(T)
}
