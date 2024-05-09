// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package core

import "sync/atomic"

type Volatile[T any] atomic.Value

func NewVolatile[T any](t T) *Volatile[T] {
	v := new(Volatile[T])
	v.Store(t) // t may be nil
	return v
}

func (a *Volatile[T]) Load() (t T) {
	aa := (*atomic.Value)(a)
	t, _ = aa.Load().(T)
	return
}

func (a *Volatile[T]) Store(t T) {
	aa := (*atomic.Value)(a)
	aa.Store(t)
}

func (a *Volatile[T]) Cas(old, new T) bool {
	aa := (*atomic.Value)(a)
	return aa.CompareAndSwap(old, new)
}

func (a *Volatile[T]) Swap(new T) (old T) {
	aa := (*atomic.Value)(a)
	old, _ = aa.Swap(new).(T)
	return old
}
