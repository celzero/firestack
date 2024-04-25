// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"sync/atomic"
	"time"
)

var zerotime = time.Time{}

type atomicatomic[T any] atomic.Value

func (a *atomicatomic[T]) Load() (t T) {
	aa := (*atomic.Value)(a)
	t, _ = aa.Load().(T)
	return
}

func (a *atomicatomic[T]) Store(t T) {
	aa := (*atomic.Value)(a)
	aa.Store(t)
}

func (a *atomicatomic[T]) Cas(old, new T) bool {
	aa := (*atomic.Value)(a)
	return aa.CompareAndSwap(old, new)
}

type Hangover struct {
	start *atomicatomic[time.Time]
}

func NewHangover() *Hangover {
	s := new(atomicatomic[time.Time])
	s.Store(zerotime)
	return &Hangover{start: s}
}

func (h *Hangover) Note() {
	s := h.start.Load()
	if s.IsZero() {
		h.start.Cas(s, time.Now())
	} // else: already started
}

func (h *Hangover) Break() {
	s := h.start.Load()
	if !s.IsZero() {
		h.start.Cas(s, zerotime)
	} // else: already stopped
}

func (h *Hangover) Within(d time.Duration) bool {
	s := h.start.Load()
	if s.IsZero() {
		return true
	}
	return time.Since(s) <= d
}
