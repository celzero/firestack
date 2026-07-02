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

type Hangover struct {
	t atomic.Value // [time.Time]
}

func NewHangover() *Hangover {
	h := &Hangover{}
	h.t.Store(zerotime)
	return h
}

func (h *Hangover) start() time.Time {
	return h.t.Load().(time.Time)
}

func (h *Hangover) Note() {
	if s := h.start(); s.IsZero() {
		h.t.CompareAndSwap(s, time.Now())
	} // else: already started
}

func (h *Hangover) Break() {
	if s := h.start(); !s.IsZero() {
		h.t.CompareAndSwap(s, zerotime)
	} // else: already stopped
}

func (h *Hangover) Within(d time.Duration) bool {
	s := h.start()
	if s.IsZero() {
		return true
	}
	return time.Since(s) <= d
}

func (h *Hangover) Exceeds(d time.Duration) bool {
	return !h.Within(d)
}
