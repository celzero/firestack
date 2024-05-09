// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"time"
)

var zerotime = time.Time{}

type Hangover struct {
	start *Volatile[time.Time]
}

func NewHangover() *Hangover {
	return &Hangover{start: NewVolatile(zerotime)}
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

func (h *Hangover) Exceeds(d time.Duration) bool {
	return !h.Within(d)
}
