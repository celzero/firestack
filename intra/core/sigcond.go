// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"sync/atomic"
	"time"
)

// A "signalable boolean". This is like sync.Cond but light-weight and
// only allows a single state transition: false -> true. Once signalled,
// it stays signalled forever. Waiters wait until the condition is true.
// This is useful for one-time events like "the connection is closed".
//
// It is safe for multiple goroutines to call Signal concurrently; only
// one will succeed and the others will be no-ops.
//
// It is safe for multiple goroutines to call Wait concurrently; all
// will be woken when the condition is signalled.
//
// It is safe for one goroutine to call Signal while other goroutines
// are calling Wait.
//
// It is not safe to reuse a SigCond after signalling it.
type SigCond struct {
	c chan struct{} // always unbuffered
	b atomic.Bool
}

func NewSigCond() *SigCond {
	return &SigCond{
		c: make(chan struct{}),
	}
}

// Cond returns true if the signal has been fired.
func (sc *SigCond) Cond() bool {
	return sc.b.Load()
}

// Wait waits until the condition is true.
// If the condition is already true, it returns immediately.
func (sc *SigCond) Wait() {
	if sc.b.Load() {
		return
	}
	<-sc.c
}

// TryWait waits until signalled, or until max time has elapsed.
// It returns true if signal fires, false if timeout elapsed.
// If already signalled, it returns immediately.
func (sc *SigCond) TryWait(timeout time.Duration) (fired bool) {
	if sc.b.Load() {
		return true
	}
	select {
	case <-sc.c:
		return true
	case <-time.After(timeout):
		return false
	}
}

// Signal sets the condition to true and wakes all waiters, if any.
func (sc *SigCond) Signal() (fired bool) {
	if sc.b.Swap(true) { // already true
		return false
	}
	close(sc.c)
	return true
}
