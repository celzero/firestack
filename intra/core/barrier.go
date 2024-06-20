// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     Copyright 2013 The Go Authors.  All rights reserved.
//     Use of this source code is governed by a BSD-style
//     license that can be found in the LICENSE file.

package core

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// Anew is the value returned by Barrier.Do when the function was
	// executed and its results are stored in the Barrier.
	Anew = iota
	// Shared is the value returned by Barrier.Do when the function's
	// results are already stored in the Barrier.
	Shared
)

// Work is the type of the function to memoize.
type Work[T any] func() (T, error)
type Work1[T any] func(T) (T, error)

// V is an in-flight or completed Barrier.Do V
type V[T any] struct {
	wg  sync.WaitGroup
	dob time.Time
	Val T
	Err error
	N   atomic.Uint32
}

func (v *V[t]) String() string {
	return fmt.Sprintf("v: %v // n: %d; exp: %s // err: %v", v.Val, v.N.Load(), v.dob, v.Err)
}

// Barrier represents a class of work and forms a namespace in
// which units of work can be executed with duplicate suppression.
type Barrier[T any] struct {
	mu  sync.Mutex       // protects m
	m   map[string]*V[T] // caches in-flight and completed Vs
	ttl time.Duration    // time-to-live for completed Vs in m
	neg time.Duration    // time-to-live for errored Vs in m
}

// NewBarrier returns a new Barrier with the given time-to-live for
// completed Vs.
func NewBarrier[T any](ttl time.Duration) *Barrier[T] {
	return NewBarrier2[T](ttl, ttl/5)
}

// NewBarrier2 returns a new Barrier with the time-to-lives for
// completed Vs (ttl) and errored Vs (neg).
func NewBarrier2[T any](ttl, neg time.Duration) *Barrier[T] {
	return &Barrier[T]{
		m:   make(map[string]*V[T]),
		ttl: ttl,
		neg: max(1*time.Second /*min neg*/, neg),
	}
}

func (ba *Barrier[T]) getLocked(k string) (*V[T], bool) {
	v, ok := ba.m[k]
	if v != nil {
		ttl := ba.ttl
		if v.Err != nil {
			ttl = ba.neg
		}
		if time.Since(v.dob.Add(ttl)) > 0 {
			delete(ba.m, k)
			return nil, false
		}
	}
	return v, ok
}

func (ba *Barrier[T]) addLocked(k string) *V[T] {
	v := new(V[T])
	v.wg.Add(1)
	v.dob = time.Now()
	ba.m[k] = v
	return v
}

// Do executes and returns the results of the given function, making
// sure that only one execution is in-flight for a given key at a
// time. If a duplicate comes in, the duplicate caller waits for the
// original to complete and receives the same results.
func (ba *Barrier[T]) Do(k string, once Work[T]) (*V[T], int) {
	ba.mu.Lock()
	c, _ := ba.getLocked(k)
	if c != nil {
		ba.mu.Unlock()

		c.N.Add(1)  // register presence
		c.wg.Wait() // wait for the in-flight req to complete
		return c, Shared
	}
	c = ba.addLocked(k)
	ba.mu.Unlock()

	c.Val, c.Err = once()

	c.wg.Done() // unblock all waiters
	return c, Anew
}

// Do1 is like Do but for Work1 with one arg.
func (ba *Barrier[T]) Do1(k string, once Work1[T], arg T) (*V[T], int) {
	ba.mu.Lock()
	c, _ := ba.getLocked(k)
	if c != nil {
		ba.mu.Unlock()

		c.N.Add(1)  // register presence
		c.wg.Wait() // wait for the in-flight req to complete
		return c, Shared
	}
	c = ba.addLocked(k)
	ba.mu.Unlock()

	c.Val, c.Err = once(arg)

	c.wg.Done() // unblock all waiters
	return c, Anew
}

// untested
func (ba *Barrier[T]) Go(k string, once Work[T]) <-chan *V[T] {
	ch := make(chan *V[T])

	Go(k, func() {
		defer close(ch)

		ba.mu.Lock()
		c, _ := ba.getLocked(k)
		if c != nil {
			ba.mu.Unlock()

			c.N.Add(1) // register presence
			c.wg.Wait()
			ch <- c
			return
		}
		c = ba.addLocked(k)
		ba.mu.Unlock()

		c.Val, c.Err = once()

		c.wg.Done() // unblock all waiters
		ch <- c
	})

	return ch
}
