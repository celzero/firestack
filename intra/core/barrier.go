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
	"context"
	"errors"
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

var errTimeout = errors.New("core: timeout")

// Work is the type of the function to memoize.
type Work[T any] func() (T, error)
type Work1[T any] func(T) (T, error)
type WorkCtx[T any] func(context.Context) (T, error)

// V is an in-flight or completed Barrier.Do V
type V[T any, K comparable] struct {
	wg  sync.WaitGroup
	dob time.Time
	Val T
	Err error
	N   atomic.Uint32
}

func (v *V[t, k]) String() string {
	if v == nil {
		return "core.V: <nil>"
	}
	return fmt.Sprintf("v: %v // n: %d; exp: %s // err: %v", v.Val, v.N.Load(), v.dob, v.Err)
}

func (v *V[t, k]) E() string {
	if v == nil {
		return "core.V: <nil>"
	} else if ve := v.Err; ve == nil {
		return "core.V: no error"
	} else {
		return ve.Error()
	}
}

func (v *V[t, k]) id() string {
	return fmt.Sprintf("%p", v)
}

// Barrier represents a class of work and forms a namespace in
// which units of work can be executed with duplicate suppression.
type Barrier[T any, K comparable] struct {
	mu  sync.Mutex     // protects m
	m   map[K]*V[T, K] // caches in-flight and completed Vs
	ttl time.Duration  // time-to-live for completed Vs in m
	neg time.Duration  // time-to-live for errored Vs in m
	to  time.Duration  // timeout for Do(), Do1(), Go()
}

func NewKeyedBarrier[T any, K comparable](ttl time.Duration) *Barrier[T, K] {
	return NewBarrier2[T, K](ttl, ttl/5)
}

// NewBarrier returns a new Barrier with the given time-to-live for
// completed Vs.
func NewBarrier[T any](ttl time.Duration) *Barrier[T, string] {
	return NewBarrier2[T, string](ttl, ttl/5)
}

// NewBarrier2 returns a new Barrier with the time-to-lives for
// completed Vs (ttl) and errored Vs (neg).
func NewBarrier2[T any, K comparable](ttl, neg time.Duration) *Barrier[T, K] {
	return &Barrier[T, K]{
		m:   make(map[K]*V[T, K]),
		ttl: ttl,
		neg: max(1*time.Second /*min neg*/, neg),
		to:  ttl,
	}
}

func (ba *Barrier[T, K]) getLocked(k K) (*V[T, K], bool) {
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

func (ba *Barrier[T, K]) addLocked(k K) *V[T, K] {
	v := new(V[T, K])
	v.wg.Add(1)
	v.dob = time.Now()
	ba.m[k] = v
	return v
}

// Do executes and returns the results of the given function, making
// sure that only one execution is in-flight for a given key at a
// time. If a duplicate comes in, the duplicate caller waits for the
// original to complete and receives the same results.
func (ba *Barrier[T, K]) Do(k K, once Work[T]) (*V[T, K], int) {
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

	if _, completed := Grx("ba.do."+c.id(), func(_ context.Context) (*V[T, K], error) {
		c.Val, c.Err = once()
		return c, c.Err
	}, ba.to); !completed {
		c.Err = errTimeout
	}

	c.wg.Done() // unblock all waiters
	return c, Anew
}

// Do1 is like Do but for Work1 with one arg.
func (ba *Barrier[T, K]) Do1(k K, once Work1[T], arg T) (*V[T, K], int) {
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

	if _, completed := Grx("ba.do1."+c.id(), func(_ context.Context) (*V[T, K], error) {
		c.Val, c.Err = once(arg)
		return c, c.Err
	}, ba.to); !completed {
		c.Err = errTimeout
	}

	c.wg.Done() // unblock all waiters
	return c, Anew
}

// untested
func (ba *Barrier[T, K]) Go(k K, once Work[T]) <-chan *V[T, K] {
	ch := make(chan *V[T, K])

	Go("ba.go", func() {
		defer close(ch)

		ba.mu.Lock()
		c, _ := ba.getLocked(k)
		if c != nil {
			ba.mu.Unlock()

			c.N.Add(1)  // register presence
			c.wg.Wait() // wait for the in-flight req to complete
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
