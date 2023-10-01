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
	"sync"
	"sync/atomic"
	"time"
)

// V is an in-flight or completed Barrier.Do V
type V struct {
	wg  sync.WaitGroup
	Val any
	Dur time.Duration
	Err error
	N   atomic.Uint32
}

// Barrier represents a class of work and forms a namespace in
// which units of work can be executed with duplicate suppression.
type Barrier struct {
	sync.Mutex               // protects m
	m          map[string]*V // lazily initialized
}

func NewBarrier() *Barrier {
	return &Barrier{
		m: make(map[string]*V),
	}
}

// Do executes and returns the results of the given function, making
// sure that only one execution is in-flight for a given key at a
// time. If a duplicate comes in, the duplicate caller waits for the
// original to complete and receives the same results.
func (ba *Barrier) Do(k string, me func() (any, error)) *V {
	ba.Lock()
	c, ok := ba.m[k]
	if ok {
		ba.Unlock()

		c.N.Add(1)
		c.wg.Wait() // wait for the in-flight req to complete
		return c
	}
	c = new(V)
	c.wg.Add(1)
	ba.m[k] = c
	ba.Unlock()

	start := time.Now()
	c.Val, c.Err = me()
	c.Dur = time.Since(start)

	c.wg.Done() // unblock all waiters
	return c
}
