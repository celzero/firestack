// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"context"
	"sync"
	"time"
)

var (
	reapthreshold = 5 * time.Minute
	maxreapiter   = 100
	sizethreshold = 500
)

type val[V any] struct {
	v      V
	expiry time.Time
	hits   uint32
}

// ExpMap holds expiring keys and read hits.
type ExpMap[P comparable, Q any] struct {
	sync.Mutex // guards ExpMap.
	m          map[P]*val[Q]
	sigreap    chan struct{}
	lastreap   time.Time
}

// NewExpiringMap returns a new ExpMap.
func NewExpiringMap[P comparable, Q any](ctx context.Context) *ExpMap[P, Q] {
	m := &ExpMap[P, Q]{
		m:        make(map[P]*val[Q]),
		sigreap:  make(chan struct{}),
		lastreap: time.Now(),
	}
	go m.reaper(ctx)
	// test: go.dev/play/p/EYq_STKvugb
	return m
}

// Get returns the number of hits for the given key.
func (m *ExpMap[P, Q]) Get(key P) uint32 {
	n := time.Now()

	m.Lock()
	defer m.Unlock()

	v, ok := m.m[key]
	if !ok {
		v = &val[Q]{
			expiry: n,
		}
		m.m[key] = v
	} else if n.After(v.expiry) {
		v.hits = 0
	} else {
		v.hits++
	}
	return v.hits
}

// Set sets the expiry for the given key and returns the number of hits.
func (m *ExpMap[P, Q]) Set(key P, expiry time.Duration) uint32 {
	n := time.Now().Add(expiry)

	m.Lock()
	defer m.Unlock()

	v, ok := m.m[key]
	if v == nil || !ok { // add new val
		v = &val[Q]{
			expiry: n,
		}
		m.m[key] = v
	} else if n.After(v.expiry) { // update expiry
		v.expiry = n
	} // else: no change

	select {
	case m.sigreap <- struct{}{}:
	default:
	}

	var zz Q
	v.v = zz
	return v.hits
}

// Set sets the (value, expiry) for the given key and returns the number of hits.
func (m *ExpMap[P, Q]) K(key P, value Q, expiry time.Duration) uint32 {
	n := time.Now().Add(expiry)

	m.Lock()
	defer m.Unlock()

	v, ok := m.m[key]
	if v == nil || !ok { // add new val
		v = &val[Q]{
			expiry: n,
		}
		m.m[key] = v
	} else if n.After(v.expiry) { // update expiry
		v.expiry = n
	} // else: no change

	select {
	case m.sigreap <- struct{}{}:
	default:
	}

	v.v = value
	return v.hits
}

func (m *ExpMap[P, Q]) V(key P) (zz Q, fresh bool) {
	m.Lock()
	defer m.Unlock()

	now := time.Now()
	if v, ok := m.m[key]; ok && v != nil {
		return v.v, now.Before(v.expiry)
	}
	return // zz
}

func (m *ExpMap[P, Q]) Alive(key P) bool {
	m.Lock()
	defer m.Unlock()

	now := time.Now()
	if v, ok := m.m[key]; ok && v != nil {
		return now.Before(v.expiry)
	}
	return false
}

// Delete deletes the given key.
func (m *ExpMap[P, Q]) Delete(key P) {
	m.Lock()
	defer m.Unlock()

	delete(m.m, key)
}

// Len returns the number of keys, which may or may not have expired.
func (m *ExpMap[P, Q]) Len() int {
	m.Lock()
	defer m.Unlock()

	return len(m.m)
}

// Clear deletes all keys and returns the number of keys deleted.
func (m *ExpMap[P, Q]) Clear() int {
	m.Lock()
	defer m.Unlock()

	l := len(m.m)
	clear(m.m)
	return l
}

// reaper deletes expired keys.
// Must always be called from a goroutine.
func (m *ExpMap[P, Q]) reaper(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.sigreap:
		}
		m.Lock()

		l := len(m.m)
		if l < sizethreshold {
			m.Unlock()
			continue
		}

		now := time.Now()
		treap := m.lastreap.Add(reapthreshold)
		// if last reap was reap-threshold minutes ago...
		if now.Sub(treap) <= 0 {
			m.Unlock()
			continue
		}
		m.lastreap = now
		// reap up to maxreapiter entries
		i := 0
		for k, v := range m.m {
			i += 1
			if now.Sub(v.expiry) > 0 {
				delete(m.m, k)
			}
			if i > maxreapiter {
				break
			}
		}
		m.Unlock()
	}
}
