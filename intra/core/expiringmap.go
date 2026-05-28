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
	maxreapiter   = 50
	lifetime      = 0 * time.Millisecond
)

type val[V any] struct {
	v      V
	expiry time.Time
	hits   uint32
}

// ExpMap holds expiring keys and read hits.
type ExpMap[P comparable, Q any] struct {
	id         string // identifier; used in metrics
	sync.Mutex        // guards ExpMap.
	ctx        context.Context
	m          map[P]*val[Q]
	sigreap    chan struct{}
	lastreap   time.Time
	minlife    time.Duration

	ngets uint64 // count of Get() calls; under Mutex
	nsets uint64 // count of Set()/K() calls; under Mutex
	ndels uint64 // count of Delete() calls; under Mutex
}

// NewExpiringMap returns a new ExpMap with min lifetime of 0.
func NewExpiringMap[P comparable, Q any](ctx context.Context, id string) *ExpMap[P, Q] {
	m := NewExpiringMapLifetime[P, Q](ctx, id, lifetime)
	dereg := trackmap(m.id, m.Stat)
	context.AfterFunc(ctx, dereg)
	return m
}

func NewExpiringMapLifetime[P comparable, Q any](ctx context.Context, id string, min time.Duration) *ExpMap[P, Q] {
	m := &ExpMap[P, Q]{
		id:       id,
		ctx:      ctx,
		m:        make(map[P]*val[Q]),
		sigreap:  make(chan struct{}),
		lastreap: time.Now(),
		minlife:  min,
	}
	m.id = m.id + "." + LocStr(m)
	Gx1("expm.reaper."+m.id, m.reaper, ctx)
	// test: go.dev/play/p/EYq_STKvugb
	return m
}

// Stat returns a snapshot of the map's current state.
func (m *ExpMap[P, Q]) Stat() MapState {
	m.Lock()
	defer m.Unlock()
	return MapState{
		Typ:  "expmap",
		ID:   m.id,
		Len:  uint64(len(m.m)),
		Gets: m.ngets,
		Puts: m.nsets,
		Dels: m.ndels,
	}
}

// Get returns the number of hits for the given key.
func (m *ExpMap[P, Q]) Get(key P) uint32 {
	if done(m.ctx) {
		return 0
	}

	n := time.Now()

	m.Lock()
	defer m.Unlock()
	m.ngets++

	v, ok := m.m[key]
	if !ok {
		v = &val[Q]{
			expiry: n,
		}
		m.m[key] = v
		// new entries have expiry = now (immediately expired); signal the
		// reaper so they are eventually cleaned up even if Set/K is never
		// called. Without this, Get-only usage grows the map without bound.
		select {
		case m.sigreap <- struct{}{}:
		default:
		}
	} else if n.After(v.expiry) {
		v.hits = 0
	} else {
		v.hits++
	}
	return v.hits
}

// Set sets the expiry for the given key and returns the number of hits.
// expiry must be greater than the minimum lifetime.
func (m *ExpMap[P, Q]) Set(key P, expiry time.Duration) uint32 {
	if done(m.ctx) {
		return 0
	}

	if expiry < m.minlife {
		expiry = m.minlife
	}

	n := time.Now().Add(expiry)

	m.Lock()
	defer m.Unlock()
	m.nsets++

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

// K sets the (value, expiry) for the given key and returns the number of hits.
// expiry must be greater than the minimum lifetime.
func (m *ExpMap[P, Q]) K(key P, value Q, expiry time.Duration) uint32 {
	if done(m.ctx) {
		return 0
	}

	if expiry < m.minlife {
		expiry = m.minlife
	}

	n := time.Now().Add(expiry)

	m.Lock()
	defer m.Unlock()
	m.nsets++

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
	if done(m.ctx) {
		return // zz, false
	}

	m.Lock()
	defer m.Unlock()

	now := time.Now()
	if v, ok := m.m[key]; ok && v != nil {
		return v.v, now.Before(v.expiry)
	}
	return // zz, false
}

func (m *ExpMap[P, Q]) Alive(key P) bool {
	if done(m.ctx) {
		return false
	}

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
	m.ndels++
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
	m.ndels += uint64(l)
	clear(m.m)
	return l
}

// reaper deletes expired keys.
// Must always be called from a goroutine.
func (m *ExpMap[P, Q]) reaper(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			m.Clear()
			return
		case <-m.sigreap:
		}

		m.Lock()

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
				m.ndels++
				delete(m.m, k)
			}
			if i > maxreapiter {
				break
			}
		}
		m.Unlock()
	}
}

// done returns true if the context is done.
func done(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
	}
	return false
}
