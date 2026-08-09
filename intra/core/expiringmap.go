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

	clearall Finally // called after reap if map is empty; set by Sieve2K

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

// Get returns the number of hits for the given key. On miss it inserts
// an immediately-expired entry (expiry=now, hits=0) so the reaper can GC
// Get-only keys; callers see 0 either way. On hit, it resets hits to 0,
// if expired, else increments by 1.
func (m *ExpMap[P, Q]) Get(key P) uint32 {
	if done(m.ctx) {
		return 0
	}
	n := time.Now()
	m.Lock()
	defer m.Unlock()
	m.ngets++
	v, ok := m.m[key]
	if !ok || v == nil {
		v = &val[Q]{expiry: n}
		m.m[key] = v
		select {
		case m.sigreap <- struct{}{}:
		default:
		}
		return 0
	}
	if n.After(v.expiry) {
		v.hits = 0
	} else {
		v.hits++
	}
	return v.hits
}

// Set sets the expiry for the given key and returns the number of hits.
// expiry is clamped to minlife. If the key was expired, its hit window
// is reset to 0 before returning. Value is set to Q's zero value.
func (m *ExpMap[P, Q]) Set(key P, expiry time.Duration) uint32 {
	if done(m.ctx) {
		return 0
	}
	var zz Q
	hits, _ := m.upsert(key, zz, expiry)
	return hits
}

// K sets the (value, expiry) for the given key and returns the number of hits.
// expiry is clamped to minlife. If the key was expired, its hit window
// is reset to 0 before returning.
func (m *ExpMap[P, Q]) K(key P, value Q, expiry time.Duration) uint32 {
	if done(m.ctx) {
		return 0
	}
	hits, _ := m.upsert(key, value, expiry)
	return hits
}

// Upsert is the single path for Set and K.
// Clamps expiry to minlife, resets hits when expiry is after existing expiry;
// returns total hits and whether a not-expired entry was replaced.
func (m *ExpMap[P, Q]) Upsert(key P, value Q, expiry time.Duration) (hits uint32, replaced bool) {
	return m.upsert(key, value, expiry)
}

func (m *ExpMap[P, Q]) upsert(key P, value Q, expiry time.Duration) (uint32, bool) {
	if expiry < m.minlife {
		expiry = m.minlife
	}
	now := time.Now()
	n := now.Add(expiry)
	m.Lock()
	defer m.Unlock()
	m.nsets++
	v, ok := m.m[key]
	replaced := ok && v != nil && now.Before(v.expiry)
	if v == nil || !ok {
		v = &val[Q]{expiry: n}
		m.m[key] = v
	} else {
		if now.After(v.expiry) {
			v.hits = 0
		}
		if n.After(v.expiry) {
			v.expiry = n
		}
	}
	select {
	case m.sigreap <- struct{}{}:
	default:
	}
	v.v = value
	return v.hits, replaced
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

// purgeLocked deletes all expired keys (now.After expiry).
// Caller must hold m.Mutex; it updates ndels and lastreap.
func (m *ExpMap[P, Q]) purgeLocked(now time.Time) int {
	if len(m.m) == 0 {
		return 0
	}
	n := 0
	for k, v := range m.m {
		if now.After(v.expiry) {
			delete(m.m, k)
			n++
		}
	}
	if n > 0 {
		m.ndels += uint64(n)
		m.lastreap = now
	}
	return n
}

func (m *ExpMap[P, Q]) purgeExpired(now time.Time) int {
	m.Lock()
	defer m.Unlock()
	return m.purgeLocked(now)
}

// reaper deletes expired keys — single reaper per ExpMap, no
// per-Sieve2K goroutine. Sieve2K outer leak is fixed by hooking
// inner reapers (see Sieve2K.Put/reclaimIfEmpty): when an inner
// becomes empty its hook reclaims the outer K1 entry.
// Single sweep path: purgeLocked is the only expiry loop.
func (m *ExpMap[P, Q]) reaper(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			m.Clear()
			if m.clearall != nil {
				m.clearall()
			}
			return
		case <-m.sigreap:
		}
		m.Lock()
		now := time.Now()
		if now.Sub(m.lastreap.Add(reapthreshold)) <= 0 {
			m.Unlock()
			continue
		}
		m.purgeLocked(now)
		empty := len(m.m) == 0
		m.Unlock()

		if empty && m.clearall != nil {
			m.clearall()
		}
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
