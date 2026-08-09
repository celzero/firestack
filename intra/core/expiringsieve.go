// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Sieve2K is a map of expiring maps. The outer map is keyed to K1,
// while the inner expiring maps are keyed to K2.
type Sieve2K[K1, K2 comparable, V any] struct {
	id   string // identifier; used in metrics
	ctx  context.Context
	mu   sync.RWMutex // protects m, c
	m    map[K1]*Sieve[K2, V]
	d    map[K1]context.CancelFunc
	life time.Duration

	nputs atomic.Uint64 // count of Put() calls
	ngets atomic.Uint64 // count of Get() calls
	ndels atomic.Uint64 // count of Del() calls
}

// NewSieve2K returns a new Sieve2K with keys expiring after lifetime.
func NewSieve2K[K1, K2 comparable, V any](ctx context.Context, id string, dur time.Duration) *Sieve2K[K1, K2, V] {
	s := &Sieve2K[K1, K2, V]{
		id:   id,
		ctx:  ctx,
		m:    make(map[K1]*Sieve[K2, V]),
		d:    make(map[K1]context.CancelFunc),
		life: dur,
	}
	s.id = s.id + "." + LocStr(s)
	dereg := trackmap(s.id, s.Stat)
	context.AfterFunc(ctx, dereg)
	return s
}

// Sieve is a thread-safe map with expiring keys.
type Sieve[K comparable, V any] struct {
	id string
	c  *ExpMap[K, V]
}

// NewSieve returns a new Sieve with keys expiring after lifetime.
func NewSieve[K comparable, V any](ctx context.Context, id string, dur time.Duration) *Sieve[K, V] {
	s := &Sieve[K, V]{
		id: id,
		c:  NewExpiringMapLifetime[K, V](ctx, id, dur),
	}
	s.id = s.id + "." + LocStr(s)
	dereg := trackmap(s.id, s.Stat)
	context.AfterFunc(ctx, dereg)
	return s
}

// newInnerSieve creates a Sieve without registering it in the global map registry.
// Used internally by Sieve2K to avoid polluting the registry with implementation details.
func newInnerSieve[K comparable, V any](ctx context.Context, id string, dur time.Duration) *Sieve[K, V] {
	s := &Sieve[K, V]{
		id: id,
		c:  NewExpiringMapLifetime[K, V](ctx, id, dur),
	}
	s.id = s.id + "." + LocStr(s)
	return s
}

// Get returns the value associated with the given key,
// and a boolean indicating whether the key was found.
func (s *Sieve[K, V]) Get(k K) (V, bool) {
	return s.c.V(k)
}

// Put adds/updates k->v with lifetime; returns whether a
// not-expired entry was replaced or inserted/revived after expiry.
func (s *Sieve[K, V]) Put(k K, v V) (replaced bool) {
	_, replaced = s.c.Upsert(k, v, s.c.minlife)
	return replaced
}

// Del removes the element with the given key from the sieve.
func (s *Sieve[K, V]) Del(k K) bool {
	return s.c.Delete(k)
}

// Len returns the number of elements in the sieve.
func (s *Sieve[K, V]) Len() int {
	if s == nil || s.c == nil {
		return 0
	}

	return s.c.Len()
}

// Clear removes all elements from the sieve.
func (s *Sieve[K, V]) Clear() int {
	if s == nil || s.c == nil {
		return 0
	}
	return s.c.Clear()
}

// Stat returns a snapshot of the sieve's current state.
func (s *Sieve[K, V]) Stat() MapState {
	if s == nil || s.c == nil {
		return MapState{}
	}
	return s.c.Stat()
}

// Get returns the value associated with the given key,
// and a boolean indicating whether the key was found.
func (s *Sieve2K[K1, K2, V]) Get(k1 K1, k2 K2) (zz V, ok bool) {
	s.ngets.Add(1)
	s.mu.RLock()
	inn := s.m[k1]
	s.mu.RUnlock()

	if inn != nil {
		return inn.Get(k2)
	}
	return
}

// Put adds an element to the sieve with the given key and value.
func (s *Sieve2K[K1, K2, V]) Put(k1 K1, k2 K2, v V) (replaced bool) {
	s.nputs.Add(1)
	s.mu.RLock()
	inn := s.m[k1]
	s.mu.RUnlock()

	if inn == nil {
		s.mu.Lock()
		inn = s.m[k1]
		if inn == nil {
			ctx, done := context.WithCancel(s.ctx)
			inn = newInnerSieve[K2, V](ctx, s.id+".inner", s.life)
			// Hook inner reaper: when inner becomes empty (via expiry
			// reaps), reclaim the outer entry without a dedicated ticker.
			k1copy := k1
			inn.c.clearall = func() { s.reclaimIfEmpty(k1copy) }
			s.m[k1] = inn
			s.d[k1] = done
		}
		s.mu.Unlock()
	}

	return inn.Put(k2, v)
}

// Del removes the element with the given key from the sieve.
func (s *Sieve2K[K1, K2, V]) Del(k1 K1, k2 K2) (deleted bool) {
	s.mu.RLock()
	inn := s.m[k1]
	if inn != nil {
		deleted = inn.Del(k2)
	}
	empty := inn == nil || inn.Len() == 0 // inn may be nil
	s.mu.RUnlock()

	if deleted {
		s.ndels.Add(1)
	}

	if empty {
		s.mu.Lock()
		inn = s.m[k1]   // inn may be nil
		done := s.d[k1] // done may be nil
		if inn.Len() == 0 {
			delete(s.m, k1)
			delete(s.d, k1)
			if done != nil {
				done()
			}
		}
		s.mu.Unlock()
	}
	return deleted
}

// Len returns the number of elements in the sieve.
func (s *Sieve2K[K1, K2, V]) Len() (n int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, inn := range s.m {
		n += inn.Len()
	}
	return
}

// Clear removes all elements from the sieve.
func (s *Sieve2K[K1, K2, V]) Clear() (n int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, inn := range s.m {
		d := inn.Clear()
		n += d
		s.ndels.Add(uint64(d))
	}
	for _, done := range s.d {
		done()
	}

	clear(s.m)
	clear(s.d)
	return
}

func (s *Sieve2K[K1, K2, V]) reclaimIfEmpty(k1 K1) {
	s.mu.Lock()
	defer s.mu.Unlock()

	inn := s.m[k1]
	if inn == nil || inn.c == nil {
		if done := s.d[k1]; done != nil {
			done()
		}
		delete(s.m, k1)
		delete(s.d, k1)
		return
	}
	// reaper already did the single purgeLocked sweep; just check emptiness.
	// No second purge here — avoids reaper -> clearall -> purgeLocked cycle.
	if inn.Len() == 0 {
		if done := s.d[k1]; done != nil {
			done()
		}
		delete(s.m, k1)
		delete(s.d, k1)
	}
}

// Stat returns a snapshot of the sieve's current state.
func (s *Sieve2K[K1, K2, V]) Stat() MapState {
	return MapState{
		ID:   s.id,
		Len:  uint64(s.Len()),
		Puts: s.nputs.Load(),
		Gets: s.ngets.Load(),
		Dels: s.ndels.Load(),
	}
}
