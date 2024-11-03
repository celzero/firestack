// Copyright (c) 2024 RethinkDNS and its authors.
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

// Sieve2K is a map of expiring maps. The outer map is keyed to K1,
// while the inner expiring maps are keyed to K2.
type Sieve2K[K1, K2 comparable, V any] struct {
	ctx  context.Context
	mu   sync.RWMutex // protects m, c
	m    map[K1]*Sieve[K2, V]
	d    map[K1]context.CancelFunc
	life time.Duration
}

// NewSieve2K returns a new Sieve2K with keys expiring after lifetime.
func NewSieve2K[K1, K2 comparable, V any](ctx context.Context, dur time.Duration) *Sieve2K[K1, K2, V] {
	return &Sieve2K[K1, K2, V]{
		ctx:  ctx,
		m:    make(map[K1]*Sieve[K2, V]),
		d:    make(map[K1]context.CancelFunc),
		life: dur,
	}
}

// Sieve is a thread-safe map with expiring keys.
type Sieve[K comparable, V any] struct {
	c *ExpMap[K, V]
}

// NewSieve returns a new Sieve with keys expiring after lifetime.
func NewSieve[K comparable, V any](ctx context.Context, dur time.Duration) *Sieve[K, V] {
	return &Sieve[K, V]{
		c: NewExpiringMapLifetime[K, V](ctx, dur),
	}
}

// Get returns the value associated with the given key,
// and a boolean indicating whether the key was found.
func (s *Sieve[K, V]) Get(k K) (V, bool) {
	return s.c.V(k)
}

// Put adds an element to the sieve with the given key and value.
func (s *Sieve[K, V]) Put(k K, v V) (replaced bool) {
	return s.c.K(k, v, s.c.minlife) > 0
}

// Del removes the element with the given key from the sieve.
func (s *Sieve[K, V]) Del(k K) {
	s.c.Delete(k)
}

// Len returns the number of elements in the sieve.
func (s *Sieve[K, V]) Len() int {
	return s.c.Len()
}

// Clear removes all elements from the sieve.
func (s *Sieve[K, V]) Clear() int {
	return s.c.Clear()
}

// Get returns the value associated with the given key,
// and a boolean indicating whether the key was found.
func (s *Sieve2K[K1, K2, V]) Get(k1 K1, k2 K2) (zz V, ok bool) {
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
	s.mu.RLock()
	inn := s.m[k1]
	s.mu.RUnlock()

	if inn == nil {
		s.mu.Lock()
		inn = s.m[k1]
		if inn == nil {
			ctx, done := context.WithCancel(s.ctx)
			inn = NewSieve[K2, V](ctx, s.life)
			s.m[k1] = inn
			s.d[k1] = done
		}
		s.mu.Unlock()
	}

	return inn.Put(k2, v)
}

// Del removes the element with the given key from the sieve.
func (s *Sieve2K[K1, K2, V]) Del(k1 K1, k2 K2) {
	s.mu.RLock()
	inn := s.m[k1]
	if inn != nil {
		inn.Del(k2)
	}
	empty := inn.Len() == 0
	s.mu.RUnlock()

	if empty {
		s.mu.Lock()
		inn = s.m[k1]   // inn may be nil
		done := s.d[k1] // done may be nil
		if inn == nil || inn.Len() == 0 {
			delete(s.m, k1)
			delete(s.d, k1)
			if done != nil {
				done()
			}
		}
		s.mu.Unlock()
	}
}

// Len returns the number of elements in the sieve.
func (s *Sieve2K[K1, K2, V]) Len() (n int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, inn := range s.m {
		if inn == nil { // unlikely
			continue
		}
		n += inn.Len()
	}
	return
}

// Clear removes all elements from the sieve.
func (s *Sieve2K[K1, K2, V]) Clear() (n int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, inn := range s.m {
		n += inn.Clear()
	}
	for _, done := range s.d {
		done()
	}

	clear(s.m)
	clear(s.d)
	return
}
