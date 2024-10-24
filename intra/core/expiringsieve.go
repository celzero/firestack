// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"context"
	"time"
)

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
