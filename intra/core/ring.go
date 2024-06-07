// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import "sync"

// A thread-safe ring buffer implementation
type Ring[T any] struct {
	sync.RWMutex
	buf  []T
	head int
	tail int
}

// NewRing creates a new ring buffer with the given capacity
func NewRing[T any](capacity int) *Ring[T] {
	return &Ring[T]{buf: make([]T, capacity)}
}

// Push adds an element to the ring buffer
func (r *Ring[T]) Push(v T) {
	r.Lock()
	defer r.Unlock()

	r.buf[r.head] = v
	r.head = (r.head + 1) % len(r.buf)
	if r.head == r.tail {
		r.tail = (r.tail + 1) % len(r.buf)
	}
}

// Pop removes and returns the oldest element from the ring buffer
func (r *Ring[T]) Pop() (v T) {
	r.Lock()
	defer r.Unlock()

	if r.head == r.tail {
		return
	}
	v = r.buf[r.tail]
	r.tail = (r.tail + 1) % len(r.buf)
	return v
}

// Len returns the number of elements in the ring buffer
func (r *Ring[T]) Len() int {
	r.RLock()
	defer r.RUnlock()

	if r.head >= r.tail {
		return r.head - r.tail
	}
	return len(r.buf) - r.tail + r.head
}

// Cap returns the capacity of the ring buffer
func (r *Ring[T]) Cap() int {
	r.RLock()
	defer r.RUnlock()

	return len(r.buf)
}

// Peek returns the oldest element from the ring buffer without removing it
func (r *Ring[T]) Peek() (v T) {
	r.RLock()
	defer r.RUnlock()

	if r.head == r.tail {
		return
	}
	return r.buf[r.tail]
}

// Reset resets the ring buffer
func (r *Ring[T]) Reset() {
	r.Lock()
	defer r.Unlock()

	r.head = 0
	r.tail = 0
}

// Iter returns a channel that yields all elements in the ring buffer
func (r *Ring[T]) Iter() <-chan interface{} {
	ch := make(chan interface{})
	go func() {
		defer close(ch)
		r.Lock()
		defer r.Unlock()

		for i := r.tail; i != r.head; i = (i + 1) % len(r.buf) {
			ch <- r.buf[i]
		}
	}()
	return ch
}

// IterBack returns a channel that yields all elements in the ring buffer in reverse order
func (r *Ring[T]) IterBack() <-chan interface{} {
	ch := make(chan interface{})
	go func() {
		defer close(ch)
		r.Lock()
		defer r.Unlock()

		for i := r.head - 1; i != r.tail-1; i-- {
			if i < 0 {
				i = len(r.buf) - 1
			}
			ch <- r.buf[i]
		}
	}()
	return ch
}
