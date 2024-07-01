// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package log

import (
	"context"
	"sync"
)

// A thread-safe ring buffer implementation
type ring[T any] struct {
	sync.RWMutex
	ctx  context.Context
	b    []T    // buffer
	inC  chan T // input channel
	head int
	tail int
}

// NewRing creates a new ring buffer with the given capacity
func newRing[T any](ctx context.Context, capacity int) *ring[T] {
	r := &ring[T]{
		ctx: ctx,
		b:   make([]T, capacity),
		inC: make(chan T, capacity/2),
	}
	go r.process()
	return r
}

func (r *ring[T]) closeWaiter() {
	select {
	case <-r.ctx.Done():
		close(r.inC)
	}
}

// Push adds an element to the ring buffer
func (r *ring[T]) Push(v T) (ok bool) {
	select {
	case <-r.ctx.Done():
	default:
		select {
		case <-r.ctx.Done():
		case r.inC <- v:
			return true
		default: // over cap, drop
		}
	}
	return
}

// process reads from the input channel and adds elements to the ring buffer.
// Must be run in a goroutine.
func (r *ring[T]) process() {
	go r.closeWaiter()

	for v := range r.inC {
		r.Lock()
		r.b[r.head] = v
		r.head = (r.head + 1) % len(r.b)
		if r.head == r.tail {
			r.tail = (r.tail + 1) % len(r.b)
		}
		r.Unlock()
	}
}

// Pop removes and returns the oldest element from the ring buffer
func (r *ring[T]) Pop() (v T) {
	r.Lock()
	defer r.Unlock()

	if r.head == r.tail {
		return
	}
	v = r.b[r.tail]
	r.tail = (r.tail + 1) % len(r.b)
	return v
}

// Len returns the number of elements in the ring buffer
func (r *ring[T]) Len() int {
	r.RLock()
	defer r.RUnlock()

	if r.head >= r.tail {
		return r.head - r.tail
	}
	return len(r.b) - r.tail + r.head
}

// Cap returns the capacity of the ring buffer
func (r *ring[T]) Cap() int {
	r.RLock()
	defer r.RUnlock()

	return len(r.b)
}

// Peek returns the oldest element from the ring buffer without removing it
func (r *ring[T]) Peek() (v T) {
	r.RLock()
	defer r.RUnlock()

	if r.head == r.tail {
		return
	}
	return r.b[r.tail]
}

// Reset resets the ring buffer
func (r *ring[T]) Reset() {
	r.Lock()
	defer r.Unlock()

	r.head = 0
	r.tail = 0
}

// Iter returns a channel that yields all elements in the ring buffer
func (r *ring[T]) Iter() <-chan T {
	ch := make(chan T, r.Cap())

	go func() {
		defer close(ch)
		r.RLock()
		defer r.RUnlock()

		for i := r.tail; i != r.head; i = (i + 1) % len(r.b) {
			ch <- r.b[i]
		}
	}()
	return ch
}
