// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import "sync"

// RollingWaitGroup is like sync.WaitGroup but rolls over to a new internal
// WaitGroup after each Wait() call. This allows reuse of the same RollingWaitGroup
// for multiple wait cycles, without having to create a new instance each time.
// Each Add() call returns a generation number that must be passed to the
// corresponding Done() call. This ensures that Done() calls from a previous
// generation do not affect the current generation.
type RollingWaitGroup struct {
	mu         sync.Mutex
	generation uint
	deltas     [2]int
	wgs        [2]*sync.WaitGroup
}

// Add adds delta, which may be negative, to the WaitGroup counter for the
// current generation.
func (m *RollingWaitGroup) Add(delta uint16) bool {
	d := int(delta)
	if d < 0 {
		return false
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.generation % 2
	if wg := m.wgs[g]; wg == nil {
		m.wgs[g] = &sync.WaitGroup{}
	}
	m.wgs[g].Add(d)
	m.deltas[g] += d
	return true
}

// Done decrements the WaitGroup counter for the current generation by one.
func (m *RollingWaitGroup) Done() {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.generation % 2
	if m.deltas[g] <= 0 {
		m.wgs[g] = nil // should already be nil, but just in case
		return
	}
	wg := m.wgs[g]
	if wg == nil {
		m.deltas[g] = 0 // should already be 0, but just in case
		return
	}

	m.deltas[g] = m.deltas[g] - 1
	if m.deltas[g] == 0 {
		m.wgs[g] = nil
		m.generation++
	}

	wg.Done()
}

// Wait blocks until the WaitGroup counter for the current generation is zero.
// It then rolls over to a new generation. It is safe to call Wait concurrently
// with Add and Done.
func (m *RollingWaitGroup) Wait() {
	m.mu.Lock()
	g := m.generation % 2
	wg := m.wgs[g]
	d := m.deltas[g]
	if wg == nil || d <= 0 {
		m.wgs[g] = nil  // should already be nil, but just in case
		m.deltas[g] = 0 // should already be 0, but just in case
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()

	wg.Wait()
}

// WouldWait returns true if the WaitGroup counter for the current generation
// is non-zero.
func (m *RollingWaitGroup) WouldWait() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.generation % 2
	delta := m.deltas[g]
	return delta > 0
}
