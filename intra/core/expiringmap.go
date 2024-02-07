// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"sync"
	"time"
)

var (
	reapthreshold = 5 * time.Minute
	maxreapiter   = 100
	sizethreshold = 500
)

type val struct {
	expiry time.Time
	hits   uint32
}

// ExpMap holds expiring keys and read hits.
type ExpMap struct {
	sync.Mutex // guards ExpMap.
	m          map[string]*val
	lastreap   time.Time
}

// NewExpiringMap returns a new ExpMap.
func NewExpiringMap() *ExpMap {
	m := &ExpMap{
		m:        make(map[string]*val),
		lastreap: time.Now(),
	}
	// test: go.dev/play/p/EYq_STKvugb
	return m
}

// Get returns the number of hits for the given key.
func (m *ExpMap) Get(key string) uint32 {
	n := time.Now()

	m.Lock()
	defer m.Unlock()

	v, ok := m.m[key]
	if !ok {
		v = &val{
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
func (m *ExpMap) Set(key string, expiry time.Duration) uint32 {
	n := time.Now().Add(expiry)

	m.Lock()
	defer m.Unlock()

	v, ok := m.m[key]
	if v == nil || !ok { // add new val
		v = &val{
			expiry: n,
		}
		m.m[key] = v
	} else if n.After(v.expiry) { // update expiry
		v.expiry = n
	} // else: no change

	go m.reaper()

	return v.hits
}

// Delete deletes the given key.
func (m *ExpMap) Delete(key string) {
	m.Lock()
	defer m.Unlock()

	delete(m.m, key)
}

// Len returns the number of keys, which may or may not have expired.
func (m *ExpMap) Len() int {
	m.Lock()
	defer m.Unlock()

	return len(m.m)
}

// Clear deletes all keys and returns the number of keys deleted.
func (m *ExpMap) Clear() int {
	m.Lock()
	defer m.Unlock()

	l := len(m.m)
	clear(m.m)
	return l
}

// reaper deletes expired keys.
func (m *ExpMap) reaper() {
	m.Lock()
	defer m.Unlock()

	l := len(m.m)
	if l < sizethreshold {
		return
	}

	now := time.Now()
	treap := m.lastreap.Add(reapthreshold)
	// if last reap was reap-threshold minutes ago...
	if now.Sub(treap) <= 0 {
		return
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
}
