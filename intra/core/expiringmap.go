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
)

type val struct {
	expiry time.Time
	hits   uint32
}

type ExpMap struct {
	sync.RWMutex
	m        map[string]*val
	lastreap time.Time
}

func NewExpiringMap() *ExpMap {
	m := &ExpMap{
		m:        make(map[string]*val),
		lastreap: time.Now(),
	}
	return m
}

func (m *ExpMap) Get(key string) uint32 {
	m.RLock()
	v, ok := m.m[key]
	m.RUnlock()

	if !ok {
		return 0
	}
	if time.Now().After(v.expiry) {
		v.hits = 0
	} else {
		v.hits += 1
	}
	return v.hits
}

func (m *ExpMap) Set(key string, expiry time.Duration) uint32 {
	n := time.Now().Add(expiry)

	m.Lock()
	defer m.Unlock()

	v, ok := m.m[key]
	if ok {
		v.expiry = n
	} else {
		v = &val{
			expiry: n,
		}
		m.m[key] = v
	}

	go m.reaper()

	return v.hits
}

func (m *ExpMap) Delete(key string) {
	m.Lock()
	defer m.Unlock()

	delete(m.m, key)
}

func (m *ExpMap) Len() int {
	m.RLock()
	defer m.RUnlock()

	return len(m.m)
}

func (m *ExpMap) Clear() {
	m.Lock()
	defer m.Unlock()

	m.m = make(map[string]*val)
}

func (m *ExpMap) reaper() {
	m.Lock()
	treap := m.lastreap.Add(reapthreshold)
	// if last reap was reap-threshold minutes ago...
	if time.Since(treap) > 0 {
		m.lastreap = time.Now()
		// reap up to maxreapiter entries
		i := 0
		for k, v := range m.m {
			i += 1
			if time.Since(v.expiry) > 0 {
				delete(m.m, k)
			}
			if i > maxreapiter {
				break
			}
		}
	}
	m.Unlock()
}
