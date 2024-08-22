// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"sync"

	"github.com/celzero/firestack/intra/log"
)

type ConnTuple struct {
	CID string // conn id
	UID string // proc id
}

type ConnMapper interface {
	// Clear untracks all conns.
	Clear() []string
	// Track maps x[] to cid.
	Track(cid string, x ...MinConn) int
	// Get returns a conn mapped to connection id, cid.
	Get(cid string) []MinConn
	// Untrack closes all conns with connection id, cid.
	Untrack(cid string) int
	// UntrackBatch untracks one cid at a time.
	UntrackBatch(cids []string) []string
}

type cm struct {
	sync.RWMutex
	trac map[string][]MinConn // id -> conns
}

var _ ConnMapper = (*cm)(nil)

func NewConnMap() *cm {
	return &cm{
		trac: make(map[string][]MinConn),
	}
}

func NewConnDestMap() *cm {
	return &cm{
		trac: make(map[string][]MinConn),
	}
}

func (h *cm) Track(cid string, conns ...MinConn) (n int) {
	h.Lock()
	defer h.Unlock()

	if v, ok := h.trac[cid]; !ok {
		h.trac[cid] = conns
		n = len(conns)
	} else { // should not happen?
		h.trac[cid] = append(v, conns...)
		n = len(v) + len(conns)
	}

	log.D("connmap: track: %d conns for %s", n, cid)
	return
}

func (h *cm) Untrack(cid string) (n int) {
	h.Lock()
	defer h.Unlock()

	for _, c := range h.trac[cid] {
		if c != nil && IsNotNil(c) {
			_ = c.Close()
			n += 1
		}
	}
	delete(h.trac, cid)
	log.D("connmap: untrack: %d conns for %s", n, cid)
	return
}

func (h *cm) UntrackBatch(cids []string) (out []string) {
	h.Lock()
	defer h.Unlock()

	out = make([]string, 0, len(cids))
	for _, id := range cids {
		for _, c := range h.trac[id] {
			if c != nil && IsNotNil(c) {
				_ = c.Close()
			}
		}
		delete(h.trac, id)
		out = append(out, id)
	}
	log.D("connmap: untrack: batch %d conns", len(out))
	return
}

func (h *cm) Get(cid string) (conns []MinConn) {
	h.RLock()
	defer h.RUnlock()

	if conns, ok := h.trac[cid]; ok {
		return conns
	}
	return
}

func (h *cm) Clear() (cids []string) {
	h.Lock()
	defer h.Unlock()

	cids = make([]string, 0, len(h.trac))
	for k, v := range h.trac {
		CloseConn(v...)
		cids = append(cids, k)
	}
	clear(h.trac)
	log.D("connmap: clear: %d conns", len(cids))
	return
}
