// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"net"
	"sync"
)

type ConnMapper interface {
	Clear() []string
	Track(id string, x ...net.Conn) int
	Untrack(id string) int
	UntrackBatch(ids []string) []string
}

type cm struct {
	sync.Mutex
	conntracker map[string][]net.Conn
}

var _ ConnMapper = (*cm)(nil)

func NewConnMap() *cm {
	return &cm{
		conntracker: make(map[string][]net.Conn),
	}
}

func (h *cm) Track(cid string, conns ...net.Conn) (n int) {
	h.Lock()
	defer h.Unlock()

	if v, ok := h.conntracker[cid]; !ok {
		h.conntracker[cid] = conns
		n = len(conns)
	} else { // should not happen?
		h.conntracker[cid] = append(v, conns...)
		n = len(v) + len(conns)
	}
	return
}

func (h *cm) Untrack(cid string) (n int) {
	h.Lock()
	defer h.Unlock()

	for _, c := range h.conntracker[cid] {
		if c != nil {
			n++
			go c.Close()
		}
	}
	delete(h.conntracker, cid)
	return
}

func (h *cm) UntrackBatch(cids []string) (out []string) {
	h.Lock()
	defer h.Unlock()

	out = make([]string, 0, len(cids))
	for _, id := range cids {
		for _, c := range h.conntracker[id] {
			if c != nil {
				go c.Close()
			}
		}
		delete(h.conntracker, id)
		out = append(out, id)
	}
	return
}

func (h *cm) Clear() (ids []string) {
	h.Lock()
	defer h.Unlock()

	ids = make([]string, 0, len(h.conntracker))
	for k, v := range h.conntracker {
		for _, c := range v {
			if c != nil {
				go c.Close()
			}
		}
		ids = append(ids, k)
	}
	clear(h.conntracker)
	return
}
