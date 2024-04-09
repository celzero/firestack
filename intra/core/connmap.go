// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"net"
	"strings"
	"sync"
)

type ConnTuple struct {
	CID string // conn id
	UID string // proc id
}

type ConnMapper interface {
	Clear() []string
	Track(t ConnTuple, x ...net.Conn) int
	Find(dst string) (t []ConnTuple)
	FindAll(csvdst string) (t []ConnTuple)
	Get(cid string) []net.Conn
	Untrack(cid string) int
	UntrackBatch(cids []string) []string
}

type cm struct {
	sync.RWMutex
	conntracker map[string][]net.Conn  // id -> conns
	dsttracker  map[string][]ConnTuple // dst ipport -> conntuple
}

var _ ConnMapper = (*cm)(nil)

func NewConnMap() *cm {
	return &cm{
		conntracker: make(map[string][]net.Conn),
		dsttracker:  make(map[string][]ConnTuple),
	}
}

func (h *cm) Track(t ConnTuple, conns ...net.Conn) (n int) {
	h.Lock()
	defer h.Unlock()

	cid := t.CID

	if v, ok := h.conntracker[cid]; !ok {
		h.conntracker[cid] = conns
		n = len(conns)
	} else { // should not happen?
		h.conntracker[cid] = append(v, conns...)
		n = len(v) + len(conns)
	}
	h.trackDstLocked(t, conns)

	return
}

func (h *cm) trackDstLocked(t ConnTuple, conns []net.Conn) {
	for _, c := range conns {
		if c == nil {
			continue
		}
		raddr := c.RemoteAddr()
		if raddr == nil {
			continue
		}
		dst := raddr.String()
		if tups, ok := h.dsttracker[dst]; ok {
			h.dsttracker[dst] = append(tups, t)
		} else {
			h.dsttracker[dst] = []ConnTuple{t}
		}
	}
}

func (h *cm) Untrack(cid string) (n int) {
	h.Lock()
	defer h.Unlock()

	for _, c := range h.conntracker[cid] {
		if c != nil {
			n++
			h.untrackDstLocked(cid, c)
			go c.Close()
		}
	}
	delete(h.conntracker, cid)
	return
}

func (h *cm) untrackDstLocked(cid string, c net.Conn) {
	raddr := c.RemoteAddr()
	if raddr == nil {
		return
	}
	dst := raddr.String()
	if tups, ok := h.dsttracker[dst]; ok {
		for i, t := range tups {
			if t.CID == cid {
				// ids[i+1:] does not panic if i+1 is out of range
				// go.dev/play/p/troeQ5djf9h
				h.dsttracker[dst] = append(tups[:i], tups[i+1:]...)
				break
			}
		}
		if len(h.dsttracker[dst]) == 0 {
			delete(h.dsttracker, dst)
		}
	}
}

func (h *cm) UntrackBatch(cids []string) (out []string) {
	h.Lock()
	defer h.Unlock()

	out = make([]string, 0, len(cids))
	for _, id := range cids {
		for _, c := range h.conntracker[id] {
			if c != nil {
				h.untrackDstLocked(id, c)
				go c.Close()
			}
		}
		delete(h.conntracker, id)
		out = append(out, id)
	}
	return
}

func (h *cm) Get(cid string) (conns []net.Conn) {
	h.RLock()
	defer h.RUnlock()

	if conns, ok := h.conntracker[cid]; ok {
		return conns
	}
	return
}

func (h *cm) Find(dst string) (tups []ConnTuple) {
	if len(dst) == 0 {
		return
	}

	h.RLock()
	defer h.RUnlock()

	if tups, ok := h.dsttracker[dst]; ok {
		return tups
	}
	return
}

func (h *cm) FindAll(csvdst string) (out []ConnTuple) {
	out = make([]ConnTuple, 0)

	if len(csvdst) == 0 {
		return
	}

	h.RLock()
	defer h.RUnlock()

	dsts := strings.Split(csvdst, ",")
	for _, dst := range dsts {
		if tups, ok := h.dsttracker[dst]; ok {
			out = append(out, tups...)
		}
	}
	return
}

func (h *cm) Clear() (cids []string) {
	h.Lock()
	defer h.Unlock()

	cids = make([]string, 0, len(h.conntracker))
	for k, v := range h.conntracker {
		for _, c := range v {
			if c != nil {
				go c.Close()
			}
		}
		cids = append(cids, k)
	}
	clear(h.conntracker)
	clear(h.dsttracker)
	return
}
