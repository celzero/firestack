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

type ConnMapper interface {
	Clear() []string
	Track(id string, x ...net.Conn) int
	Find(dst string) (ids []string)
	FindAny(csvdst string) (ids []string)
	Get(id string) []net.Conn
	Untrack(id string) int
	UntrackBatch(ids []string) []string
}

type cm struct {
	sync.RWMutex
	conntracker map[string][]net.Conn // id -> conns
	dsttracker  map[string][]string   // dst ipport -> ids
}

var _ ConnMapper = (*cm)(nil)

func NewConnMap() *cm {
	return &cm{
		conntracker: make(map[string][]net.Conn),
		dsttracker:  make(map[string][]string),
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
	h.trackDstLocked(cid, conns)

	return
}

func (h *cm) trackDstLocked(cid string, conns []net.Conn) {
	for _, c := range conns {
		if c == nil {
			continue
		}
		raddr := c.RemoteAddr()
		if raddr == nil {
			continue
		}
		dst := raddr.String()
		if ids, ok := h.dsttracker[dst]; ok {
			h.dsttracker[dst] = append(ids, cid)
		} else {
			h.dsttracker[dst] = []string{cid}
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
	if ids, ok := h.dsttracker[dst]; ok {
		for i, id := range ids {
			if id == cid {
				// ids[i+1:] does not panic if i+1 is out of range
				// go.dev/play/p/troeQ5djf9h
				h.dsttracker[dst] = append(ids[:i], ids[i+1:]...)
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

func (h *cm) Get(id string) (conns []net.Conn) {
	h.RLock()
	defer h.RUnlock()

	if conns, ok := h.conntracker[id]; ok {
		return conns
	}
	return
}

func (h *cm) Find(dst string) (ids []string) {
	if len(dst) == 0 {
		return
	}

	h.RLock()
	defer h.RUnlock()

	if ids, ok := h.dsttracker[dst]; ok {
		return ids
	}
	return
}

func (h *cm) FindAny(csvdst string) (ids []string) {
	if len(csvdst) == 0 {
		return
	}

	h.RLock()
	defer h.RUnlock()

	dsts := strings.Split(csvdst, ",")
	for _, dst := range dsts {
		if ids, ok := h.dsttracker[string(dst)]; ok {
			return ids
		}
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
	clear(h.dsttracker)
	return
}
