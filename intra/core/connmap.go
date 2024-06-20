// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/celzero/firestack/intra/log"
)

type ConnTuple struct {
	CID string // conn id
	UID string // proc id
}

func (t ConnTuple) String() string {
	return t.CID + ":" + t.UID
}

type ConnMapper interface {
	Clear() []string
	Track(t ConnTuple, x ...net.Conn) int
	TrackDest(t ConnTuple, x netip.AddrPort) int
	Find(dst string) (t []ConnTuple)
	FindAll(csvips, port string) (t []ConnTuple)
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
	h.addToDstTrackerLocked(t, conns)

	log.D("connmap: track: %d conns for %s", n, cid)
	return
}

func (h *cm) TrackDest(t ConnTuple, x netip.AddrPort) (n int) {
	h.Lock()
	defer h.Unlock()

	return h.trackDestLocked(t, x.String())
}

func (h *cm) trackDestLocked(t ConnTuple, dst string) (n int) {
	if tups, ok := h.dsttracker[dst]; ok {
		// TODO: do not add dup ConnTuples
		h.dsttracker[dst] = append(tups, t)
		n = len(tups) + 1
	} else {
		h.dsttracker[dst] = []ConnTuple{t}
		n = 1
	}
	log.VV("connmap: trackDest: %d dst for %s", n, t.CID)
	return
}

func (h *cm) addToDstTrackerLocked(t ConnTuple, conns []net.Conn) (n int) {
	for _, c := range conns {
		if c == nil || IsNil(c) {
			continue
		}
		// TODO: handle unconnected udp sockets
		raddr := c.RemoteAddr()
		if raddr == nil {
			continue
		}
		n += h.trackDestLocked(t, raddr.String())
	}
	log.D("connmap: track: %d dst for %s", n, t.CID)
	return
}

func (h *cm) Untrack(cid string) (n int) {
	h.Lock()
	defer h.Unlock()

	for _, c := range h.conntracker[cid] {
		if c != nil && IsNotNil(c) {
			h.delFromDstTrackerLocked(cid, c)
			_ = c.Close()
			n += 1
		}
	}
	delete(h.conntracker, cid)
	log.D("connmap: untrack: %d conns for %s", n, cid)
	return
}

func (h *cm) delFromDstTrackerLocked(cid string, c net.Conn) (rmv bool) {
	raddr := c.RemoteAddr()
	if raddr == nil { // should not happen?
		log.W("connmap: untrack: no remote addr for %s", cid)
		return
	}
	dst := raddr.String()
	newtups := make([]ConnTuple, 0)
	if tups, ok := h.dsttracker[dst]; ok {
		for _, t := range tups {
			if t.CID == cid {
				log.D("connmap: untrack: dst %s -> %s", cid, dst)
				rmv = true
				// TODO: break if dups are handled in trackDstLocked
			} else {
				newtups = append(newtups, t)
			}
		}
		if len(newtups) == 0 {
			delete(h.dsttracker, dst)
		} else {
			h.dsttracker[dst] = newtups
		}
		log.VV("connmap: untrack: %d/%d dst for %s; rmv? %t", len(newtups), len(tups), cid, rmv)
	} else {
		log.V("connmap: untrack: no dst for %s", cid)
	}
	return
}

func (h *cm) UntrackBatch(cids []string) (out []string) {
	h.Lock()
	defer h.Unlock()

	out = make([]string, 0, len(cids))
	for _, id := range cids {
		for _, c := range h.conntracker[id] {
			if c != nil && IsNotNil(c) {
				h.delFromDstTrackerLocked(id, c)
				_ = c.Close()
			}
		}
		delete(h.conntracker, id)
		out = append(out, id)
	}
	log.D("connmap: untrack: batch %d conns", len(out))
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
		// too verbose: log.V("connmap: find: empty dst")
		return
	}

	h.RLock()
	defer h.RUnlock()
	// TODO: handle unconnected udp sockets
	tups = h.dsttracker[dst]
	log.VV("connmap: find: %d tuples for %s", len(tups), dst)
	return
}

func (h *cm) FindAll(csvips, port string) (out []ConnTuple) {
	out = make([]ConnTuple, 0)

	if len(csvips) == 0 {
		// too verbose: log.V("connmap: findAll: empty csvips")
		return
	}

	h.RLock()
	defer h.RUnlock()

	dsts := strings.Split(csvips, ",")
	for _, dst := range dsts {
		dst = net.JoinHostPort(dst, port)
		if tups, ok := h.dsttracker[dst]; ok {
			out = append(out, tups...)
		}
	}
	log.VV("connmap: findAll: %d tuples for %s", len(out), csvips)
	return
}

func (h *cm) Clear() (cids []string) {
	h.Lock()
	defer h.Unlock()

	cids = make([]string, 0, len(h.conntracker))
	for k, v := range h.conntracker {
		for _, c := range v {
			CloseConn(c)
		}
		cids = append(cids, k)
	}
	clear(h.conntracker)
	clear(h.dsttracker)
	log.D("connmap: clear: %d conns", len(cids))
	return
}
