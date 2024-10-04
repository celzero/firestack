// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/celzero/firestack/intra/log"
)

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
	// Len returns the number of tracked conns.
	Len() int
	// String returns a string repr of all tracked conns.
	String() string
}

type connstat struct {
	c []MinConn
	t time.Time
}

type cm struct {
	sync.RWMutex
	trac map[string]connstat // id -> conns
	sz   int
}

var _ ConnMapper = (*cm)(nil)

func NewConnMap() *cm {
	return &cm{
		trac: make(map[string]connstat),
	}
}

func (h *cm) Track(cid string, conns ...MinConn) (n int) {
	h.Lock()
	defer h.Unlock()

	n = h.addLocked(cid, conns)

	log.D("connmap: track: %d/%d conns for %s", n, h.sz, cid)
	return
}

func (h *cm) Untrack(cid string) (n int) {
	h.Lock()
	defer h.Unlock()

	n = h.delLocked(cid)
	log.D("connmap: untrack: %d/%d conns for %s", n, h.sz, cid)
	return
}

func (h *cm) addLocked(cid string, conns []MinConn) (n int) {
	if v, ok := h.trac[cid]; !ok {
		h.trac[cid] = connstat{conns, time.Now()}
		n = len(conns)
	} else { // should not happen?
		v.c = append(v.c, conns...)
		n = len(v.c)
	}

	h.sz += len(conns)
	return
}

func (h *cm) getLocked(cid string) *connstat {
	if v, ok := h.trac[cid]; ok {
		return &v
	}
	return nil
}

func (h *cm) delLocked(cid string) (n int) {
	if v, ok := h.trac[cid]; ok {
		CloseConn(v.c...)
		delete(h.trac, cid)
		n = len(v.c)
	}
	h.sz -= n
	return
}

func (h *cm) UntrackBatch(cids []string) (out []string) {
	h.Lock()
	defer h.Unlock()

	n := 0
	out = make([]string, 0, len(cids))
	for _, id := range cids {
		n += h.delLocked(id)
		out = append(out, id)
	}
	log.D("connmap: untrack: batch %d conns / %d cids", n, len(out))
	return
}

func (h *cm) Get(cid string) (conns []MinConn) {
	h.RLock()
	defer h.RUnlock()

	if cs := h.getLocked(cid); cs != nil {
		return cs.c
	}
	return nil
}

func (h *cm) String() string {
	h.RLock()
	defer h.RUnlock()

	var s strings.Builder
	for _, v := range h.trac {
		s.WriteString(fmt.Sprintf("%s\n", v.String()))
	}
	return s.String()
}

func (h *cm) Clear() (cids []string) {
	h.Lock()
	defer h.Unlock()

	cids = make([]string, 0, len(h.trac))
	for k, v := range h.trac {
		CloseConn(v.c...)
		cids = append(cids, k)
	}
	clear(h.trac)
	log.D("connmap: clear: %d conns", len(cids))
	return
}

func (h *cm) Len() int {
	h.RLock()
	defer h.RUnlock()

	return h.sz
}

func (c *connstat) String() string {
	return fmt.Sprintf("%s:%d[%s]", formatTime(c.t), len(c.c), conn2str(c.c...))
}

func formatTime(t time.Time) string {
	if s := int64(time.Since(t).Seconds()); s < 60 {
		return fmt.Sprintf("%ds", s)
	} else if s < 3600 {
		return fmt.Sprintf("%dm", s/60)
	} else {
		return fmt.Sprintf("%dh", s/3600)
	}
}

func conn2str(c ...MinConn) (csv string) {
	if len(c) == 0 {
		return ""
	}
	s := make([]string, 0, len(c))
	for _, v := range c {
		if v == nil || IsNil(v) {
			continue
		}
		laddr := v.LocalAddr()
		if cc, ok := v.(net.Conn); ok {
			raddr := cc.RemoteAddr()
			s = append(s, fmt.Sprintf("%s=>%s", laddr, raddr))
		} else if laddr != nil { // nilaway
			s = append(s, laddr.String())
		}
	}
	return strings.Join(s, ",")
}
