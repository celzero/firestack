// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"crypto/tls"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unique"
	"weak"

	"slices"

	"github.com/celzero/firestack/intra/log"
)

var globalTLSSessionCache = tls.NewLRUClientSessionCache(1024 * 2)

func TlsSessionCache() tls.ClientSessionCache {
	return globalTLSSessionCache
}

type ConnMapper interface {
	// Clear untracks all conns.
	Clear() []string
	// Track maps x[] to cid.
	Track(cid, uid, pid string, x ...MinConn) int
	// Get returns a conn mapped to connection id, cid.
	Get(cid string) []MinConn
	// GetAll returns all conns mapped to pid or uid.
	GetAll(uidOrPid string) []MinConn
	// Untrack closes all conns with connection id, cid.
	Untrack(cid string) int
	// UntrackBatch untracks one cid at a time.
	UntrackBatch(cidsOrUidsOrPids []string) []string
	// Len returns the number of tracked conns.
	Len() int
	// String returns a string repr of all tracked conns.
	String() string
}

type connstat struct {
	c []MinConn
	t time.Time

	uid, pid string
}

type cm struct {
	id string // identifier; used in metrics
	sync.RWMutex
	tracc map[string]connstat // cid -> conns
	tracp map[string][]string // pid -> cid
	tracu map[string][]string // uid -> cid
	sz    int

	ntracks   atomic.Uint64 // count of Track() calls
	nuntracks atomic.Uint64 // count of Untrack() calls
	ngets     atomic.Uint64 // count of Get() / GetAll() calls
}

var _ ConnMapper = (*cm)(nil)

func NewConnMap(id string) *cm {
	m := &cm{
		id:    id,
		tracc: make(map[string]connstat),
		tracp: make(map[string][]string),
		tracu: make(map[string][]string),
	}
	m.id = m.id + "." + LocStr(m)
	id = m.id
	wm := weak.Make(m)
	deregister := trackmap(m.id, func() MapState {
		if p := wm.Value(); p != nil {
			return p.Stat()
		}
		return MapState{Typ: "connmap", ID: "gc." + id}
	})
	runtime.AddCleanup(m, func(f func()) { f() }, deregister)
	return m
}

// Stat returns a snapshot of the map's current state.
func (h *cm) Stat() MapState {
	h.RLock()
	l := h.sz
	h.RUnlock()
	return MapState{
		ID:   h.id,
		Typ:  "connmap",
		Len:  uint64(l),
		Puts: h.ntracks.Load(),
		Gets: h.ngets.Load(),
		Dels: h.nuntracks.Load(),
	}
}

func (h *cm) Track(cid, uid, pid string, conns ...MinConn) (n int) {
	h.ntracks.Add(1)
	h.Lock()
	defer h.Unlock()

	n = h.addLocked(cid, uid, pid, conns)

	log.D("connmap: track: %d/%d conns for %s+%s+%s", n, h.sz, cid, uid, pid)
	return
}

func (h *cm) Untrack(cid string) (n int) {
	h.nuntracks.Add(1)
	h.Lock()
	defer h.Unlock()

	n = h.delLocked(cid)
	log.D("connmap: untrack: %d/%d conns for %s", n, h.sz, cid)
	return
}

func (h *cm) addLocked(cid, uid, pid string, conns []MinConn) (n int) {
	if v, ok := h.tracc[cid]; !ok {
		h.tracc[cid] = connstat{conns, time.Now(), uid, pid}
		n = len(conns)
	} else { // should not happen?
		// TODO: append uid and pid?
		v.c = append(v.c, conns...)
		n = len(v.c)
		h.tracc[cid] = v
	}
	h.addByPidLocked(pid, cid)
	h.addByUidLocked(uid, cid)

	h.sz += len(conns)
	return
}

func (h *cm) addByPidLocked(pid, cid string) {
	if len(pid) <= 0 || len(cid) <= 0 {
		return
	}
	h.tracp[pid] = CopyUniq(h.tracp[pid], []string{cid})
}

func (h *cm) addByUidLocked(uid, cid string) {
	if len(uid) <= 0 || len(cid) <= 0 {
		return
	}
	h.tracu[uid] = CopyUniq(h.tracu[uid], []string{cid})
}

func (h *cm) getLocked(cid string) *connstat {
	if v, ok := h.tracc[cid]; ok {
		return &v
	}
	return nil
}

func (h *cm) getByUidLocked(uid string) []string {
	if v, ok := h.tracu[uid]; ok {
		return v
	}
	return nil
}

func (h *cm) getByPidLocked(pid string) []string {
	if v, ok := h.tracp[pid]; ok {
		return v
	}
	return nil
}

func (h *cm) delLocked(id string) (n int) {
	if v, ok := h.tracc[id]; ok {
		defer delete(h.tracc, id)
		defer h.delByPidLocked(v.pid, id)
		defer h.delByUidLocked(v.uid, id)

		n = len(v.c)
		CloseConn(v.c...)

		h.sz -= n
		// id maybe pid or uid
	} else if cidsByUid := h.getByUidLocked(id); len(cidsByUid) > 0 {
		// untrackBatchLocked calls delLocked per cid, which calls
		// delByUidLocked => slices.Delete on the same backing array we are
		// about to iterate; the in-place shift zeroes the tail and the range
		// loop skips entries (e.g. [c1,c2,c3] => delete c1 => [c2,c3,""],
		// loop reads index 1 = "c3", never sees "c2").
		return len(h.untrackBatchLocked(slices.Clone(cidsByUid)))
	} else if cidsByPid := h.getByPidLocked(id); len(cidsByPid) > 0 {
		return len(h.untrackBatchLocked(slices.Clone(cidsByPid)))
	} else {
		log.VV("connmap: untrack: id not tracked %s", id)
	}

	return
}

func (h *cm) delByPidLocked(pid, cid string) (deleted []string) {
	if len(pid) <= 0 {
		return
	}
	cids := h.tracp[pid]
	if len(cid) <= 0 { // delete all
		deleted = cids
		delete(h.tracp, pid)
		return
	}
	for i, id := range cids {
		if id == cid {
			deleted = append(deleted, id)
			if rem := slices.Delete(cids, i, i+1); len(rem) <= 0 {
				delete(h.tracp, pid)
				break
			} else {
				h.tracp[pid] = rem
			}
		}
	}
	return
}

func (h *cm) delByUidLocked(uid, cid string) (deleted []string) {
	if len(uid) <= 0 {
		return
	}
	cids := h.tracu[uid]
	if len(cid) <= 0 { // delete all
		deleted = cids
		delete(h.tracu, uid)
		return
	}
	for i, id := range cids {
		if id == cid {
			deleted = append(deleted, id)
			if rem := slices.Delete(cids, i, i+1); len(rem) <= 0 {
				delete(h.tracu, uid)
				break
			} else {
				h.tracu[uid] = rem
			}
		}
	}
	return
}

func (h *cm) UntrackBatch(cidsOrUidsOrPids []string) (closedCids []string) {
	h.Lock()
	defer h.Unlock()

	return h.untrackBatchLocked(cidsOrUidsOrPids)
}

func (h *cm) untrackBatchLocked(cidsOrUidsOrPids []string) (out []string) {
	processed := 0
	n := 0
	out = make([]string, 0, len(cidsOrUidsOrPids))
	for _, id := range cidsOrUidsOrPids {
		connsclosed := h.delLocked(id)
		if connsclosed > 0 {
			out = append(out, id)
			n += connsclosed
		}
		processed++
	}
	log.D("connmap: untrack: %d batches of %d/%d (conns/cids)", processed, n, len(out))
	return
}

func (h *cm) Get(cid string) (conns []MinConn) {
	h.ngets.Add(1)
	h.RLock()
	defer h.RUnlock()

	if cs := h.getLocked(cid); cs != nil {
		return cs.c
	}
	return nil
}

func (h *cm) GetAll(uidOrPid string) (conns []MinConn) {
	h.ngets.Add(1)
	h.RLock()
	defer h.RUnlock()

	if len(uidOrPid) <= 0 {
		return
	}
	cidsByPid := h.getByPidLocked(uidOrPid)
	cidsByUid := h.getByUidLocked(uidOrPid)
	// slices.Concat always allocates a new slice; using append(cidsByPid, cidsByUid...)
	// would mutate the map-owned backing array when cidsByPid has spare capacity
	// (left by slices.Delete), causing a data race between concurrent RLock readers.
	for _, cid := range slices.Concat(cidsByPid, cidsByUid) {
		if cs := h.getLocked(cid); cs != nil {
			conns = append(conns, cs.c...)
		}
	}
	return
}

func (h *cm) String() string {
	h.RLock()
	defer h.RUnlock()

	var s strings.Builder
	for id, cs := range h.tracc {
		s.WriteString(id)
		s.WriteString(cs.String())
		s.WriteString("\n")
	}
	return s.String()
}

func (h *cm) Clear() (cids []string) {
	h.Lock()
	defer h.Unlock()

	cids = make([]string, 0, len(h.tracc))
	for k, v := range h.tracc {
		CloseConn(v.c...)
		cids = append(cids, k)
	}
	clear(h.tracc)
	clear(h.tracu)
	clear(h.tracp)
	sz := h.sz
	closed := len(cids)
	h.sz = 0
	log.D("connmap: clear: closed %d/%d conns", closed, sz)
	return
}

func (h *cm) Len() int {
	h.RLock()
	defer h.RUnlock()

	return h.sz
}

func (c *connstat) String() string {
	if c == nil {
		return "<nil>"
	}
	return fmt.Sprintf(":%s+%s:%s:%d[%s]",
		c.pid, c.uid, FmtTimeAsPeriod(c.t), len(c.c), conn2str(c.c...))
}

func minconn2str(c ...MinConn) (csv string) {
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
			s = append(s, laddr.String()) // net.PacketConn
		}
	}
	return strings.Join(s, ",")
}

// use unique.Handle to handle conn2str
func conn2str(c ...MinConn) string {
	return UniqStr(minconn2str(c...))
}

func UniqStringer(s fmt.Stringer) string {
	return UniqStr(s.String())
}

// not always optimal: go.dev/blog/unique
// (a footnote about interning strings)
func UniqStr(s string) string {
	h := unique.Make(s)
	return h.Value()
}
