// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package multihost

import (
	"net/netip"
	"net/url"
	"strings"
	"sync"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
)

type MHMap struct {
	sync.RWMutex
	k          string // uniq identifier
	uniq       map[*MH]struct{}
	byIpp      map[netip.AddrPort]*MH // ip:port => MH
	byHostport map[string]*MH         // host:port => MH
}

func (m *MHMap) Get(hostOrIpport string) (h *MH, _ error) {
	if m == nil {
		return nil, errMhNotFound
	}
	m.RLock()
	defer m.RUnlock()

	host, port := normalize(hostOrIpport) // port may be 0
	if len(host) <= 0 {
		log.D("multihost: %s map: get for %s => %s:%d", m.k, hostOrIpport, host, port)
		return nil, url.InvalidHostError(hostOrIpport)
	}

	ipp, err := netip.ParseAddrPort(hostOrIpport)
	if err == nil { // is ip:port
		h = m.byIpp[ipp]
	} else { // may be host:port
		h = m.byHostport[hostOrIpport]
	}

	ok := h != nil
	logeif(!ok)("multihost: %s map: get: for %s [%s]; ok? %t, by ip? %t; parse-err: %v",
		m.k, hostOrIpport, ipp, ok, err == nil, err)

	if h == nil {
		return nil, core.JoinErr(err, errMhNotFound)
	}
	return h, nil
}

func (m *MHMap) Put(h *MH) (ok bool) {
	if h == nil {
		log.W("multihost: %s map: put: nil? %t", m.k, h == nil)
		return
	}

	m.Lock()
	defer m.Unlock()
	return m.putLocked(h)
}

func (m *MHMap) putLocked(h *MH) (ok bool) {
	if _, dup := m.uniq[h]; dup {
		log.W("multihost: %s map: put: dup; call refresh instead?", m.k, dup)
		return h.Len() > 0
	}

	ipps := h.Addrs()
	names := h.Names()
	ok = len(ipps) > 0 || len(names) > 0

	if ok { // overwrites all existing
		m.uniq[h] = struct{}{}
		for _, ipp := range ipps {
			m.byIpp[ipp] = h
		}
		for _, name := range names {
			m.byHostport[name] = h
		}
	}

	logeif(!ok)("multihost: %s map: %s put: ipps %d, names %d; ok? %t",
		m.k, h.o, len(ipps), len(names), ok)

	return
}

func (m *MHMap) Del(h *MH) (ok bool) {
	if h == nil {
		log.W("multihost: %s map: del: nil? %t", m.k, h == nil)
		return
	}

	m.Lock()
	defer m.Unlock()
	return m.delLocked(h)
}

func (m *MHMap) delLocked(h *MH) (ok bool) {
	ipps := h.Addrs()
	names := h.Names()
	ok = len(ipps) > 0 || len(names) > 0

	if ok {
		delete(m.uniq, h)
		for _, ip := range ipps {
			if x := m.byIpp[ip]; x == h {
				delete(m.byIpp, ip)
			}
		}
		for _, name := range names {
			if x := m.byHostport[name]; x == h {
				delete(m.byHostport, name)
			}
		}
	}

	logeif(!ok)("multihost: %s map: %s del: ipps %d, names %d",
		m.k, h.o, len(ipps), len(names))

	return
}

func (m *MHMap) Len() (n int64) {
	if m == nil {
		return
	}

	m.RLock()
	defer m.RUnlock()
	for h := range m.uniq {
		n += int64(h.Len())
	}
	return
}

func (m *MHMap) Refresh() (n int64) {
	if m == nil {
		return
	}

	m.Lock()
	defer m.Unlock()
	for h := range m.uniq {
		m.delLocked(h)
		n += int64(h.Refresh())
		m.putLocked(h)
	}
	return
}

func (m *MHMap) MaybeRefresh() (n int64) {
	if m == nil {
		return
	}

	m.Lock()
	defer m.Unlock()
	for h := range m.uniq {
		if _, stale := h.stale(); stale {
			m.delLocked(h)
			n += int64(h.Refresh())
			m.putLocked(h)
		}
	}
	return
}

func (m *MHMap) String() string {
	if m == nil {
		return "<nil>"
	}

	m.RLock()
	defer m.RUnlock()
	if len(m.uniq) <= 0 {
		return m.k + ": <empty>"
	}

	var sb strings.Builder
	sb.WriteString(m.k + ": ")
	for h := range m.uniq {
		sb.WriteString(h.String())
		sb.WriteString("  /  ")
	}
	return sb.String()
}

func NewMap(id string) *MHMap {
	return &MHMap{
		k:          id,
		uniq:       make(map[*MH]struct{}),
		byIpp:      make(map[netip.AddrPort]*MH),
		byHostport: make(map[string]*MH),
	}
}
