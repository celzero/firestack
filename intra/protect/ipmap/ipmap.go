// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     Copyright 2019 The Outline Authors
//
//     Licensed under the Apache License, Version 2.0 (the "License");
//     you may not use this file except in compliance with the License.
//     You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
//     Unless required by applicable law or agreed to in writing, software
//     distributed under the License is distributed on an "AS IS" BASIS,
//     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//     See the License for the specific language governing permissions and
//     limitations under the License.

package ipmap

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
)

const maxFailLimit = 8

var zeroaddr = netip.Addr{}

// Type of IPSet.
type IPSetType int

const (
	Protected IPSetType = iota
	Regular
	AutoType
)

func (h IPSetType) String() string {
	switch h {
	case Protected:
		return "Protected"
	case Regular:
		return "Regular"
	case AutoType:
		return "Auto"
	default:
		return "Unknown"
	}
}

// IPMapper is an interface for resolving hostnames to IP addresses.
// For internal used by firestack.
type IPMapper interface {
	// net.Resolver does not impl Lookup
	// IPMapper must confirm to net.Resolver
	// Lookup(q []byte) ([]byte, error)
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// IPMap maps hostnames to IPSets.
type IPMap interface {
	IPMapper
	// Resolves hostname and adds the resulting IPs to its IPSet.
	Add(hostOrIP string) *IPSet
	// Get creates an IPSet for this hostname populated with the IPs
	// discovered by resolving it. Subsequent calls to Get return the
	// same IPSet. Never returns nil.
	Get(hostOrIP string) *IPSet
	// GetAny creates an IPSet for this hostname, which may be empty.
	// Subsequent calls to GetAny return the same IPSet. Never returns nil.
	GetAny(hostOrIP string) *IPSet
	// MakeIPSet creates an IPSet for this hostname bootstrapped with given IPs
	// or IP:Ports. Subsequent calls to MakeIPSet return a new, overriden IPSet.
	MakeIPSet(hostOrIP string, ipps []string, typ IPSetType) *IPSet
	// With sets the default resolver to use for hostname resolution.
	With(r IPMapper)
	// Clear removes all IPSets from the map.
	Clear()
}

type ipmap struct {
	sync.RWMutex
	m map[string]*IPSet
	p map[string]*IPSet // protected ips; immutable, never cleared
	r IPMapper          // always the default system resolver
}

// IPSet represents an unordered collection of IP addresses for a single host.
// One IP can be marked as confirmed to be working correctly.
type IPSet struct {
	sync.RWMutex                            // Protects this struct.
	ips          []netip.Addr               // All known IPs for the server.
	confirmed    *core.Volatile[netip.Addr] // netip.Addr confirmed to be working.
	typ          IPSetType                  // Regular, Protected, or AutoType
	r            IPMapper                   // For hostname resolution, never nil
	seed         []string                   // Bootstrap ips or ip:ports; may be nil.
	fails        atomic.Uint32              // Number of times the confirmed IP has failed.
}

func NewIPMap() *ipmap {
	return NewIPMapFor(nil)
}

// NewIPMapFor returns a fresh IPMap with r as its nameserver.
func NewIPMapFor(r IPMapper) *ipmap {
	return &ipmap{
		m: make(map[string]*IPSet),
		p: make(map[string]*IPSet),
		r: r, // may be nil
	}
}

func (m *ipmap) With(r IPMapper) {
	log.I("ipmap: new resolver; ok? %t", r != nil)
	m.r = r // may be nil
}

func (m *ipmap) Clear() {
	m.Lock()
	defer m.Unlock()

	sz := len(m.m)
	purge := make(chan *IPSet, sz)
	defer close(purge)

	core.Go("ipmap.goclear", func() {
		n := 0
		for s := range purge {
			s.clear()
			n++
		}
		log.D("ipmap: clear: done %d/%d sets", n, sz)
	})

	n := 0
	for _, s := range m.m { // regular / auto
		purge <- s // preserves seed addrs
		n++
	}
	for _, s := range m.p { // protected
		purge <- s // only clears confirmed ip
		n++
	}
	log.I("ipmap: clear: requested %d/%d sets", n, sz)
}

// Implements IPMapper.
func (m *ipmap) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	r := m.r // actual ipmapper implementation
	if r == nil {
		return nil, &net.DNSError{Err: "no resolver", Name: host, Server: "localhost"}
	}
	return r.LookupNetIP(ctx, network, host)
}

func (m *ipmap) Add(hostOrIP string) *IPSet {
	s := m.get(hostOrIP, AutoType)
	log.I("ipmap: Add: resolving %s", hostOrIP)
	if ok := s.add(hostOrIP); !ok {
		log.W("ipmap: Add: zero ips for %s", hostOrIP)
	}
	return s
}

func (m *ipmap) Get(hostOrIP string) *IPSet {
	s := m.get(hostOrIP, AutoType)
	if s.Empty() {
		log.I("ipmap: Get: resolving %s", hostOrIP)
		if ok := s.add(hostOrIP); !ok {
			log.W("ipmap: Get: zero ips for %s", hostOrIP)
		}
	}
	log.D("ipmap: Get: %s => %s", hostOrIP, s.Addrs())
	return s
}

func (m *ipmap) GetAny(hostOrIP string) *IPSet {
	return m.get(hostOrIP, AutoType) // may be empty
}

func (m *ipmap) get(hostOrIP string, typ IPSetType) (s *IPSet) {
	if host, _, err := net.SplitHostPort(hostOrIP); err == nil {
		hostOrIP = host
	}

	m.RLock()
	sp := m.p[hostOrIP]
	sr := m.m[hostOrIP]
	m.RUnlock()

	if sp != nil || typ == Protected {
		s = sp          // may be nil or empty
		typ = Protected // discard Regular or AutoType
	} else { // Regular or AutoType
		s = sr        // may be nil or empty
		typ = Regular // discard AutoType
	}

	if s == nil {
		s = m.makeIPSet(hostOrIP, nil, typ) // typ is never AutoType
	}

	return s
}

func (m *ipmap) MakeIPSet(hostOrIP string, ipps []string, typ IPSetType) *IPSet {
	if len(ipps) <= 0 && typ == Protected {
		// TODO: error?
		log.T(fmt.Sprintf("ipmap: renew: %s; empty seed for Protected!", hostOrIP))
	} else {
		log.D("ipmap: renew: %s / seed: %v / typ: %s", hostOrIP, ipps, typ)
	}
	if host, _, err := net.SplitHostPort(hostOrIP); err == nil {
		hostOrIP = host
	}
	return m.makeIPSet(hostOrIP, ipps, typ)
}

func (m *ipmap) makeIPSet(hostname string, ipps []string, typ IPSetType) *IPSet {
	if ipps == nil {
		ipps = []string{}
	}

	mm := m.m // Regular or AutoType
	if protect.NeverResolve(hostname) || typ == Protected {
		mm = m.p
		typ = Protected // discard Regular or AutoType
	} else {
		typ = Regular // discard AutoType
	}

	log.D("ipmap: makeIPSet: %s, seed: %v, typ: %s", hostname, ipps, typ)

	// TODO: disallow confirm/disconfirm if hostname is an IP address
	s := &IPSet{r: m, seed: ipps, confirmed: core.NewZeroVolatile[netip.Addr](), typ: typ, fails: atomic.Uint32{}}
	if ip, err := netip.ParseAddr(hostname); err == nil && !ip.IsUnspecified() && ip.IsValid() {
		log.D("ipmap: makeIPSet: %s for %s, confirmed addr %s", hostname, typ, ip)
		s.confirmed.Store(ip)
		s.Lock()
		s.addLocked(ip)
		s.Unlock()
	} else {
		s.confirmed.Store(zeroaddr)
	}

	totalseeds := s.bootstrap()

	// if typ is Protected, then seeds must never be empty
	if typ == Protected && totalseeds <= 0 {
		log.W("ipmap: makeIPSet: zero seeds; %s for type %s discarded", hostname, typ)
	} else {
		m.Lock()
		mm[hostname] = s
		m.Unlock()
	}

	return s
}

// Reports whether ip is in the set.  Must be called under RLock.
func (s *IPSet) hasLocked(ip netip.Addr) bool {
	for _, oldIP := range s.ips {
		if oldIP.Compare(ip) == 0 {
			return true
		}
	}
	return false
}

// Adds an IP to the set if it is not present.  Must be called under Lock.
func (s *IPSet) addLocked(ip netip.Addr) {
	uns := !ip.IsUnspecified()
	valip := ip.IsValid()
	newip := !s.hasLocked(ip.Unmap())
	if uns && valip && newip {
		// always unmapped; github.com/golang/go/issues/53607
		s.ips = append(s.ips, ip.Unmap())
	} else {
		log.D("ipmap: add: fail %s; !uns? %t, val? %t, !new? %t", ip, uns, valip, newip)
	}
}

// Returns bootstrap ips or ip:ports.
func (s *IPSet) Seed() []string {
	s.RLock()
	defer s.RLock()
	return s.seed
}

// add one or more IP addresses to the set.
// The hostname can be a domain name or an IP address.
func (s *IPSet) add(hostOrIP string) bool {
	if host, _, err := net.SplitHostPort(hostOrIP); err == nil {
		hostOrIP = host
	}
	r := s.r
	if r == nil { // unlikley; s.r is never nil
		log.W("ipmap: Add: no resolver for %s", hostOrIP)
		return false
	}

	resolved, err := r.LookupNetIP(context.Background(), "ip", hostOrIP)
	if err != nil {
		log.W("ipmap: Add: err resolving %s: %v", hostOrIP, err)
		return false
	} else {
		log.D("ipmap: Add: resolved? %s => %s", hostOrIP, resolved)
	}
	s.Lock()
	for _, addr := range resolved { // resolved may be nil
		s.addLocked(addr)
	}
	s.Unlock()
	ok := !s.Empty()
	if ok {
		s.fails.Store(0) // reset fails, since we have a new ips
	}
	return ok
}

// Adds one or more IP addresses to the set.
func (s *IPSet) bootstrap() (n int) {
	s.Lock()
	defer s.Unlock()

	for _, ipstr := range s.seed {
		ipstr = strings.TrimSpace(ipstr)
		if len(ipstr) <= 0 {
			continue
		}
		if ip, err := netip.ParseAddr(ipstr); err == nil {
			s.addLocked(ip)
			n += 1
		} else {
			if ipport, err2 := netip.ParseAddrPort(ipstr); err2 == nil {
				s.addLocked(ipport.Addr())
				n += 1
			} else {
				log.W("ipmap: seed: invalid ipstr %s: err1 %v / err2 %v", ipstr, err, err2)
			}
		}
	}
	return n
}

// Empty reports whether the set is empty.
func (s *IPSet) Empty() bool {
	return s.Size() == 0
}

func (s *IPSet) Size() uint32 {
	s.RLock()
	defer s.RUnlock()
	return uint32(len(s.ips))
}

// Addrs returns a copy of the IP set as a slice in random order.
// The slice is owned by the caller, but the elements are owned by the set.
func (s *IPSet) Addrs() []netip.Addr {
	s.RLock()
	ips := s.ips
	s.RUnlock()

	sz := len(ips)
	if sz <= 0 {
		return []netip.Addr{}
	}

	c := make([]netip.Addr, 0, sz)
	c = append(c, ips...)
	if len(c) > 2 {
		rand.Shuffle(len(c), func(i, j int) {
			c[i], c[j] = c[j], c[i]
		})
	}
	return c
}

func (s *IPSet) Protected() bool {
	return s.typ == Protected
}

// Confirmed returns the confirmed IP address, or zeroaddr if there is no such address.
func (s *IPSet) Confirmed() netip.Addr {
	return s.confirmed.Load()
}

// Confirm marks ip as the confirmed address.
func (s *IPSet) Confirm(ip netip.Addr) {
	s.fails.Store(0) // reset fails, a new confirmed ip
	if ip.Compare(s.confirmed.Load()) == 0 {
		return
	}
	s.confirmed.Store(ip)
	core.Gx("ipset.confirm", func() {
		s.Lock()
		defer s.Unlock()

		s.addLocked(ip) // Add is O(N)
	})
}

func (s *IPSet) clear() {
	if s.typ != Protected {
		s.Lock()
		s.ips = nil
		s.Unlock()
	}
	s.confirmed.Store(zeroaddr)
	s.fails.Store(0)
}

// Disconfirm sets the confirmed address to zeroaddr if the current confirmed address
// is the provided ip.
func (s *IPSet) Disconfirm(ip netip.Addr) (ok bool) {
	c := s.confirmed.Load()
	if ip.Compare(c) == 0 {
		s.confirmed.Store(zeroaddr)
		ok = true
	}

	// if s is not empty, act on disconfirm
	if sz := s.Size(); sz > 0 {
		// either the confirmed was disconfirmed above
		// or s never had a confirmed ip, but still
		// Disconfirm() was called, indicating a failure
		if c.Compare(zeroaddr) == 0 {
			s.fails.Add(1)
		}
		if s.fails.Load() > max(2*sz, maxFailLimit) {
			// empty out the set, may be refilled by Get()
			s.clear()
		}
	}
	return
}
