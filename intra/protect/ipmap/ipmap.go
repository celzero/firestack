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
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/celzero/firestack/intra/log"
)

const maxFailLimit = 4

var zeroaddr = netip.Addr{}

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
	MakeIPSet(hostOrIP string, ipps []string) *IPSet
	// With sets the default resolver to use for hostname resolution.
	With(r IPMapper)
	// Clear removes all IPSets from the map.
	Clear()
}

type ipmap struct {
	sync.RWMutex
	m map[string]*IPSet
	r IPMapper // always the default system resolver
}

// IPSet represents an unordered collection of IP addresses for a single host.
// One IP can be marked as confirmed to be working correctly.
type IPSet struct {
	sync.RWMutex              // Protects this struct.
	ips          []netip.Addr // All known IPs for the server.
	confirmed    atomic.Value // netip.Addr confirmed to be working.
	r            IPMapper     // Resolver to use for hostname resolution.
	seed         []string     // Bootstrap ips or ip:ports; may be nil.
	fails        int          // Number of times the confirmed IP has failed.
}

func NewIPMap() IPMap {
	return NewIPMapFor(nil)
}

// NewIPMapFor returns a fresh IPMap with r as its nameserver.
func NewIPMapFor(r IPMapper) IPMap {
	return &ipmap{
		m: make(map[string]*IPSet),
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
	clear(m.m)
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
	s := m.get(hostOrIP)
	log.I("ipmap: Add: resolving %s", hostOrIP)
	if ok := s.add(hostOrIP); !ok {
		log.W("ipmap: Add: zero ips for %s", hostOrIP)
	}
	return s
}

func (m *ipmap) Get(hostOrIP string) *IPSet {
	s := m.get(hostOrIP)
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
	return m.get(hostOrIP) // may be empty
}

func (m *ipmap) get(hostOrIP string) *IPSet {
	if host, _, err := net.SplitHostPort(hostOrIP); err == nil {
		hostOrIP = host
	}
	m.RLock()
	s := m.m[hostOrIP]
	m.RUnlock()

	if s == nil {
		s = m.makeIPSet(hostOrIP, nil)
	}

	return s
}

func (m *ipmap) MakeIPSet(hostOrIP string, ipps []string) *IPSet {
	log.D("ipmap: renew: %s / seed: %v", hostOrIP, ipps)
	if host, _, err := net.SplitHostPort(hostOrIP); err == nil {
		hostOrIP = host
	}
	return m.makeIPSet(hostOrIP, ipps)
}

func (m *ipmap) makeIPSet(hostname string, ipps []string) *IPSet {
	log.D("ipmap: makeIPSet: %s, seed: %v", hostname, ipps)

	if ipps == nil {
		ipps = []string{}
	}
	// TODO: disallow confirm/disconfirm if hostname is an IP address
	s := &IPSet{r: m, seed: ipps}
	if ip, err := netip.ParseAddr(hostname); err == nil && !ip.IsUnspecified() && ip.IsValid() {
		log.D("ipmap: makeIPSet: for ipaddr as confirmed %s", ip)
		s.confirmed.Store(ip)
		s.Lock()
		s.addLocked(ip)
		s.Unlock()
	} else {
		s.confirmed.Store(zeroaddr)
	}

	s.bootstrap()

	m.Lock()
	m.m[hostname] = s
	m.Unlock()

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
	if r == nil {
		log.W("ipmap: Add: (processing: %s) resolver missing", hostOrIP)
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
		s.fails = 0 // reset fails, since we have a new ips
	}
	return ok
}

// Adds one or more IP addresses to the set.
func (s *IPSet) bootstrap() (n int) {
	s.Lock()
	defer s.Unlock()

	for _, ipstr := range s.seed {
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
	s.RLock()
	defer s.RUnlock()
	return len(s.ips) == 0
}

// Addrs returns a copy of the IP set as a slice in random order.
// The slice is owned by the caller, but the elements are owned by the set.
func (s *IPSet) Addrs() []netip.Addr {
	s.RLock()
	sz := len(s.ips)
	if sz <= 0 {
		s.RUnlock()
		return nil
	}
	c := make([]netip.Addr, 0, sz)
	c = append(c, s.ips...)
	s.RUnlock()

	if len(c) > 2 {
		rand.Shuffle(len(c), func(i, j int) {
			c[i], c[j] = c[j], c[i]
		})
	}
	return c
}

// Confirmed returns the confirmed IP address, or zeroaddr if there is no such address.
func (s *IPSet) Confirmed() netip.Addr {
	ip, _ := s.confirmed.Load().(netip.Addr)
	return ip
}

// Confirm marks ip as the confirmed address.
func (s *IPSet) Confirm(ip netip.Addr) {
	if ip.Compare(s.Confirmed()) == 0 {
		return
	}
	s.confirmed.Store(ip)
	s.Lock()
	s.addLocked(ip) // Add is O(N)
	s.Unlock()
}

func (s *IPSet) clear() {
	s.Lock()
	defer s.Unlock()
	s.ips = nil
	s.confirmed.Store(zeroaddr)
}

// Disconfirm sets the confirmed address to zeroaddr if the current confirmed address
// is the provided ip.
func (s *IPSet) Disconfirm(ip netip.Addr) (ok bool) {
	if ip.Compare(s.Confirmed()) == 0 {
		s.fails++
		s.confirmed.Store(zeroaddr)
		ok = true
	}
	if s.fails > len(s.ips) || s.fails > maxFailLimit {
		// empty out the set, may be refilled by Get()
		s.clear()
		s.fails = 0
	}
	return
}
