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

	"github.com/celzero/firestack/intra/log"
)

var zeroaddr = netip.Addr{}

type IPMapper interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// IPMap maps hostnames to IPSets.
type IPMap interface {
	IPMapper
	// Get creates an IPSet for this hostname populated with the IPs
	// discovered by resolving it. Subsequent calls to Get return the
	// same IPSet. Never returns nil.
	Get(hostname string) *IPSet
	// GetAny creates an IPSet for this hostname, which may be empty.
	// Subsequent calls to GetAny return the same IPSet. Never returns nil.
	GetAny(hostname string) *IPSet
	// MakeIPSet creates an IPSet for this hostname bootstrapped with given IPs.
	// Subsequent calls to MakeIPSet return a new, overriden IPSet.
	MakeIPSet(hostname string, ips []string) *IPSet
	// With sets the default resolver to use for hostname resolution.
	With(r IPMapper)
}

type ipMap struct {
	sync.RWMutex
	m map[string]*IPSet
	r IPMapper // always the default system resolver
}

// IPSet represents an unordered collection of IP addresses for a single host.
// One IP can be marked as confirmed to be working correctly.
type IPSet struct {
	sync.RWMutex              // Protects this struct.
	ips          []netip.Addr // All known IPs for the server.
	confirmed    netip.Addr   // IP address confirmed to be working.
	r            IPMapper     // Resolver to use for hostname resolution.
	seed         []string     // Bootstrap IPs; may be nil.
}

func NewIPMap() IPMap {
	return NewIPMapFor(nil)
}

// NewIPMapFor returns a fresh IPMap with r as its nameserver.
func NewIPMapFor(r IPMapper) IPMap {
	return &ipMap{
		m: make(map[string]*IPSet),
		r: r,
	}
}

func (m *ipMap) With(r IPMapper) {
	log.I("ipmap: new resolver")
	m.r = r // may be nil
}

// Implements IPMapper.
func (m *ipMap) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	r := m.r
	if host == "localhost" || host == "localhost." {
		return []netip.Addr{netip.IPv6Loopback()}, nil
	}
	if host == "rethink" { // == protect.UidSelf
		return nil, nil
	}
	if r == nil {
		return nil, &net.DNSError{Err: "no resolver", Name: host}
	}
	return r.LookupNetIP(ctx, network, host)
}

func (m *ipMap) Get(hostOrIP string) *IPSet {
	return m.get(hostOrIP, false)
}

func (m *ipMap) GetAny(hostOrIP string) *IPSet {
	return m.get(hostOrIP, true)
}

func (m *ipMap) get(hostOrIP string, emptyok bool) *IPSet {
	if host, _, err := net.SplitHostPort(hostOrIP); err == nil {
		hostOrIP = host
	}
	m.RLock()
	s := m.m[hostOrIP]
	m.RUnlock()

	if s == nil {
		s = m.MakeIPSet(hostOrIP, nil)
	}

	if emptyok || !s.Empty() {
		return s
	}

	s.Add(hostOrIP)
	if s.Empty() {
		log.W("ipmap: Get: zero ips for %s", hostOrIP)
	}

	return s
}

func (m *ipMap) MakeIPSet(hostOrIP string, ips []string) *IPSet {
	if ips == nil {
		ips = []string{}
	}
	s := &IPSet{r: m, seed: ips, confirmed: zeroaddr}
	s.bootstrap()

	m.Lock()
	m.m[hostOrIP] = s
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
	if !ip.IsUnspecified() && ip.IsValid() && !s.hasLocked(ip) {
		// always unmapped; github.com/golang/go/issues/53607
		s.ips = append(s.ips, ip.Unmap())
	}
}

func (s *IPSet) Seed() []string {
	s.RLock()
	defer s.RLock()
	return s.seed
}

// Add one or more IP addresses to the set.
// The hostname can be a domain name or an IP address.
func (s *IPSet) Add(hostname string) {
	r := s.r
	if r == nil {
		log.W("ipmap: Add: (processing: %s) resolver missing", hostname)
		return
	}
	resolved, err := r.LookupNetIP(context.Background(), "ip", hostname)
	if err != nil {
		log.W("ipmap: Add: err resolving %s: %v", hostname, err)
		return
	}
	s.Lock()
	for _, addr := range resolved { // resolved may be nil
		s.addLocked(addr)
	}
	s.Unlock()
}

// Adds one or more IP addresses to the set.
func (s *IPSet) bootstrap() {
	s.Lock()
	for _, ipstr := range s.seed {
		if ip, err := netip.ParseAddr(ipstr); err == nil {
			s.addLocked(ip)
		} else {
			log.W("ipmap: bootstrap: invalid ipstr %s: %v", ipstr, err)
			if ipstr2, _, err := net.SplitHostPort(ipstr); err == nil {
				if ip2, err := netip.ParseAddr(ipstr2); err == nil {
					s.addLocked(ip2)
				} else {
					log.W("ipmap: bootstrap: invalid ipstr2 %s: %v", ipstr2, err)
				}
			}
		}
	}
	s.Unlock()
}

// Empty reports whether the set is empty.
func (s *IPSet) Empty() bool {
	s.RLock()
	defer s.RUnlock()
	return len(s.ips) == 0
}

// GetAll returns a copy of the IP set as a slice in random order.
// The slice is owned by the caller, but the elements are owned by the set.
func (s *IPSet) GetAll() []netip.Addr {
	s.RLock()
	if len(s.ips) <= 0 {
		return nil
	}
	c := make([]netip.Addr, 0, len(s.ips))
	c = append(c, s.ips...)
	s.RUnlock()

	rand.Shuffle(len(c), func(i, j int) {
		c[i], c[j] = c[j], c[i]
	})
	return c
}

// Confirmed returns the confirmed IP address, or nil if there is no such address.
func (s *IPSet) Confirmed() netip.Addr {
	s.RLock()
	defer s.RUnlock()
	return s.confirmed
}

// Confirm marks ip as the confirmed address.
func (s *IPSet) Confirm(ip netip.Addr) {
	// Optimization: Skip setting if it hasn't changed.
	if ip.Compare(s.Confirmed()) == 0 {
		// This is the common case.
		return
	}
	s.Lock()
	// Add is O(N)
	s.addLocked(ip)
	s.confirmed = ip
	s.Unlock()
}

// Disconfirm sets the confirmed address to nil if the current confirmed address
// is the provided ip.
func (s *IPSet) Disconfirm(ip netip.Addr) {
	s.Lock()
	if ip.Compare(s.confirmed) == 0 {
		s.confirmed = zeroaddr
	}
	s.Unlock()
}
