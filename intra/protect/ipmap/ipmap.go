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
var tresolver = net.DefaultResolver

type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// IPMap maps hostnames to IPSets.
type IPMap interface {
	// Get creates an IPSet for this hostname populated with the IPs
	// discovered by resolving it.  Subsequent calls to Get return the
	// same IPSet.
	Get(hostname string) *IPSet
	GetAny(hostname string) *IPSet
	// Of creates an IPSet for this hostname bootstrapped with given IPs.
	// Subsequent calls to Of return a new, overriden IPSet.
	Of(hostname string, ips []string) *IPSet
}

type ipMap struct {
	sync.RWMutex
	m map[string]*IPSet
	r Resolver // always the default system resolver
}

// IPSet represents an unordered collection of IP addresses for a single host.
// One IP can be marked as confirmed to be working correctly.
type IPSet struct {
	sync.RWMutex              // Protects this struct.
	ips          []netip.Addr // All known IPs for the server.
	confirmed    netip.Addr   // IP address confirmed to be working.
	r            Resolver     // Resolver to use for hostname resolution.
	seed         []string     // Bootstrap IPs; may be nil.
}

// NewIPMap returns a fresh IPMap.
// `r` will be used to resolve any hostnames passed to Get or Add.
func NewIPMap() IPMap {
	return NewIPMapFor(tresolver)
}

func NewIPMapFor(r Resolver) IPMap {
	return &ipMap{
		m: make(map[string]*IPSet),
		r: r,
	}
}

func (m *ipMap) Get(hostname string) *IPSet {
	return m.get(hostname, false)
}

func (m *ipMap) GetAny(hostname string) *IPSet {
	return m.get(hostname, true)
}

func (m *ipMap) get(hostname string, emptyok bool) *IPSet {
	m.RLock()
	s := m.m[hostname]
	m.RUnlock()
	if s != nil {
		if emptyok || !s.Empty() {
			return s
		}
	}

	s = &IPSet{r: m.r}
	s.Add(hostname)

	if s.Empty() {
		log.W("ipmap: Get: zero ips for %s", hostname)
		return s
	}

	m.Lock()
	s2 := m.m[hostname]
	if s2 == nil || s2.Empty() {
		m.m[hostname] = s
	} else {
		// Another pending call to Get populated m[hostname]
		// while we were building s.  Use that one to ensure
		// consistency.
		s = s2
	}
	m.Unlock()

	return s
}

func (m *ipMap) Of(hostname string, ips []string) *IPSet {
	if len(ips) <= 0 {
		ips = []string{}
	}
	s := &IPSet{r: m.r, seed: ips}
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
	if !ip.IsUnspecified() && ip.IsValid() && !s.hasLocked(ip) {
		s.ips = append(s.ips, ip)
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
		log.W("ipmap: Add: resolver not set")
		return
	}
	ctx := context.Background()
	// Don't hold the ipMap lock during blocking I/O.
	resolved, err := s.r.LookupNetIP(ctx, "ip", hostname)
	if err != nil {
		log.W("ipmap: Add: err resolving %s: %v", hostname, err)
		return
	}
	s.Lock()
	for _, addr := range resolved {
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
