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
	"strings"
	"sync"
	"sync/atomic"

	x "github.com/celzero/firestack/intra/backend"
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
	IPAddr
	AutoType
)

func (h IPSetType) String() string {
	switch h {
	case Protected:
		return "Protected"
	case Regular:
		return "Regular"
	case IPAddr:
		return "ipaddr"
	case AutoType:
		return "Auto"
	default:
		return "Unknown"
	}
}

// IPMapper is an interface for resolving hostnames to IP addresses.
// For internal used by firestack.
type IPMapper interface {
	// Lookup resolves q over one of the tids. If tids is empty, either
	// dnsx.Default, and if that fails, dnsx.System or dnsx.Goos tids.
	Lookup(q []byte, tids ...string) ([]byte, error)
	// LookupFor resolves q over client-code preferred tid conveyed via
	// DNSOpts returned from DNSListener.OnQuery. As a special case, UID
	// may be protect.UidSelf ("rethink") or core.UNKNOWN_UID_STR ("-1")
	// but otherwise it is usually a Linux user-id assigned to a process
	// which presumably is requesting this lookup.
	LookupFor(q []byte, uid string) ([]byte, error)
	// LookupNetIP is like Lookup but with empty tids.
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	// LookupNetIPFor is like LookupFor
	LookupNetIPFor(ctx context.Context, network, host, uid string) ([]netip.Addr, error)
	// LookupNetIPOn is like Lookup but with tids set to some preset IDs.
	LookupNetIPOn(ctx context.Context, network, host string, tids ...string) ([]netip.Addr, error)
}

// IPMap maps hostnames to IPSets.
type IPMap interface {
	IPMapper
	// Resolves hostOrIP and adds the resulting IPs to its IPSet.
	// hostOrIP may be host:port, or ip:port, or host, or ip.
	Add(hostOrIP string) *IPSet
	// Get creates an IPSet for this hostname populated with the IPs
	// discovered by resolving it. Subsequent calls to Get return the
	// same IPSet. Never returns nil.
	// hostOrIP may be host:port, or ip:port, or host, or ip.
	Get(hostOrIP string) *IPSet
	// GetAny creates an IPSet for this hostname, which may be empty.
	// Subsequent calls to GetAny return the same IPSet. Never returns nil.
	// hostOrIP may be host:port, or ip:port, or host, or ip.
	GetAny(hostOrIP string) *IPSet
	// MakeIPSet creates an IPSet for this hostname bootstrapped with given IPs
	// or IP:Ports. Subsequent calls to MakeIPSet return a new, overridden IPSet.
	// hostOrIP may be host:port, or ip:port, or host, or ip.
	MakeIPSet(hostOrIP string, ipps []string, typ IPSetType) *IPSet
	// Reverse lookup; returns hostnames for the given IP address.
	ReverseGet(ip netip.Addr) []string
	// With sets the default resolver to use for hostname resolution.
	With(r IPMapper)
	// Clear removes all IPSets from the map.
	Clear()
}

type ipmap struct {
	sync.RWMutex // protects m, p, ip

	// hostOrIP => ips
	m  map[string]*IPSet // regular type
	p  map[string]*IPSet // protected ips; immutable, never cleared
	ip map[string]*IPSet // ipaddrs

	// ip => host
	rptr x.IpTree // regular => hostname
	pptr x.IpTree // protected => hostname

	r *core.Volatile[IPMapper] // resolver
}

// IPSet represents an unordered collection of IP addresses for a single host.
// One IP can be marked as confirmed to be working correctly.
type IPSet struct {
	mu  sync.RWMutex // Protects ips.
	ips []netip.Addr // All known IPs for the server.
	typ IPSetType    // Regular, Protected, or AutoType

	r    IPMapper // For hostname resolution, never nil
	seed []string // Bootstrap ips or ip:ports; may be nil; is immutable.

	confirmed *core.Volatile[netip.Addr] // netip.Addr confirmed to be working.
	fails     atomic.Uint32              // Number of times the confirmed IP has failed.
}

func NewIPMap() *ipmap {
	return NewIPMapFor(nil)
}

// NewIPMapFor returns a fresh IPMap with r as its nameserver.
func NewIPMapFor(r IPMapper) *ipmap {
	return &ipmap{
		m:  make(map[string]*IPSet),
		p:  make(map[string]*IPSet),
		ip: make(map[string]*IPSet),

		rptr: x.NewIpTree(),
		pptr: x.NewIpTree(),

		r: core.NewVolatile(r), // r may be nil
	}
}

func (m *ipmap) With(r IPMapper) {
	log.I("ipmap: new resolver; ok? %t", r != nil)
	m.r.Store(r) // may be nil
}

func (m *ipmap) Clear() {
	m.Lock()
	defer m.Unlock()

	sz := len(m.m) + len(m.p)
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

	go m.rptr.Clear()
	// ipaddr type is not "cleared"
	log.I("ipmap: clear: requested %d/%d sets", n, sz)
}

// Implements IPMapper.
func (m *ipmap) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	r := m.r.Load() // actual ipmapper implementation
	if r == nil {
		return nil, &net.DNSError{Err: "no resolver", Name: host, Server: "localhost"}
	}
	return r.LookupNetIP(ctx, network, host)
}

// Implements IPMapper.
func (m *ipmap) Lookup(q []byte, tids ...string) ([]byte, error) {
	r := m.r.Load() // actual ipmapper implementation
	if r == nil {
		return nil, &net.DNSError{Err: "no resolver", Name: "Lookup", Server: "localhost"}
	}
	return r.Lookup(q, tids...)
}

// Implements IPMapper.
func (m *ipmap) LookupFor(q []byte, uid string) ([]byte, error) {
	r := m.r.Load() // actual ipmapper implementation
	if r == nil {
		return nil, &net.DNSError{Err: "no resolver", Name: "LookupFor", Server: "localhost"}
	}
	return r.LookupFor(q, uid)
}

// Implements IPMapper.
func (m *ipmap) LookupNetIPFor(ctx context.Context, network, host, uid string) ([]netip.Addr, error) {
	r := m.r.Load() // actual ipmapper implementation
	if r == nil {
		return nil, &net.DNSError{Err: "no resolver", Name: host, Server: "localhost"}
	}
	return r.LookupNetIPFor(ctx, network, host, uid)
}

// Implements IPMapper.
func (m *ipmap) LookupNetIPOn(ctx context.Context, network, host string, tid ...string) ([]netip.Addr, error) {
	r := m.r.Load() // actual ipmapper implementation
	if r == nil {
		return nil, &net.DNSError{Err: "no resolver", Name: host, Server: "localhost"}
	}
	return r.LookupNetIPOn(ctx, network, host, tid...)
}

func (m *ipmap) Add(hostOrIP string) *IPSet {
	s := m.get(hostOrIP, AutoType)
	log.I("ipmap: Add: resolving %s", hostOrIP)
	if _, ok := s.add(hostOrIP); !ok {
		log.W("ipmap: Add: zero ips for %s", hostOrIP)
	} else {
		m.revmap(hostOrIP, s, nil)
	}
	return s
}

func (m *ipmap) ReverseGet(ip netip.Addr) []string {
	q := x.StrOf(ip.String())

	s, _ := m.rptr.Get(q)
	hosts := s.V()
	if len(hosts) > 0 {
		return strings.Split(hosts, x.Vsep)
	}

	s, _ = m.pptr.Get(q)
	hosts = s.V()
	if len(hosts) > 0 {
		return strings.Split(hosts, x.Vsep)
	}
	return nil
}

func (m *ipmap) Get(hostOrIP string) *IPSet {
	s := m.get(hostOrIP, AutoType)
	if s.Empty() {
		log.I("ipmap: Get: resolving %s", hostOrIP)
		if _, ok := s.add(hostOrIP); !ok {
			log.W("ipmap: Get: zero ips for %s", hostOrIP)
		} else {
			m.revmap(hostOrIP, s, nil)
		}
	}
	log.D("ipmap: Get: %s => %s", hostOrIP, s.ips)
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
	si := m.ip[hostOrIP]
	m.RUnlock()

	if sp != nil || typ == Protected {
		s = sp          // may be nil or empty
		typ = Protected // discard Regular or AutoType
	} else if si != nil || typ == IPAddr {
		s = si
		typ = IPAddr
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
	if host, _, err := net.SplitHostPort(hostOrIP); err == nil {
		hostOrIP = host
	}
	if len(ipps) <= 0 && typ == Protected {
		ip, err := netip.ParseAddr(hostOrIP)
		if err != nil || !ip.IsValid() {
			// TODO: return error?
			log.T("ipmap: renew: %s; empty seed for Protected!", hostOrIP)
		}
		ipps = []string{hostOrIP}
		log.I("ipmap: renew: %s Protected type seeded from hostOrIP: %v", hostOrIP, ipps)
	} else {
		// TODO: hostOrIP must be IP (or IP:Port) if typ == IPAddr
		log.D("ipmap: renew: %s / seed: %v / typ: %s", hostOrIP, ipps, typ)
	}
	return m.makeIPSet(hostOrIP, ipps, typ)
}

func (m *ipmap) makeIPSet(hostname string, ipps []string, typ IPSetType) *IPSet {
	var ip netip.Addr
	var err error
	if ipps == nil {
		ipps = []string{}
	}

	mm := m.m // Regular or AutoType
	if protect.NeverResolve(hostname) || typ == Protected {
		mm = m.p
		typ = Protected // discard Regular or AutoType
	} else if ip, err = netip.ParseAddr(hostname); err == nil && !ip.IsUnspecified() && ip.IsValid() {
		mm = m.ip
		typ = IPAddr
	} else {
		typ = Regular // discard AutoType & IPAddr type
	}

	log.D("ipmap: makeIPSet: %s, seed: %v, typ: %s", hostname, ipps, typ)

	s := &IPSet{
		confirmed: core.NewZeroVolatile[netip.Addr](),
		typ:       typ,
		r:         m, // m stays constant, but m.r may change
		seed:      ipps,
		fails:     atomic.Uint32{},
	}
	if typ == IPAddr {
		log.D("ipmap: makeIPSet: %s for %s, confirmed addr %s", hostname, typ, ip)
		s.confirmed.Store(ip)
		// s.ips is empty for typ == IPAddr
	} else {
		s.confirmed.Store(zeroaddr)
	}

	totalseeds := s.bootstrap() // seed addrs only

	// if typ is Protected, then seeds must never be empty
	if typ == Protected && totalseeds <= 0 {
		log.W("ipmap: makeIPSet: zero seeds; %s for type %s discarded", hostname, typ)
	} else {
		m.Lock()
		prev := mm[hostname] // prev may be nil
		mm[hostname] = s     // overwrites existing
		m.Unlock()
		m.revmap(hostname, s, prev)
	}

	return s
}

func (m *ipmap) revmap(hostOrIP string, new *IPSet, old *IPSet) {
	if host, _, err := net.SplitHostPort(hostOrIP); err == nil {
		hostOrIP = host
	}
	if maybeip, _ := netip.ParseAddr(hostOrIP); maybeip.IsValid() {
		return // no-op
	}
	host := x.StrOf(hostOrIP)

	add := new.Addrs()    // new may be nil or addrs() may be empty
	remove := old.Addrs() // old may be nil or addrs() may be empty

	addtree, rmvtree := m.rptr, m.rptr
	if new != nil {
		if new.typ == Protected {
			addtree = m.pptr
		}
	}
	if old != nil {
		if old.typ == Protected {
			rmvtree = m.pptr
		}
	}

	var errs []error
	r, a := 0, 0
	for _, ip := range remove {
		if ip.IsValid() {
			q := x.StrOf(ip.String())
			if rmvtree.Esc(q, host) {
				r++
			}
		}
	}
	for _, ip := range add {
		if ip.IsValid() {
			q := x.StrOf(ip.String())
			if err := addtree.Add(q, host); err == nil {
				a++
			} else {
				errs = append(errs, err)
			}
		}
	}
	log.D("ipmap: rev: for %s: added %d/%d; removed %d/%d; errs: %v",
		host, a, len(add), r, len(remove), core.UniqErr(errs...))
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
func (s *IPSet) addLocked(ips ...netip.Addr) {
	for i, ip := range ips {
		uns := !ip.IsUnspecified()
		valip := ip.IsValid()
		newip := !s.hasLocked(ip.Unmap())
		if uns && valip && newip {
			// always unmapped; github.com/golang/go/issues/53607
			s.ips = append(s.ips, ip.Unmap())
		} else {
			log.D("ipmap: add #%d: fail %s; !uns? %t, val? %t, !new? %t", i, ip, uns, valip, newip)
		}
	}
}

// Returns bootstrap ips or ip:ports.
func (s *IPSet) Seed() []string {
	return s.seed
}

// add one or more IP addresses to the set.
// The hostname can be a domain name or an IP address.
func (s *IPSet) add(hostOrIP string) ([]netip.Addr, bool) {
	if s.typ == IPAddr { // nothing to do as this ipset only has one ipaddr
		return nil, false
	}

	if host, _, err := net.SplitHostPort(hostOrIP); err == nil {
		hostOrIP = host
	}
	r := s.r
	if r == nil { // unlikely; s.r is never nil
		log.W("ipmap: Add: no resolver for %s", hostOrIP)
		return nil, false
	}

	ctx := context.Background()

	var resolved []netip.Addr
	var err error
	if s.typ == Protected {
		// dnsx.System is "never resolved" and hence can be used to resolve
		// "protected" IPSets like the one used by bootstrap's DoH (x.Default)
		// see: protect.NeverResolve and dnsx.RegisterAddrs
		resolved, err = r.LookupNetIPOn(ctx, "ip", hostOrIP, x.System)
	} else if s.typ == Regular || s.typ == AutoType {
		resolved, err = r.LookupNetIP(ctx, "ip", hostOrIP)
	}

	if err != nil {
		log.W("ipmap: Add: err resolving %s: %v", hostOrIP, err)
		return nil, false
	} else {
		log.D("ipmap: Add: resolved? %s => %s", hostOrIP, resolved)
	}

	s.mu.Lock()
	s.addLocked(resolved...) // resolved may be nil
	s.mu.Unlock()

	ok := !s.Empty()
	if ok {
		s.fails.Store(0) // reset fails, since we have a new ips
	}

	return resolved, ok // resolved may be nil, even if ok == true
}

// Adds seed IP addresses to the set, if any.
func (s *IPSet) bootstrap() (n int) {
	s.mu.Lock()
	defer s.mu.Unlock()

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
	// typ == IPAddr is never empty!
	return s.Size() == 0
}

func (s *IPSet) Size() uint32 {
	if s.typ == IPAddr { // IPAddr type always has one ip (confirmed)
		return 1
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	return uint32(len(s.ips))
}

// Addrs returns a copy of the IP set as a slice in random order.
// The slice is owned by the caller, but the elements are owned by the set.
func (s *IPSet) Addrs() []netip.Addr {
	if s == nil {
		return []netip.Addr{}
	}

	if s.typ == IPAddr { // fast path for ipaddrs
		return []netip.Addr{s.confirmed.Load()}
	}

	s.mu.RLock()
	sz := len(s.ips)
	if sz <= 0 {
		s.mu.RUnlock()
		return []netip.Addr{}
	}
	c := make([]netip.Addr, 0, sz)
	c = append(c, s.ips...)
	s.mu.RUnlock()

	if len(c) > 1 {
		rand.Shuffle(len(c), func(i, j int) {
			c[i], c[j] = c[j], c[i]
		})
	}
	return c
}

func (s *IPSet) Protected() bool {
	return s.typ == Protected
}

func (s *IPSet) OneIPOnly() bool {
	return s.typ == IPAddr
}

// Confirmed returns the confirmed IP address, or zeroaddr if there is no such address.
func (s *IPSet) Confirmed() netip.Addr {
	return s.confirmed.Load()
}

// Confirm marks ip as the confirmed address.
// No-op if current confirmed IP is the same as ip.
// No-op if s is of type Protected and ip isn't in seed addrs.
// No-op if s is of type IPAddr.
func (s *IPSet) Confirm(ip netip.Addr) {
	if s.typ == IPAddr { // ipaddr fast path, no-op
		return
	}

	// do not reset fails, as confirmed ipaddrs may be repeatedly
	// disconfirmed by upstream clients (for example; dialers may
	// confirm an ip if it successfully dials, but upstream clients
	// like dot/doh/dns53 may disconfirm them on HTTP/DNS errors).
	// We'd want to keep incrementing failures, so an eventual
	// reset can happen once a generous maxFailLimit is exhausted.
	// s.fails.Store(0)
	if ip.Compare(s.confirmed.Load()) == 0 {
		return
	}

	// since mutex are acquired, perform ops asynchronously
	core.Gx("ipset.cfm."+ip.String(), func() {
		s.mu.RLock()
		newIP := !s.hasLocked(ip)
		s.mu.RUnlock()

		// Protected IPSets should stay consistent with its seed addrs
		// and must not add or confirm unseeded IPs. This happens in cases
		// where an IP from a previous Protected IPSet may be confirmed at
		// a time after the IPSet has been updated to a new one. For example,
		// if UidSelf / UidSystem has been changed to new System DNS IPs,
		// a goroutine using the previous UidSelf / UidSystem IPSet may
		// end up confirming IP address in the new one.
		if s.typ == Protected && newIP {
			return
		}

		s.confirmed.Store(ip)

		// Add this IP to the set if it hasn't been seen before.
		if s.typ != Protected && newIP {
			s.mu.Lock()
			s.addLocked(ip) // Add is O(N)
			s.mu.Unlock()
		}
	})
}

// Reset clears existing IPs for Regular and Protected types,
// while it is a no-op for type IPAddr.
func (s *IPSet) Reset() *IPSet {
	s.clear()
	return s
}

func (s *IPSet) clear() {
	if s.typ == IPAddr { // no-op for ipaddr
		return
	}

	if s.typ != Protected {
		s.mu.Lock()
		s.ips = nil
		s.mu.Unlock()
	}
	s.confirmed.Store(zeroaddr)
	s.fails.Store(0)
}

// Disconfirm sets the confirmed address to zeroaddr if the current confirmed address
// is the provided ip.
func (s *IPSet) Disconfirm(ip netip.Addr) (done bool) {
	if s.typ == IPAddr { // no-op for ipaddr
		return false
	}

	c := s.confirmed.Load()
	if ip.Compare(c) == 0 {
		s.confirmed.Store(zeroaddr)
		done = true
	}

	// Size and clear require a lock, do so asynchronously
	core.Go("ipset.dis."+ip.String(), func() {
		// if s is not empty, act on disconfirm
		if sz := s.Size(); sz > 0 {
			tot := s.fails.Load()
			// either the confirmed was disconfirmed above
			// or s never had a confirmed ip, but still
			// Disconfirm() was called, indicating a failure
			if done || c.Compare(zeroaddr) == 0 {
				tot = s.fails.Add(1)
			}

			if tot > max(2*sz, maxFailLimit) {
				// empty out the set, may be refilled by Get()
				if s.fails.CompareAndSwap(tot, 0) {
					s.clear()
				}
			}
		}
	})
	return
}
