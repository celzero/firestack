// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dialers

import (
	"context"
	"net"
	"net/netip"
	"strconv"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/protect/ipmap"
	"github.com/celzero/firestack/intra/settings"
)

const (
	errNoConn     = net.UnknownNetworkError("no connection")
	errNoIps      = net.UnknownNetworkError("no ips")
	errNoDialer   = net.UnknownNetworkError("no dialer")
	errNoListener = net.UnknownNetworkError("no listener")
)

var ipm ipmap.IPMap = ipmap.NewIPMap()
var ipProto string = settings.IP46

func addrstr(ip netip.Addr, port int) string {
	return net.JoinHostPort(ip.String(), strconv.Itoa(port))
}

func tcpaddr(ip netip.Addr, port int) *net.TCPAddr {
	// ip must never be a wildcard address and must be unmapped
	// go.dev/play/p/UopgKYEMJtw
	return &net.TCPAddr{IP: ip.AsSlice(), Port: port}
}

func udpaddr(ip netip.Addr, port int) *net.UDPAddr {
	// ip must never be a wildcard address and must be unmapped
	// go.dev/play/p/UopgKYEMJtw
	return &net.UDPAddr{IP: ip.AsSlice(), Port: port}
}

// Resolves hostOrIP, and re-seeds it if existing is non-empty
func renew(hostOrIP string, existing *ipmap.IPSet) (cur *ipmap.IPSet, ok bool) {
	// will never be able to resolve protected hosts (UidSelf, UidRethink),
	// except for the seed addrs.
	if protect.NeverResolve(hostOrIP) {
		cur, _ = NewProtected(hostOrIP, existing.Seed())
	} else if existing.Protected() {
		// if protected, preserve seed addrs; hen resolve hostOrIP
		NewProtected(hostOrIP, existing.Seed())
		cur = ipm.Add(hostOrIP)
		// fallthrough
	} else if existing.Empty() {
		// if empty, discard seed, re-resolve hostOrIP; oft times, ipset is
		// empty when its ips have been disconfirmed beyond some threshold
		cur = ipm.Add(hostOrIP)
		if cur.Empty() {
			// if still empty, fallback on seed addrs; when hostOrIP is
			// protect.UidSelf, protect.UidSystem, for example, cur will
			// always be empty (as they're unresolvable by ipm.Add)
			cur, _ = New(hostOrIP, existing.Seed())
		} // else: fallthrough
	} else {
		// if non-empty, renew hostOrIP with seed addrs
		New(hostOrIP, existing.Seed())
		cur = ipm.Add(hostOrIP)
	}
	if cur == nil { // can never happen as Add/New/NewProtected return a non-nil ipset
		return nil, false
	}
	return cur, !cur.Empty()
}

// New re-seeds hostOrIP with a new set of ips or ip:ports.
func New(hostOrIP string, ipps []string) (*ipmap.IPSet, bool) {
	ips := ipm.MakeIPSet(hostOrIP, ipps, ipmap.AutoType)
	return ips, !ips.Empty()
}

func NewProtected(hostOrIP string, ipps []string) (*ipmap.IPSet, bool) {
	ips := ipm.MakeIPSet(hostOrIP, ipps, ipmap.Protected)
	return ips, !ips.Empty()
}

// For returns addresses for hostOrIP from cache, resolving them if missing.
// Underlying cache relies on Disconfirm() to remove unreachable IP addrs;
// if not called, these entries may go stale. Use Resolve() to bypass cache.
func For(hostOrIP string) []netip.Addr {
	ipset := ipm.Get(hostOrIP)
	if ipset != nil {
		return ipset.Addrs()
	}
	return nil
}

// Resolve resolves hostname to IP addresses, bypassing cache.
// If resolution fails, entries from the cache are returned, if any.
func Resolve(hostname string) ([]netip.Addr, error) {
	// ipm.LookupNetIP itself has a short-term cache (ipmapper.go:battl)
	addrs, err := ipm.LookupNetIP(context.Background(), "ip", hostname)
	if len(addrs) <= 0 { // check cache
		if addrs = ipm.GetAny(hostname).Addrs(); len(addrs) > 0 {
			return addrs, nil
		} // else: on cached addrs
	}
	return addrs, err
}

// Mapper is a hostname to IP (a/aaaa) resolver for the network engine; may be nil.
func Mapper(m ipmap.IPMapper) {
	log.I("dialers: ips: mapper ok? %t", m != nil)
	// usually set once per tunnel disconnect/reconnect
	ipm.With(m)
}

// p must be one of settings.IP4, settings.IP6, or settings.IP46
func IPProtos(ippro string) (diff bool) {
	switch ippro {
	case settings.IP4:
		fallthrough
	case settings.IP6:
		fallthrough
	case settings.IP46:
		diff = ipProto != ippro
		ipProto = ippro
	default:
		log.D("dialers: ips: invalid protos %s; use existing: %s", ippro, ipProto)
		return
	}
	log.I("dialers: ips: protos set to %s; diff? %t", ipProto, diff)
	return
}

func Clear() {
	ipm.Clear() // does not remove UidSelf, UidSystem
}

// Confirm marks addr as preferred for hostOrIP
func Confirm(hostOrIP string, addr net.Addr) bool {
	if ip, err := netip.ParseAddr(addr.String()); err == nil {
		return Confirm2(hostOrIP, ip)
	} // not ok
	return false
}

func Confirm2(hostOrIP string, addr netip.Addr) bool {
	ips := ipm.GetAny(hostOrIP)
	if ipok(addr) {
		ips.Confirm(addr)
	}
	return ips != nil
}

// Disconfirm3 unmarks addr as preferred for hostOrIP
func Disconfirm3(hostOrIP string, addr net.Addr) bool {
	return Disconfirm2(hostOrIP, addr.String())
}

// Disconfirm unmarks addr as preferred for hostOrIP
func Disconfirm(hostOrIP string, addr netip.Addr) bool {
	ips := ipm.GetAny(hostOrIP)
	if ips != nil {
		return ips.Disconfirm(addr)
	} // not ok
	return false
}

// Disconfirm2 unmarks addr as preferred for hostOrIP
func Disconfirm2(hostOrIP string, addr string) bool {
	if ip, err := netip.ParseAddr(addr); err == nil {
		return Disconfirm(hostOrIP, ip)
	} // not ok
	return false
}
