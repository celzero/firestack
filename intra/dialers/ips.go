// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dialers

import (
	"net"
	"net/netip"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/protect/ipmap"
)

const (
	errNilConn      = net.UnknownNetworkError("nil connection")
	errNoConn       = net.UnknownNetworkError("no connection")
	errNoSysConn    = net.UnknownNetworkError("no sys connection")
	errNoDesyncConn = net.UnknownNetworkError("no desync connection")
	errNoIps        = net.UnknownNetworkError("no ips")
	errNoEch        = net.UnknownNetworkError("no ech")
	errNoDialer     = net.UnknownNetworkError("no dialer")
	errNoRetrier    = net.UnknownNetworkError("no retrier")
	errNoListener   = net.UnknownNetworkError("no listener")
)

var ipm ipmap.IPMap = ipmap.NewIPMap()

// Resolves hostOrIP, and re-seeds it if existing is non-empty
func renew(hostOrIP string, existing *ipmap.IPSet) (cur *ipmap.IPSet, ok bool) {
	// will never be able to resolve protected hosts (UidSelf, UidRethink),
	// and so, keep existing as-is (we do not want to use NewProtected and
	// race against dnsx.RegisterAddrs or other clients updating UidSelf or
	// UidRethink as changes come in from kotlinland intra.Bridge)
	if protect.NeverResolve(hostOrIP) {
		cur = existing.Reset()
	} else if existing.Protected() {
		// if protected, preserve seed addrs; then resolve hostOrIP
		NewProtected(hostOrIP, existing.Seed())
		cur = ipm.Add(hostOrIP)
		// fallthrough
	} else if existing.Empty() {
		// if empty, discard seed, re-resolve hostOrIP; oft times, ipset is
		// empty when its ips have been disconfirmed beyond some threshold
		cur = ipm.Add(hostOrIP)
		if cur.Empty() {
			// if still empty, fallback on seed addrs
			cur, _ = New(hostOrIP, existing.Seed())
		} // else: fallthrough
	} else {
		// if non-empty, renew hostOrIP with seed addrs
		// existing may be of typ IPAddr, in which case
		// existing.Seed() would be empty, and hostOrIP
		// should be a valid IP or IP:Port.
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

// Mapper is a hostname to IP (a/aaaa) resolver for the network engine; may be nil.
func Mapper(m ipmap.IPMapper) {
	log.I("dialers: ips: mapper ok? %t", m != nil)
	// usually set once per tunnel disconnect/reconnect
	ipm.With(m)
}

func Clear() {
	// do not need to handle panics w/ core.Recover
	ipm.Clear() // does not clear UidSelf, UidSystem (protected)
}

// Confirm3 marks addr as preferred for hostOrIP
func Confirm3(hostOrIP string, addr net.Addr) bool {
	return Confirm2(hostOrIP, addr.String())
}

func Confirm(hostOrIP string, addr netip.Addr) bool {
	if ipok(addr) { // confirms ONLY valid ips
		ips := ipm.GetAny(hostOrIP)
		ips.Confirm(addr)
		return ips != nil
	}
	return false
}

func Confirm2(hostOrIP string, addr string) bool {
	return Confirm(hostOrIP, ipof(addr))
}

// Disconfirm3 unmarks addr as preferred for hostOrIP
func Disconfirm3(hostOrIP string, addr net.Addr) bool {
	return Disconfirm2(hostOrIP, addr.String())
}

// Disconfirm unmarks addr as preferred for hostOrIP
func Disconfirm(hostOrIP string, addr netip.Addr) bool {
	ips := ipm.GetAny(hostOrIP)
	if ips != nil {
		return ips.Disconfirm(addr) // disconfirms ANY ip (invalid/unspecified)
	} // not ok
	return false
}

// Disconfirm2 unmarks addr as preferred for hostOrIP
func Disconfirm2(hostOrIP string, addr string) bool {
	return Disconfirm(hostOrIP, ipof(addr))
}

func ipof(addr string) (zz netip.Addr) {
	if ipp, err := netip.ParseAddrPort(addr); err == nil {
		return ipp.Addr()
	} else if ip, err := netip.ParseAddr(addr); err == nil {
		return ip
	}
	return
}
