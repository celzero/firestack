// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dialers

import (
	"errors"
	"net"
	"net/netip"
	"net/url"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/protect/ipmap"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

const ()

var (
	errNilConn      = errors.New("nil conn")
	errNoConn       = errNilConn
	errNoEch        = errors.New("no ech")
	errEchQTimeout  = errors.New("ech query timeout")
	errNoSysConn    = errors.New("no sys conn")
	errNoDesyncConn = errors.New("no desync conn")
	errTLSHandshake = errors.New("tls handshake failed")
	errNoIps        = errors.New("no ips")
	errNoDialer     = errors.New("no dialer")
	errNoRetrier    = errors.New("no retrier")
	errNoListener   = errors.New("no listener")
)

var ipm ipmap.IPMap = ipmap.NewIPMap()

// Resolves hostOrIP, and re-seeds it if existing is non-empty.
// hostOrIP may be host:port, or ip:port, or host, or ip.
func renew(hostOrIP string, existing *ipmap.IPSet) (cur *ipmap.IPSet, ok bool) {
	// will never be able to resolve protected hosts (Selfhost, Systemhost),
	// and so, keep existing as-is (we do not want to use NewProtected and
	// race against dnsx.RegisterAddrs or other clients updating Selfhost or
	// Systemhost as changes come in from kotlinland intra.Bridge)
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

// New re-seeds hostOrIP with a new set of ips.
// hostOrIP may be host:port, or ip:port, or host, or ip.
// ipps may be ip or ip:port. It makes no attempt to resolve hostOrIP.
// see also: [For] and [NewProtected].
func New(hostOrIP string, ipps []string) (*ipmap.IPSet, bool) {
	ips := ipm.MakeIPSet(hostOrIP, ipps, ipmap.AutoType)
	return ips, !ips.Empty()
}

// hostOrIP may be host:port, or ip:port, or host, or ip.
// It makes no attempt to resolve hostOrIP, and returns a non-nil ipset.
func NewProtected(hostOrIP string, ipps []string) (*ipmap.IPSet, bool) {
	ips := ipm.MakeIPSet(hostOrIP, ipps, ipmap.Protected)
	return ips, !ips.Empty()
}

// For returns addresses for hostOrIP from cache, resolving them if missing.
// Underlying cache relies on Disconfirm() to remove unreachable IP addrs;
// if not called, these entries may go stale. Use [Resolve] to bypass cache.
// Use CachedAddrs() to only ever return from cache.
// hostOrIP may be host:port, or ip:port, or host, or ip.
func For(hostOrIP string) []netip.Addr {
	ipset := ipm.Get(hostOrIP)
	if ipset != nil {
		return ipset.Addrs()
	}
	return nil
}

// ForUrl is like [For] but for a url string s. It extracts the hostname from s
// and returns corresponding addrs from cache; or, resolving it, if empty.
func ForUrl(s string) []netip.Addr {
	u, err := url.Parse(s) // works if s is mere hostname; ex: example.com
	if err != nil {
		return For(s) // fallback on hostOrIP
	}
	return For(u.Hostname())
}

// Ptr returns hostnames from the ipmap cache, given an IP address.
func Ptr(ip netip.Addr) []string {
	return ipm.ReverseGet(ip)
}

func Confirmed(hostOrIP string) (zz netip.Addr) {
	if ipset := ipm.GetAny(hostOrIP); ipset != nil {
		return ipset.Confirmed()
	}
	return
}

// CachedAddrs returns addresses for hostOrIP from cache. Use Resolve() to bypass cache.
func CachedAddrs(hostOrIP string) []netip.Addr {
	ipset := ipm.GetAny(hostOrIP)
	if ipset != nil && !ipset.Empty() {
		return ipset.Addrs()
	}
	return nil
}

// cache adds a set of addresses for host to the cache.
func cache(host string, addrs []netip.Addr) bool {
	if len(host) <= 0 || len(addrs) <= 0 {
		return false
	}
	s := ipm.AddMany(host, addrs)
	return s != nil && !s.Empty()
}

// cache2 is like cache but	for qname and IPs in dns.Msg a, if any.
func cache2(a *dns.Msg) bool {
	if a == nil {
		return false
	}
	if !xdns.HasAnyAnswer(a) {
		return false
	}
	qname := xdns.QName(a)
	host, err := xdns.NormalizeQName(qname)
	if err != nil {
		log.E("dialers: ips: cachefrom: normalize qname %s err: %v", qname, err)
		return false
	}
	return cache(host, xdns.IPs(a))
}

// Mapper is a hostname to IP (a/aaaa) resolver for the network engine; may be nil.
func Mapper(m ipmap.IPMapper) {
	log.I("dialers: ips: mapper ok? %t", m != nil)
	// usually set once per tunnel disconnect/reconnect
	ipm.With(m)
}

func Clear() {
	// do not need to handle panics w/ core.Recover
	ipm.Clear()      // does not clear Selfhost, Systemhost (protected)
	ippPins.Clear()  // clear dialer-id pins
	ttlcache.Clear() // clear desync TTL cache
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
