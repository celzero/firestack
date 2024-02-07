// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dialers

import (
	"net"
	"net/netip"
	"strconv"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect/ipmap"
)

var errNoConn = net.UnknownNetworkError("no connection")
var errNoIps = net.UnknownNetworkError("no ips")
var errNoDialer = net.UnknownNetworkError("no dialer")
var errNotTCP = net.UnknownNetworkError("not a tcp connection")

var ipm ipmap.IPMap = ipmap.NewIPMap()

func addr(ip netip.Addr, port int) string {
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

// Re-seeds and resolves hostOrIP
func renew(hostOrIP string, existing *ipmap.IPSet) (*ipmap.IPSet, bool) {
	addrs := existing.Seed()
	New(hostOrIP, addrs)
	ips := ipm.Add(hostOrIP)
	return ips, !ips.Empty()
}

// New re-seeds hostOrIP with a new set of addresses
func New(hostOrIP string, addrs []string) (*ipmap.IPSet, bool) {
	ips := ipm.MakeIPSet(hostOrIP, addrs)
	return ips, !ips.Empty()
}

// For returns addresses for hostOrIP, resolving them if missing
func For(hostOrIP string) []netip.Addr {
	ipset := ipm.Get(hostOrIP)
	if ipset != nil {
		return ipset.Addrs()
	}
	return nil
}

// Mapper is a hostname to IP (a/aaaa) resolver for the network engine
func Mapper(m ipmap.IPMapper) {
	log.I("dialers: ips: mapper ok? %t", m != nil)
	// usually set just the once
	ipm.With(m)
}

// Confirm marks addr as preferred for hostOrIP
func Confirm(hostOrIP string, addr net.Addr) bool {
	ips := ipm.GetAny(hostOrIP)
	if ips != nil {
		if ip, err := netip.ParseAddr(addr.String()); err == nil {
			ips.Confirm(ip)
			return true
		} // not ok
	} // not ok
	return false
}

// Disconfirm unmarks addr as preferred for hostOrIP
func Disconfirm(hostOrIP string, ip net.Addr) bool {
	ips := ipm.GetAny(hostOrIP)
	if ips != nil {
		if ip, err := netip.ParseAddr(ip.String()); err == nil {
			ips.Disconfirm(ip)
			return true
		} // not ok
	} // not ok
	return false
}
