// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package x64

import (
	"context"
	"net"

	"github.com/celzero/firestack/intra/log"
)

type nat64 struct {
}

func newNat64(_ context.Context) *nat64 {
	return &nat64{}
}

// xAddr translates ip6 to ip4 discarding prefix64.
// If prefix64 or ip6 is not valid, it returns zerovalueaddr.
// If ip6 is unspecified, it returns unspecified ip4.
func (n *nat64) xAddr(prefix64 *net.IPNet, ip6 net.IP) net.IP {
	return ip6to4(prefix64, ip6)
}

// prefixAddr translates ip4 to IPv6 embedding prefix64.
// If prefix64 or ip4 is not valid, it returns nil.
// If ip4 is unspecified, it returns unspecified IPv6.
func (n *nat64) prefixAddr(prefix64 *net.IPNet, ip4 net.IP) net.IP {
	return ip4to6(prefix64, ip4)
}

// ip4to6 converts ip4 to IPv6 embedding prefix64.
func ip4to6(prefix64 *net.IPNet, ip4 net.IP) net.IP {
	if ip4.IsUnspecified() {
		return net.IPv6zero
	}
	if prefix64 == nil {
		log.W("natpt: ip4to6: nil prefix64 for ip4(%v)", ip4)
		return nil
	}
	ip6 := make(net.IP, net.IPv6len)
	copy(ip6, prefix64.IP.To16())
	bitmask, _ := prefix64.Mask.Size()
	startByte := bitmask / 8

	if startByte+net.IPv4len > len(ip6) {
		log.W("natpt: too long; cannot convert ip4(%v) / prefix64(%v) to ip6", ip4, prefix64)
		return nil
	}

	copy(ip6[startByte:], ip4.To4())
	return ip6
}

// ip6to4 converts ip6 to IPv4 discarding prefix64.
func ip6to4(prefix64 *net.IPNet, ip6 net.IP) net.IP {
	if ip6.IsUnspecified() {
		return net.IPv4zero
	}
	if prefix64 == nil {
		log.W("natpt: ip6to4: nil prefix64 for ip6(%v)", ip6)
		return nil
	}
	ip4 := make(net.IP, net.IPv4len)
	bitmask, _ := prefix64.Mask.Size()
	startByte := bitmask / 8

	if startByte+net.IPv4len > len(ip6) {
		log.W("natpt: too long; cannot convert ip64(%v) / prefix64(%v) to ip4", ip6, prefix64)
		return nil
	}

	for i := range net.IPv4len {
		i6 := startByte + i
		// skip byte 8, datatracker.ietf.org/doc/html/rfc6052#section-2.2
		if i6 == 8 {
			startByte++
		}

		ip4[i] = ip6[startByte+i]
	}
	return ip4
}
