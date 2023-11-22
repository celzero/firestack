// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package x64

import (
	"net"

	"github.com/celzero/firestack/intra/log"
)

type nat64 struct {
}

func newNat64() *nat64 {
	return &nat64{}
}

func (n *nat64) IsNat64(prefix64 *net.IPNet, ip6 net.IP) bool {
	return prefix64.Contains(ip6)
}

func (n *nat64) xAddr(prefix64 *net.IPNet, ip6 net.IP) net.IP {
	return ip6to4(prefix64, ip6)
}

func ip6to4(prefix64 *net.IPNet, ip6 net.IP) net.IP {
	ip4 := make(net.IP, net.IPv4len)
	bitmask, _ := prefix64.Mask.Size() // prefix64 expected to be never nil
	startByte := bitmask / 8

	if startByte+net.IPv4len > len(ip6) {
		log.W("natpt: too long; cannot convert ip64(%v) / prefix64(%v) to ip4", ip6, prefix64)
		return nil
	}

	for i := 0; i < net.IPv4len; i++ {
		i6 := startByte + i
		// skip byte 8, datatracker.ietf.org/doc/html/rfc6052#section-2.2
		if i6 == 8 {
			startByte++
		}

		ip4[i] = ip6[startByte+i]
	}
	return ip4
}
