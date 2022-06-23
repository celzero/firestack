// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"net"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
)

type natPt struct {
	*nat64
	*dns64
	l3      string
	tunmode *settings.TunMode
}

type Resolver interface {
	Exchange([]byte) ([]byte, error)
}

type NatPt interface {
	D64(id string, ans6 []byte, f Resolver) []byte
	IsNat64(id string, ip []byte) bool
	X64(id string, ip []byte) []byte
}

func NewNatPt(l3 string, tunmode *settings.TunMode) NatPt {
	return &natPt{
		nat64:   newNat64(),
		dns64:   newDns64(),
		l3:      l3,
		tunmode: tunmode,
	}
}

func (pt *natPt) D64(id string, ans6 []byte, f Resolver) []byte {
	if pt.can64() {
		return pt.dns64.eval(id, pt.force64(), ans6, f.Exchange)
	}
	return ans6
}

func (pt *natPt) can64() bool {
	return settings.IP6 == pt.l3 || pt.force64()
}

func (pt *natPt) force64() bool {
	return pt.tunmode.PtMode == settings.PtModeForce64
}

func (n *natPt) IsNat64(id string, ip []byte) bool {
	prefixes := n.nat64PrefixForResolver(id)
	_, ok := matchNat64(prefixes, ip)
	return ok
}

func (n *natPt) X64(id string, ip6 []byte) []byte {
	if len(ip6) != net.IPv6len {
		log.Debugf("nat64: ip6(%v) len(%d) != 16", ip6, len(ip6))
		return nil
	}

	prefixes := n.nat64PrefixForResolver(id)
	if len(prefixes) <= 0 {
		log.Debugf("nat64: no prefix64 found for resolver(%s)", ip6, id)
		return nil
	}
	if x, ok := matchNat64(prefixes, ip6); ok {
		return n.xAddr(x, ip6)
	} else {
		log.Debugf("nat64: no matching prefix64 for ip(%v) in id(%s/%d)", ip6, id, len(prefixes))
	}
	return nil
}

func (n *natPt) nat64PrefixForResolver(id string) []*net.IPNet {
	if ips, ok := n.ip64[id]; !ok {
		return nil
	} else {
		return ips
	}
}

func matchNat64(nets []*net.IPNet, ip net.IP) (*net.IPNet, bool) {
	for _, p := range nets {
		if p.Contains(ip) {
			return p, true
		}
	}
	return nil, false
}
