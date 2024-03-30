// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package x64

import (
	"net"

	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
)

// app    |  interface  |  pt        |  who    |  internet?
// ----   |  --------   |  --------  |  ----   |  --------
// ip4    |  ip4        |  -         |  -      |  y
// ip4    |  ip6        |  464xlat   |  os     |  y
// ----   |  --------   |  --------  |  ----   |  --------
// ip6    |  ip6        |  -         |  -      |  y
// ip6    |  ip4        |  nat64     |  rdns   |  y
// ----   |  --------   |  --------  |  ----   |  --------
// ip4+6  |  ip6        |  464xlat   |  os     |  y
// ip4+6  |  ip4	    |  happyeye  |  app    |  y
// ----   |  --------   |  --------  |  ----   |  --------
// ip4+6  |  ip4+6      |  bind      |  rdns   |  y
// ip4+6  |  ip6+4	    |  bind      |  rdns   |  y
//
// datatracker.ietf.org/doc/html/rfc8305#section-7
type natPt struct {
	*nat64
	*dns64
	tunmode *settings.TunMode
	ip4s    []net.IP
	ip6s    []net.IP
}

var _ dnsx.NatPt = (*natPt)(nil)

func NewNatPt(tunmode *settings.TunMode) dnsx.NatPt {
	log.I("natpt: new; mode(%v)", tunmode)
	return &natPt{
		nat64:   newNat64(),
		dns64:   newDns64(),
		tunmode: tunmode,
		ip4s:    nil,
		ip6s:    nil,
	}
}

func (pt *natPt) D64(id string, ans6 []byte, f dnsx.Transport) []byte {
	if pt.do64() {
		return pt.dns64.eval(id, pt.force64(), ans6, f)
	}
	return nil
}

func (pt *natPt) force64() bool {
	return pt.tunmode.PtMode == settings.PtModeForce64
}

func (pt *natPt) do64() bool {
	return pt.tunmode.PtMode != settings.PtModeNo46
}

func (n *natPt) IsNat64(id string, ip []byte) bool {
	prefixes := n.nat64PrefixForResolver(id)
	return matchNat64(prefixes, ip) != nil
}

func (n *natPt) X64(id string, rawip6 []byte) []byte {
	ip6 := net.IP(rawip6)
	if len(ip6) != net.IPv6len {
		log.D("natpt: ip6(%v) len(%d) != 16", ip6, len(ip6))
		return nil
	}

	// blocked domains (with zero IPv6 addr) should always be translated
	// to blocked IPv4 addr regardless of NAT64 prefix
	if ip6.IsUnspecified() {
		log.D("natpt: ip6(%v) is unspecified", ip6)
		return net.IPv4zero
	}

	prefixes := n.nat64PrefixForResolver(id)
	if len(prefixes) <= 0 {
		log.D("natpt: no prefix64 found for resolver(%s)", ip6, id)
		return nil
	}
	if x := match(prefixes, ip6); x != nil {
		return n.xAddr(x, ip6)
	} else {
		log.D("natpt: no matching prefix64 for ip(%v) in id(%s/%d)", ip6, id, len(prefixes))
	}
	return nil
}

func (h *natPt) Add64(id string, f dnsx.Transport) bool {
	return h.dns64.AddResolver(id, f)
}

func (h *natPt) Remove64(id string) bool {
	return h.dns64.RemoveResolver(id)
}

func (n *natPt) ResetNat64Prefix(ip6prefix string) bool {
	var err error
	var ipnet *net.IPNet
	if _, ipnet, err = net.ParseCIDR(ip6prefix); err == nil {
		n.dns64.register(dnsx.UnderlayResolver) // wipe the slate clean
		if err = n.dns64.addNat64Prefix(dnsx.UnderlayResolver, ipnet); err == nil {
			return true
		}
	}
	log.W("natpt: could not add underlay nat64 prefix: %s; err %v", ip6prefix, err)
	return false
}

// Returns the first matching local-interface net.IP for the network
func (n *natPt) UIP(network string) []byte {
	switch network {
	case "tcp6", "udp6":
		if len(n.ip6s) > 0 {
			return n.ip6s[0]
		}
		return net.IPv6zero
	default:
		if len(n.ip4s) > 0 {
			return n.ip4s[0]
		}
		return net.IPv4zero
	}
}

func (n *natPt) nat64PrefixForResolver(id string) []*net.IPNet {
	if ips, ok := n.ip64[id]; !ok {
		return nil
	} else {
		return ips
	}
}

// match returns the first matching prefix for ip in nets.
func match(nets []*net.IPNet, ip net.IP) *net.IPNet {
	for _, p := range nets {
		if p.Contains(ip) {
			return p
		}
	}
	return nil
}
