// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"net"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
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

// datatracker.ietf.org/doc/html/rfc8305#section-7
type natPt struct {
	protect.Protector
	*nat64
	*dns64
	tunmode *settings.TunMode
	ip4s    []net.IP
	ip6s    []net.IP
}

type NatPt interface {
	protect.Protector
	DNS64
	NAT64
}

func NewNatPt(tunmode *settings.TunMode) NatPt {
	log.I("natpt: new; mode(%s)", tunmode)
	return &natPt{
		nat64:   newNat64(),
		dns64:   newDns64(),
		tunmode: tunmode,
		ip4s:    nil,
		ip6s:    nil,
	}
}

func (pt *natPt) D64(id string, ans6 []byte, f Resolver) []byte {
	return pt.dns64.eval(id, pt.force64(), ans6, f)
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
		log.D("natpt: ip6(%v) len(%d) != 16", ip6, len(ip6))
		return nil
	}

	prefixes := n.nat64PrefixForResolver(id)
	if len(prefixes) <= 0 {
		log.D("nat64: no prefix64 found for resolver(%s)", ip6, id)
		return nil
	}
	if x, ok := matchNat64(prefixes, ip6); ok {
		return n.xAddr(x, ip6)
	} else {
		log.D("natpt: no matching prefix64 for ip(%v) in id(%s/%d)", ip6, id, len(prefixes))
	}
	return nil
}

func (h *natPt) AddResolver(id string, f Resolver) bool {
	return h.dns64.AddResolver(id, f)
}

func (n *natPt) ResetNat64Prefix(ip6prefix string) bool {
	var err error
	var ipnet *net.IPNet
	if _, ipnet, err = net.ParseCIDR(ip6prefix); err == nil {
		n.dns64.register(UnderlayResolver) // wipe the slate clean
		if err = n.dns64.addNat64Prefix(UnderlayResolver, ipnet); err == nil {
			return true
		}
	}
	log.W("natpt: could not add underlay nat64 prefix: %s; err %v", ip6prefix, err)
	return false
}

// Returns the first matching local-interface net.IP for the network
func (n *natPt) UIP(network string) []byte {
	switch network {
	case "tcp6":
		fallthrough
	case "udp6":
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

func matchNat64(nets []*net.IPNet, ip net.IP) (*net.IPNet, bool) {
	for _, p := range nets {
		if p.Contains(ip) {
			return p, true
		}
	}
	return nil, false
}
