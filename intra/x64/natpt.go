// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package x64

import (
	"net"
	"net/netip"

	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"github.com/miekg/dns"
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

var (
	unspecified4  = netip.IPv4Unspecified()
	zerovalueaddr = netip.Addr{}
)

// NewNatPt returns a new NatPt.
func NewNatPt(tunmode *settings.TunMode) *natPt {
	log.I("natpt: new; mode(%v)", tunmode)
	return &natPt{
		nat64:   newNat64(),
		dns64:   newDns64(),
		tunmode: tunmode,
		ip4s:    nil,
		ip6s:    nil,
	}
}

// D64 Implements DNS64.
func (pt *natPt) D64(network string, ans6 *dns.Msg, f dnsx.Transport) *dns.Msg {
	ptmode := pt.tunmode.PtMode.Load()
	if ptmode != settings.PtModeNo46 { // do64
		force64 := ptmode == settings.PtModeForce64
		return pt.dns64.eval(network, force64, ans6, f)
	}
	return nil
}

// IsNat64 Implements NAT64.
func (n *natPt) IsNat64(id string, ip netip.Addr) bool {
	prefixes := n.nat64PrefixForResolver(id)
	return match(prefixes, addr2ip(ip)) != nil
}

// X64 Implements NAT64.
func (n *natPt) X64(id string, ip6 netip.Addr) (ip4 netip.Addr) {
	id = id64(id)
	if !ip6.Is6() {
		log.D("natpt: not ip6: %v", ip6)
		return
	}

	// blocked domains (with zero IPv6 addr) should always be translated
	// to blocked IPv4 addr regardless of NAT64 prefix
	if ip6.IsUnspecified() {
		log.D("natpt: ip6(%v) is unspecified", ip6)
		return unspecified4
	}

	rawip := addr2ip(ip6)
	if id == dnsx.AnyResolver {
		for tid, prefixes := range n.ip64 {
			if len(prefixes) <= 0 {
				continue
			}
			if x := match(prefixes, rawip); x != nil {
				return ip2addr(n.xAddr(x, rawip))
			} else {
				log.V("natpt: no matching prefix64 for ip(%v) in id(%s/%d)", ip6, tid, len(prefixes))
			}
		}
		log.D("natpt: no prefix64 found for resolver(%s)", ip6, id)
		return zerovalueaddr
	}

	prefixes := n.nat64PrefixForResolver(id)
	if len(prefixes) <= 0 {
		log.D("natpt: no prefix64 found for resolver(%s)", ip6, id)
		return zerovalueaddr
	}
	if x := match(prefixes, rawip); x != nil {
		return ip2addr(n.xAddr(x, rawip))
	} else {
		log.VV("natpt: no matching prefix64 for ip(%v) in id(%s/%d)", ip6, id, len(prefixes))
	}
	return zerovalueaddr
}

// Add64 implements DNS64.
func (h *natPt) Add64(f dnsx.Transport) bool {
	return h.dns64.AddResolver(ID64(f), f)
}

// Remove64 implements DNS64.
func (h *natPt) Remove64(id string) bool {
	return h.dns64.RemoveResolver(id64(id))
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

func ID64(t dnsx.Transport) string {
	return id64(t.ID())
}

func id64(tid string) string {
	switch tid {
	case dnsx.System:
		return dnsx.UnderlayResolver
	case dnsx.Goos:
		return dnsx.OverlayResolver
	default:
		return tid
	}
}

func addr2ip(ip netip.Addr) net.IP {
	return net.IP(ip.AsSlice())
}

func ip2addr(ip net.IP) netip.Addr {
	x, _ := netip.AddrFromSlice(ip)
	return x.Unmap()
}
