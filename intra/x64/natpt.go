// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package x64

import (
	"context"
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
// nicmx.github.io/Jool/en/intro-xlat.html
type natPt struct {
	*nat64
	*dns64
	ip4s []net.IP
	ip6s []net.IP
}

var _ dnsx.NatPt = (*natPt)(nil)

var (
	unspecified4 = netip.IPv4Unspecified()
	invalidaddr  = netip.Addr{}
)

// Only for test.
func NewNatPt() *natPt {
	return NewNatPt2(context.Background())
}

// NewNatPt2 returns a new [dnsx.NatPt].
func NewNatPt2(ctx context.Context) *natPt {
	log.I("natpt: new; mode(%v)", settings.PtMode.Load())
	return &natPt{
		nat64: newNat64(ctx),
		dns64: newDns64(ctx),
		ip4s:  nil,
		ip6s:  nil,
	}
}

// D64 implements [dnsx.DNS64].
func (pt *natPt) D64(network, id, uid string, ans6 *dns.Msg) (ans4 *dns.Msg) {
	ptmode := settings.PtMode.Load()
	if ptmode != settings.PtModeNo46 { // do64
		force64 := ptmode == settings.PtModeForce64 || ptmode == settings.PtModeForce
		return pt.dns64.eval(network, force64, ans6, id, uid)
	}
	return nil
}

// IsNat64 implements [dnsx.NAT64].
func (n *natPt) IsNat64(id string, ip netip.Addr) bool {
	prefixes := n.nat64PrefixForResolver(id)
	return match(prefixes, addr2ip(ip)) != nil
}

// WillNat64 implements [dnsx.NAT64].
func (n *natPt) WillNat64(id string) bool {
	prefixes := n.nat64PrefixForResolver(id)
	return len(prefixes) > 0
}

// X46 implements [dnsx.NAT64].
func (n *natPt) X46(id string, ip4 netip.Addr) (ip6 netip.Addr) {
	unmapped := ip4.Unmap()

	if !unmapped.Is4() {
		log.D("natpt: x46: not ip4: %v", unmapped)
		return invalidaddr
	}

	if unmapped.IsUnspecified() {
		log.D("natpt: x46: ip4(%v) is unspecified", unmapped)
		return netip.IPv6Unspecified()
	}

	prefixes := n.nat64PrefixForResolver(id)
	if len(prefixes) <= 0 {
		log.D("natpt: x46: no prefix64 found for resolver(%s)", id)
		return invalidaddr
	}
	rawip := addr2ip(unmapped)
	return ip2addr6(n.prefixAddr(&prefixes[0], rawip))
}

// X64 implements [dnsx.NAT64].
func (n *natPt) X64(id string, ip6 netip.Addr) (ip4 netip.Addr) {
	if !ip6.Is6() {
		log.D("natpt: x64: not ip6: %v", ip6)
		return invalidaddr
	}

	// blocked domains (with zero IPv6 addr) should always be translated
	// to blocked IPv4 addr regardless of NAT64 prefix
	if ip6.IsUnspecified() {
		log.D("natpt: x64: ip6(%v) is unspecified", ip6)
		return unspecified4
	}

	if id == dnsx.AnyResolver {
		rawip := addr2ip(ip6)
		all := n.dns64.allIP64s()

		for tid, prefixes := range all {
			if len(prefixes) <= 0 {
				continue
			}
			if x := match(prefixes, rawip); x != nil {
				return ip2addr4(n.xAddr(x, rawip))
			} else if log.Verbose {
				log.V("natpt: x64: no matching prefix64 for ip(%v) in id(%s/%d)", ip6, tid, len(prefixes))
			}
		}

		if log.Debug {
			log.D("natpt: x64: no prefix64 found for %s resolver(%s)", ip6, id)
		}
		return invalidaddr
	}

	prefixes := n.nat64PrefixForResolver(id)
	if len(prefixes) <= 0 {
		if log.Debug {
			log.D("natpt: x64: no prefix64 found for %s resolver(%s)", ip6, id)
		}
		return invalidaddr
	}
	rawip := addr2ip(ip6)
	if x := match(prefixes, rawip); x != nil {
		return ip2addr4(n.xAddr(x, rawip))
	} else if log.Verbose {
		log.VV("natpt: x64: no matching prefix64 for ip(%v) in id(%s/%d)", ip6, id, len(prefixes))
	}
	return invalidaddr
}

// Add64 implements [dnsx.DNS64].
func (h *natPt) Add64(id string) bool {
	return h.dns64.AddResolver(id)
}

// Remove64 implements [dnsx.DNS64].
func (h *natPt) Remove64(id string) bool {
	return h.dns64.RemoveResolver(id64(id))
}

func (n *natPt) ResetNat64Prefix(ip6prefix string) bool {
	var err error
	var ipnet *net.IPNet
	if _, ipnet, err = net.ParseCIDR(ip6prefix); err == nil {
		n.dns64.register(dnsx.UnderlayResolver) // wipe the slate clean
		if err = n.dns64.addNat64Prefix(dnsx.UnderlayResolver, *ipnet); err == nil {
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

func (n *natPt) nat64PrefixForResolver(id string) []net.IPNet {
	id = id64(id)
	return n.get(id)
}

// match returns the first matching prefix for ip in nets.
func match(nets []net.IPNet, ip net.IP) *net.IPNet {
	for _, netip := range nets {
		if netip.Contains(ip) {
			return &netip
		}
	}
	return nil
}

func ID64(t dnsx.Transport) string {
	return id64(t.ID())
}

func id64(tid string) string {
	switch tid { // may be dnsx.UnderlayResolver or dnsx.OverlayResolver
	case dnsx.System:
		return dnsx.UnderlayResolver
	case dnsx.Goos:
		return dnsx.StdlibResolver
	default:
		return tid
	}
}

func addr2ip(ip netip.Addr) net.IP {
	return net.IP(ip.AsSlice())
}

func ip2addr4(ip net.IP) netip.Addr {
	x, _ := netip.AddrFromSlice(ip.To4()) // ip may be nil, but To4() handles it
	return x
}

func ip2addr6(ip net.IP) netip.Addr {
	x, _ := netip.AddrFromSlice(ip.To16()) // ip may be nil, but To16() handles it
	return x
}
