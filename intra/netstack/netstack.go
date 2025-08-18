// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package netstack

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// enable forwarding of packets on the interface
const nicfwd = false

// ref: github.com/brewlin/net-protocol/blob/ec64e5f899/internal/endpoint/endpoint.go#L20
func Up(s *stack.Stack, ep SeamlessEndpoint, h GConnHandler) (tcpip.NICID, error) {
	nic := tcpip.NICID(settings.NICID)
	who := strconv.Itoa(ep.Stat().Fd)

	// fetch existing routes before adding removing nic, which wipes out routes
	existingroutes := s.GetRouteTable()
	newnic := false
	// also closes its netstack protos (ip4, ip6), closes link-endpoint (ep), if any
	if ferr := s.RemoveNIC(nic); ferr != nil {
		_, newnic = ferr.(*tcpip.ErrUnknownNICID)
		log.I("netstack: %s: new nic? %t; remove nic? err(%v)", who, newnic, ferr)
	} else {
		log.I("netstack: %s: removed nic(%d)", who, nic)
	}

	// TODO? Pause and resume?
	// if newnic {
	//	s.Pause()
	//	defer s.Resume()
	// }

	SetNetstackOpts(s)

	if newnic {
		// github.com/google/gvisor/blob/a7dcce93/pkg/tcpip/sample/tun_tcp_connect/main.go
		OutboundTCP(who, s, h.TCP())
		OutboundUDP(who, s, h.UDP())
		OutboundICMP(who, s, h.ICMP())
	}

	if settings.Debug {
		tcp := s.TransportProtocolInstance(tcp.ProtocolNumber) != nil     // 6
		udp := s.TransportProtocolInstance(udp.ProtocolNumber) != nil     // 17
		icmp4 := s.TransportProtocolInstance(icmp.ProtocolNumber4) != nil // 1
		icmp6 := s.TransportProtocolInstance(icmp.ProtocolNumber6) != nil // 58
		log.D("netstack: %s: transport instances: icmp4/6? %t/%t, tcp/udp %t/%t",
			who, icmp4, icmp6, tcp, udp)
	}

	// creates and enables a fake nic for netstack s
	// netstack protos (ip4, ip6) enabled and ep is attached to nic
	if nerr := s.CreateNIC(nic, ep); nerr != nil {
		return nic, e(nerr)
	}
	// add addrs to this nic just attached to netstack s
	if err := addIfAddrs(s, nic); err != nil {
		return nic, err
	}

	// ref: github.com/xjasonlyu/tun2socks/blob/31468620e/core/stack.go#L80
	// allow spoofing packets tuples
	if nerr := s.SetSpoofing(nic, true); nerr != nil {
		return nic, e(nerr)
	}
	// ref: github.com/xjasonlyu/tun2socks/blob/31468620e/core/stack.go#L94
	// allow all packets sent to our fake nic through to netstack
	if nerr := s.SetPromiscuousMode(nic, true); nerr != nil {
		return nic, e(nerr)
	}

	if4, _ := s.GetMainNICAddress(nic, ipv4.ProtocolNumber)
	if6, _ := s.GetMainNICAddress(nic, ipv6.ProtocolNumber)

	s.SetNICForwarding(nic, ipv4.ProtocolNumber, nicfwd)
	s.SetNICForwarding(nic, ipv6.ProtocolNumber, nicfwd)
	// s.SetNICMulticastForwarding(nic, ipv4.ProtocolNumber, nicfwd)
	// s.SetNICMulticastForwarding(nic, ipv6.ProtocolNumber, nicfwd)
	// use existing routes if the nic is being recycled
	useExistingRoutes := !newnic && len(existingroutes) > 0
	if useExistingRoutes {
		s.SetRouteTable(existingroutes)
	}

	log.I("netstack: %s: up(%d)! new? %t; addrs: %v %v; routes? %s / existing? %t: %s",
		who, nic, newnic, if4, if6, s.GetRouteTable(), useExistingRoutes, existingroutes)

	return nic, nil
}

func e(err tcpip.Error) error {
	if err != nil {
		return errors.New(err.String())
	}
	return nil
}

func addIfAddrs(s *stack.Stack, nic tcpip.NICID) error {
	if !settings.ExperimentalWireGuard.Load() {
		log.W("netstack: %d add ifaddrs: skipped; experimental features, disabled", nic)
		return nil
	}

	// TODO: make ifaddrs configurable like fakedns is
	// The NIC is set in Spoofing mode. When the UDP Endpoint uses a non-local
	// address to "Connect", netstack generates a temporary addressState to
	// build a route, which can be primary but is always ephemeral. When this
	// UDP Endpoint uses a multicast address to "Connect", netstack selects
	// any available primary addressState to build a route. However, when the
	// NIC is in the just-initialized or idle state, no primary addressState
	// is readily available, and "Connect" fails. And so, permanent addresses,
	// e.g. 10.111.222.1/24 and fd66:f83a:c650::1/120, are assigned to the NIC,
	// which are only used to build routes for multicast response (and should
	// for any other connection that is "ingressing" into netstack).
	//
	// In fact, for multicast, the sender normally does not expect a response.
	// So, the ep.net.Connect is unnecessary.

	// 10.111.222.0/24 / [fd66:f83a:c650::0]/120
	// must match with:
	// github.com/celzero/rethink-app/blob/59aa0daae/app/src/main/java/com/celzero/bravedns/service/BraveVPNService.kt#L2813
	ifaddr4, err4 := netip.ParsePrefix("10.111.222.1/24")
	ifaddr6, err6 := netip.ParsePrefix("fd66:f83a:c650::1/120")

	if err4 != nil || err6 != nil { // should never happen
		return core.JoinErr(err4, err6)
	}

	// go.dev/play/p/Clg4geOwXMf
	nsaddr4 := tcpip.AddrFrom4(ifaddr4.Addr().As4())
	nsaddr6 := tcpip.AddrFrom16(ifaddr6.Addr().As16())

	ap4 := tcpip.AddressWithPrefix{
		Address:   nsaddr4,        // 10.111.222.1
		PrefixLen: ifaddr4.Bits(), // 24
	}
	ap6 := tcpip.AddressWithPrefix{
		Address:   nsaddr6,        // fd66:f83a:c650::1
		PrefixLen: ifaddr6.Bits(), // 120
	}
	protoaddr4 := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: ap4,
	}
	protoaddr6 := tcpip.ProtocolAddress{
		Protocol:          ipv6.ProtocolNumber,
		AddressWithPrefix: ap6,
	}

	asMainAddr := stack.AddressProperties{PEB: stack.CanBePrimaryEndpoint}

	// at: github.com/google/gvisor/blob/1f4299ee3f/pkg/tcpip/stack/addressable_endpoint_state.go#L177
	if err := s.AddProtocolAddress(nic, protoaddr4, asMainAddr); err != nil {
		return fmt.Errorf("netstack: %d add addr(%v): %v", nic, ifaddr6, err)
	}
	if err := s.AddProtocolAddress(nic, protoaddr6, asMainAddr); err != nil {
		return fmt.Errorf("netstack: %d add addr(%v): %v", nic, ifaddr4, err)
	}

	log.I("netstack: %d ifaddrs 4(%v) 6(%v)", nic, ifaddr4, ifaddr6)
	return nil
}

func Route(s *stack.Stack, l3 string) {
	// TODO? s.Pause()
	// defer s.Resume()

	which := l3
	switch l3 {
	case settings.IP46:
		s.SetRouteTable([]tcpip.Route{
			{
				Destination: header.IPv4EmptySubnet,
				NIC:         settings.NICID,
			},
			{
				Destination: header.IPv6EmptySubnet,
				NIC:         settings.NICID,
			},
		})
	case settings.IP6:
		s.SetRouteTable([]tcpip.Route{
			{
				Destination: header.IPv6EmptySubnet,
				NIC:         settings.NICID,
			},
		})
	case settings.IP4:
		fallthrough
	default:
		which = settings.IP4
		s.SetRouteTable([]tcpip.Route{
			{
				Destination: header.IPv4EmptySubnet,
				NIC:         settings.NICID,
			},
		})
	}
	// s.AddTCPProbe(func(state *stack.TCPEndpointState) {})
	log.I("netstack: route(ask:%s; set: %s); done", l3, which)
}

// also: github.com/google/gvisor/blob/adbdac747/runsc/boot/loader.go#L1132
// github.com/FlowerWrong/tun2socks/blob/1045a49618/cmd/netstack/main.go
// github.com/zen-of-proxy/go-tun2io/blob/c08b329b8/tun2io/util.go
// github.com/WireGuard/wireguard-go/blob/42c9af4/tun/netstack/tun.go
// github.com/telepresenceio/telepresence/pull/2709
func NewNetstack() (s *stack.Stack) {
	o := stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
			// arp.NewProtocol, unused
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			icmp.NewProtocol4,
			icmp.NewProtocol6,
			tcp.NewProtocol,
			udp.NewProtocol,
		},
		// HandleLocal if the packets must be forwarded to another nic within this stack, or
		// to let this stack forward packets to the OS' network stack.
		// also: github.com/Jigsaw-Code/outline-go-tun2socks/blob/5416729062/tunnel/tunnel.go#L45
		// HandleLocal: true,
	}

	s = stack.New(o)
	log.I("netstack: new stack4 and stack6")
	return
}
