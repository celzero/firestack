// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package netstack

import (
	"errors"
	"io"
	"syscall"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// enable forwarding of packets on the interface
const nicfwd = false

const SnapLen uint32 = 2048 // in bytes; some sufficient value

type sniff struct {
	stack.LinkEndpoint
	Swapper
}

// ref: github.com/google/gvisor/blob/91f58d2cc/pkg/tcpip/sample/tun_tcp_echo/main.go#L102
func NewEndpoint(dev, mtu int, sink io.WriteCloser) (ep SeamlessEndpoint, err error) {
	defer func() {
		if err != nil {
			_ = syscall.Close(dev)
		}
		log.I("netstack: new endpoint(fd:%d / mtu:%d); err? %v", dev, mtu, err)
	}()

	umtu := uint32(mtu)
	opt := Options{
		FDs: []int{dev},
		MTU: umtu,
	}

	if ep, err = NewFdbasedInjectableEndpoint(&opt); err != nil {
		return nil, err
	}
	// ref: github.com/google/gvisor/blob/aeabb785278/pkg/tcpip/link/sniffer/sniffer.go#L111-L131
	return asSniffer(ep, sink)
}

func asSniffer(ep SeamlessEndpoint, sink io.WriteCloser) (SeamlessEndpoint, error) {
	if sink == nil {
		return ep, nil
	}
	// TODO: MTU instead of SnapLen? Must match pcapsink.begin()
	if link, err := sniffer.NewWithWriter(ep, sink, SnapLen); err != nil {
		return nil, err
	} else {
		return sniff{link, ep}, nil
	}
}

func LogPcap(y bool) (ok bool) {
	if y {
		ok = sniffer.LogPackets.CompareAndSwap(0, 1)
	} else {
		ok = sniffer.LogPackets.CompareAndSwap(1, 0)
	}
	log.I("netstack: pcap stdout(%t): done?(%t)", y, ok)
	return
}

func FilePcap(y bool) (ok bool) {
	if y {
		ok = sniffer.LogPacketsToPCAP.CompareAndSwap(0, 1)
	} else {
		ok = sniffer.LogPacketsToPCAP.CompareAndSwap(1, 0)
	}
	log.I("netstack: pcap sink?(%t); done?(%t)", y, ok)
	return
}

// ref: github.com/brewlin/net-protocol/blob/ec64e5f899/internal/endpoint/endpoint.go#L20
func Up(s *stack.Stack, ep stack.LinkEndpoint, h GConnHandler) error {
	var nic tcpip.NICID = settings.NICID

	// fetch existing routes before adding removing nic, which wipes out routes
	existingroutes := s.GetRouteTable()
	newnic := false
	// also closes its netstack protos (ip4, ip6), closes link-endpoint (ep), if any
	if ferr := s.RemoveNIC(nic); ferr != nil {
		_, newnic = ferr.(*tcpip.ErrUnknownNICID)
		log.I("netstack: new nic? %t; remove nic? err(%v)", newnic, ferr)
	} else {
		log.I("netstack: removed nic(%d)", nic)
	}

	// TODO? Pause and resume?
	// if newnic {
	//	s.Pause()
	//	defer s.Resume()
	// }

	core.SetNetstackOpts(s)

	// TODO: other stack otps?
	// github.com/xjasonlyu/tun2socks/blob/31468620e/core/option/option.go#L69

	if newnic {
		setupTcpHandler(s, h.TCP())
		setupUdpHandler(s, h.UDP())
		setupIcmpHandler(s, ep, h.ICMP())
	}

	if settings.Debug {
		tcp := s.TransportProtocolInstance(tcp.ProtocolNumber) != nil     // 6
		udp := s.TransportProtocolInstance(udp.ProtocolNumber) != nil     // 17
		icmp4 := s.TransportProtocolInstance(icmp.ProtocolNumber4) != nil // 1
		icmp6 := s.TransportProtocolInstance(icmp.ProtocolNumber6) != nil // 58
		log.D("netstack: transport instances: icmp4/6? %t/%t, tcp/udp %t/%t", icmp4, icmp6, tcp, udp)
	}

	// creates and enables a fake nic for netstack s
	// netstack protos (ip4, ip6) enabled and ep is attached to nic
	if nerr := s.CreateNIC(nic, ep); nerr != nil {
		return e(nerr)
	}
	// ref: github.com/xjasonlyu/tun2socks/blob/31468620e/core/stack.go#L80
	// allow spoofing packets tuples
	if nerr := s.SetSpoofing(nic, true); nerr != nil {
		return e(nerr)
	}
	// ref: github.com/xjasonlyu/tun2socks/blob/31468620e/core/stack.go#L94
	// allow all packets sent to our fake nic through to netstack
	if nerr := s.SetPromiscuousMode(nic, true); nerr != nil {
		return e(nerr)
	}

	s.SetNICForwarding(nic, ipv4.ProtocolNumber, nicfwd)
	s.SetNICForwarding(nic, ipv6.ProtocolNumber, nicfwd)
	// use existing routes if the nic is being recycled
	if !newnic && len(existingroutes) > 0 {
		log.I("netstack: up(%d)! existing routes? %s; new routes: %s", nic, s.GetRouteTable(), existingroutes)
		s.SetRouteTable(existingroutes)
	} else {
		log.I("netstack: up(%d)! new? %t; routes? %s", nic, newnic, s.GetRouteTable())
	}

	return nil
}

func e(err tcpip.Error) error {
	if err != nil {
		return errors.New(err.String())
	}
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
