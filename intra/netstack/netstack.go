// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package netstack

import (
	"errors"
	"io"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// use netstack's built-in ip-tables rules to trap and handle icmp packets
const useIPTablesForICMP = false

// enable forwarding of packets on the interface
const nicfwd = false

var errInvalidTunFd = errors.New("invalid tun fd")

// ref: github.com/google/gvisor/blob/91f58d2cc/pkg/tcpip/sample/tun_tcp_echo/main.go#L102
func NewEndpoint(fd, mtu int, sink io.WriteCloser) (stack.LinkEndpoint, error) {
	dev, err := dup(fd)
	if err != nil {
		return nil, err
	}
	umtu := uint32(mtu)
	opt := Options{
		FDs: []int{dev},
		MTU: umtu,
	}

	if fdep, err1 := NewFdbasedInjectableEndpoint(&opt); err1 != nil {
		log.E("netstack: new endpoint(fd:%d / mtu:%d); err? %v", dev, mtu, err1)
		return fdep, err1
	} else {
		// ref: github.com/google/gvisor/blob/aeabb785278/pkg/tcpip/link/sniffer/sniffer.go#L111-L131
		ep, err2 := sniffer.NewWithWriter(fdep, sink, umtu)
		log.I("netstack: new endpoint(fd:%d / mtu:%d); err? %v", dev, mtu, err2)
		return ep, err2
	}
}

func dup(fd int) (int, error) {
	if fd < 0 {
		return -1, errInvalidTunFd
	}

	// Make a copy of `fd` so that os.File's finalizer doesn't close `fd`
	newfd, err := unix.Dup(fd)
	if err != nil {
		return -1, err
	}

	// java-land gives up its ownership of fd
	return newfd, nil
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

	newnic := false
	// also closes its link endpoints, if any
	if ferr := s.RemoveNIC(nic); ferr != nil {
		_, newnic = ferr.(*tcpip.ErrUnknownNICID)
		log.I("netstack: remove nic? %t; err(%v)", newnic, ferr)
	} else {
		log.I("netstack: removed nic(%d)", nic)
	}

	// TODO: setup protocol opts?
	// github.com/google/gvisor/blob/ef9e8d91/test/benchmarks/tcp/tcp_proxy.go#L233
	sack := tcpip.TCPSACKEnabled(true)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)

	// from: github.com/telepresenceio/telepresence/blob/ab7dda7d55/pkg/vif/stack.go#L232
	// Enable Receive Buffer Auto-Tuning, see: github.com/google/gvisor/issues/1666
	bufauto := tcpip.TCPModerateReceiveBufferOption(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &bufauto)

	ttl := tcpip.DefaultTTLOption(64)
	s.SetNetworkProtocolOption(ipv4.ProtocolNumber, &ttl)
	s.SetNetworkProtocolOption(ipv6.ProtocolNumber, &ttl)

	// TODO: other stack otps?
	// github.com/xjasonlyu/tun2socks/blob/31468620e/core/option/option.go#L69

	if useIPTablesForICMP {
		// TODO: untested
		setupIcmpHandlerV2(s, ep, h.ICMP())
	} else {
		setupIcmpHandler(s, ep, h.ICMP())
	}

	if newnic {
		setupTcpHandler(s, h.TCP())
		setupUdpHandler(s, h.UDP())
	}

	// creates a fake nic and attaches netstack to it
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

	log.I("netstack: up(%d)!", nic)

	return nil
}

func e(err tcpip.Error) error {
	if err != nil {
		return errors.New(err.String())
	}
	return nil
}

func Route(s *stack.Stack, l3 string) {
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
		s.SetRouteTable([]tcpip.Route{
			{
				Destination: header.IPv4EmptySubnet,
				NIC:         settings.NICID,
			},
		})
	}
}

// also: github.com/google/gvisor/blob/adbdac747/runsc/boot/loader.go#L1132
// github.com/FlowerWrong/tun2socks/blob/1045a49618/cmd/netstack/main.go
// github.com/zen-of-proxy/go-tun2io/blob/c08b329b8/tun2io/util.go
// github.com/WireGuard/wireguard-go/blob/42c9af4/tun/netstack/tun.go
// github.com/telepresenceio/telepresence/pull/2709
func NewNetstack(l3 string) (s *stack.Stack) {
	var nic tcpip.NICID = settings.NICID
	switch l3 {
	case settings.IP46:
		o := stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{
				ipv4.NewProtocol,
				ipv6.NewProtocol,
				arp.NewProtocol, // unused
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
		s.SetRouteTable([]tcpip.Route{
			{
				Destination: header.IPv4EmptySubnet,
				NIC:         nic,
			},
			{
				Destination: header.IPv6EmptySubnet,
				NIC:         nic,
			},
		})
		s.SetNICForwarding(nic, ipv4.ProtocolNumber, nicfwd)
		s.SetNICForwarding(nic, ipv6.ProtocolNumber, nicfwd)
		log.I("netstack: new stack4 and stack6 for %s", l3)
	case settings.IP6:
		o := stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{
				ipv6.NewProtocol,
				arp.NewProtocol, // unused
			},
			TransportProtocols: []stack.TransportProtocolFactory{
				icmp.NewProtocol6,
				tcp.NewProtocol,
				udp.NewProtocol,
			},
		}
		s = stack.New(o)
		s.SetRouteTable([]tcpip.Route{
			{
				Destination: header.IPv6EmptySubnet,
				NIC:         nic,
			},
		})
		s.SetNICForwarding(nic, ipv6.ProtocolNumber, nicfwd)
		log.I("netstack: new stack6 for %s", l3)
	case settings.IP4:
		fallthrough
	default:
		o := stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{
				ipv4.NewProtocol,
				arp.NewProtocol, // unused
			},
			TransportProtocols: []stack.TransportProtocolFactory{
				icmp.NewProtocol4,
				tcp.NewProtocol,
				udp.NewProtocol,
			},
		}
		s = stack.New(o)
		s.SetRouteTable([]tcpip.Route{
			{
				Destination: header.IPv4EmptySubnet,
				NIC:         nic,
			},
		})
		s.SetNICForwarding(nic, ipv4.ProtocolNumber, nicfwd)
		log.I("netstack: new stack4 for %s", l3)
	}

	return
}
