// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package netstack

import (
	"errors"
	"os"

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

// ref: github.com/google/gvisor/blob/91f58d2cc/pkg/tcpip/sample/tun_tcp_echo/main.go#L102
func NewEndpoint(dev int, mtu int) (stack.LinkEndpoint, error) {
	var endpoint stack.LinkEndpoint
	opt := Options{
		FDs: []int{dev},
		MTU: uint32(mtu),
	}
	endpoint, _ = NewFdbasedInjectableEndpoint(&opt)
	log.Infof("netstack: new endpoint(fd:%d / mtu:%d)", dev, mtu)
	return endpoint, nil
}

// ref: github.com/google/gvisor/blob/aeabb785278/pkg/tcpip/link/sniffer/sniffer.go#L111-L131
func PcapOf(south stack.LinkEndpoint, fd int) (stack.LinkEndpoint, error) {
	if fd < 3 { // 0, 1, 2 are for stdin, stdout, stderr; log packets to stdout
		log.Infof("netstack: stdout(%d) pcap", fd)
		return sniffer.NewWithPrefix(south, "rdnspcap"), nil
	}
	log.Infof("netstack: fd(%d) pcap", fd)
	fout := os.NewFile(uintptr(fd), "")
	return sniffer.NewWithWriter(south, fout, south.MTU())
}

// ref: github.com/brewlin/net-protocol/blob/ec64e5f899/internal/endpoint/endpoint.go#L20
func Up(s *stack.Stack, ep stack.LinkEndpoint, h GConnHandler) error {
	var nic tcpip.NICID = settings.NICID
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

	setupTcpHandler(s, ep, h.TCP())
	setupUdpHandler(s, ep, h.UDP())
	// TODO: setupIcmpHandler(s, h.ICMP())

	// TODO: setup protocol opts?
	// github.com/google/gvisor/blob/ef9e8d91/test/benchmarks/tcp/tcp_proxy.go#L233
	log.Infof("netstack: up(%d)!", nic)

	return nil
}

func e(err tcpip.Error) error {
	if err != nil {
		return errors.New(err.String())
	}
	return nil
}

// also: github.com/google/gvisor/blob/adbdac747/runsc/boot/loader.go#L1132
// github.com/FlowerWrong/tun2socks/blob/1045a49618/cmd/netstack/main.go
// github.com/zen-of-proxy/go-tun2io/blob/c08b329b8/tun2io/util.go
// github.com/WireGuard/wireguard-go/blob/42c9af4/tun/netstack/tun.go
func NewNetstack(l3 string) (s *stack.Stack) {
	var nic tcpip.NICID = settings.NICID
	switch l3 {
	case settings.IP46:
		o := stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{
				ipv4.NewProtocol,
				ipv6.NewProtocol,
			},
			TransportProtocols: []stack.TransportProtocolFactory{
				tcp.NewProtocol,
				udp.NewProtocol,
				icmp.NewProtocol4,
				icmp.NewProtocol6,
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
		s.SetNICForwarding(nic, ipv4.ProtocolNumber, false)
		s.SetNICForwarding(nic, ipv6.ProtocolNumber, false)
	case settings.IP6:
		o := stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{
				ipv6.NewProtocol,
			},
			TransportProtocols: []stack.TransportProtocolFactory{
				tcp.NewProtocol,
				udp.NewProtocol,
				icmp.NewProtocol6,
			},
		}
		s = stack.New(o)
		s.SetRouteTable([]tcpip.Route{
			{
				Destination: header.IPv6EmptySubnet,
				NIC:         nic,
			},
		})
		s.SetNICForwarding(nic, ipv6.ProtocolNumber, false)
	case settings.IP4:
		fallthrough
	default:
		o := stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{
				ipv4.NewProtocol,
			},
			TransportProtocols: []stack.TransportProtocolFactory{
				tcp.NewProtocol,
				udp.NewProtocol,
				icmp.NewProtocol4,
			},
		}
		s = stack.New(o)
		s.SetRouteTable([]tcpip.Route{
			{
				Destination: header.IPv4EmptySubnet,
				NIC:         nic,
			},
		})
		s.SetNICForwarding(nic, ipv4.ProtocolNumber, false)
	}

	// TODO: setup stack otps?
	// github.com/xjasonlyu/tun2socks/blob/31468620e/core/option/option.go#L69
	log.Infof("netstack: new L3(%s)", l3)
	return
}
