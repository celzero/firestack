// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package netstack

import (
	"errors"
	"fmt"
	"io"
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

// use netstack's built-in ip-tables rules to trap and handle icmp packets
const useIPTablesForICMP = true

// ref: github.com/google/gvisor/blob/91f58d2cc/pkg/tcpip/sample/tun_tcp_echo/main.go#L102
func NewEndpoint(dev int, mtu int) (stack.LinkEndpoint, error) {
	var endpoint stack.LinkEndpoint
	opt := Options{
		FDs: []int{dev},
		MTU: uint32(mtu),
	}
	endpoint, _ = NewFdbasedInjectableEndpoint(&opt)
	log.I("netstack: new endpoint(fd:%d / mtu:%d)", dev, mtu)
	return endpoint, nil
}

// ref: github.com/google/gvisor/blob/aeabb785278/pkg/tcpip/link/sniffer/sniffer.go#L111-L131
func PcapOf(south stack.LinkEndpoint, nom string) (stack.LinkEndpoint, io.Closer, error) {
	if len(nom) == 1 {
		// 0, 1, 2 are for stdin, stdout, stderr; log packets to stdout
		log.I("netstack: pcap stdout(%s)", nom)
		nom = "rdnspcap"
		return sniffer.NewWithPrefix(south, nom), nil, nil
	} else if len(nom) > 1 {
		if fout, err := os.OpenFile(nom, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600); err != nil {
			return nil, fout, err
		} else {
			mtu := south.MTU()
			ep, err := sniffer.NewWithWriter(south, fout, mtu)
			log.I("netstack: pcap(%s)/file(%v)/mtu(%d)/err(%v)", nom, fout, mtu, err)
			return ep, fout, err
		}
	}
	return nil, nil, fmt.Errorf("netstack: pcap: invalid file name %s", nom)
}

// ref: github.com/brewlin/net-protocol/blob/ec64e5f899/internal/endpoint/endpoint.go#L20
func Up(s *stack.Stack, ep stack.LinkEndpoint, h GConnHandler) error {
	var nic tcpip.NICID = settings.NICID

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

	setupTcpHandler(s, ep, h.TCP())
	setupUdpHandler(s, ep, h.UDP())
	if useIPTablesForICMP {
		setupIcmpHandlerV2(s, ep, h.ICMP())
	} else {
		setupIcmpHandler(s, ep, h.ICMP())
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
		s.SetNICForwarding(nic, ipv4.ProtocolNumber, false)
		s.SetNICForwarding(nic, ipv6.ProtocolNumber, false)
		log.I("netstack: new stack4 and stack6 for %s", l3)
	case settings.IP6:
		o := stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{
				ipv6.NewProtocol,
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
		s.SetNICForwarding(nic, ipv6.ProtocolNumber, false)
		log.I("netstack: new stack6 for %s", l3)
	case settings.IP4:
		fallthrough
	default:
		o := stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{
				ipv4.NewProtocol,
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
		s.SetNICForwarding(nic, ipv4.ProtocolNumber, false)
		log.I("netstack: new stack4 for %s", l3)
	}

	return
}
