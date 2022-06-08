// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package netstack

import (
	"errors"

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

func NewEndpoint(dev int) (stack.LinkEndpoint, error) {
	var mtu uint32 = settings.VpnMtu
	var endpoint stack.LinkEndpoint
	opt := Options{
		FDs: []int{dev},
		MTU: mtu,
	}
	endpoint, _ = NewFdbasedInjectableEndpoint(&opt)
	log.Infof("netstack: new endpoint(fd:%d / mtu:%d)", dev, mtu)
	return endpoint, nil
}

func Up(s *stack.Stack, ep stack.LinkEndpoint, h GConnHandler) error {
	var nic tcpip.NICID = settings.NICID
	// creates a fake nic and attaches netstack to it
	if nerr := s.CreateNIC(nic, ep); nerr != nil {
		return e(nerr)
	}
	// allow spoofing packets tuples
	if nerr := s.SetSpoofing(nic, true); nerr != nil {
		return e(nerr)
	}
	// allow all packets sent to our fake nic through to netstack
	if nerr := s.SetPromiscuousMode(nic, true); nerr != nil {
		return e(nerr)
	}

	setupTcpHandler(s, h.TCP())
	setupUdpHandler(s, h.UDP())
	// TODO: setupIcmpHandler(s, h.ICMP())

	log.Infof("netstack: up(%d)!", nic)

	return nil
}

func e(err tcpip.Error) error {
	if err != nil {
		return errors.New(err.String())
	}
	return nil
}

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
	}

	log.Infof("netstack: new L3(%s)", l3)
	return
}
