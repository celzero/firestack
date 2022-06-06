// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package netstack

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const nic tcpip.NICID = 0x01

type GConnHandler interface {
	TCP() GTCPConnHandler
	UDP() GUDPConnHandler
}

type gconnhandler struct {
	GConnHandler
	tcp GTCPConnHandler
	udp GUDPConnHandler
}

func NewGConnHandler(tcp GTCPConnHandler, udp GUDPConnHandler) GConnHandler {
	return &gconnhandler{
		tcp: tcp,
		udp: udp,
	}
}

func (g *gconnhandler) TCP() GTCPConnHandler {
	return g.tcp
}

func (g *gconnhandler) UDP() GUDPConnHandler {
	return g.udp
}

func NewEndpoint(dev int, mtu uint32) (stack.LinkEndpoint, error) {
	var endpoint stack.LinkEndpoint
	var fd_array []int
	fd_array[0] = int(dev)
	opt := Options{
		FDs: fd_array,
		MTU: mtu,
	}
	endpoint, _ = NewFdbasedInjectableEndpoint(&opt)
	return endpoint, nil
}

func NewStack(handler GConnHandler, endpoint stack.LinkEndpoint) (*stack.Stack, error) {
	var o stack.Options
	o = stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
		},
	}

	s := stack.New(o)
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

	// creates a fake nic and attaches netstack to it
	assertNoErr(s.CreateNIC(nic, endpoint))
	// allow spoofing packets tuples
	assertNoErr(s.SetSpoofing(nic, true))
	// allow all packets sent to our fake nic through to netstack
	assertNoErr(s.SetPromiscuousMode(nic, true))
	setupTcpHandler(s, handler.TCP())
	setupUdpHandler(s, handler.UDP())
	// setupIcmpHandler(s, endpoint, handler)

	return s, nil
}

func assertNoErr(err tcpip.Error) {
	if err != nil {
		panic(err.String())
	}
}
