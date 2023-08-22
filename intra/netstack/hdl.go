// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package netstack

import (
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type GConnHandler interface {
	TCP() GTCPConnHandler
	UDP() GUDPConnHandler
	ICMP() GICMPHandler
}

type gconnhandler struct {
	GConnHandler
	tcp  GTCPConnHandler
	udp  GUDPConnHandler
	icmp GICMPHandler
}

func NewGConnHandler(tcp GTCPConnHandler, udp GUDPConnHandler, icmp GICMPHandler) GConnHandler {
	return &gconnhandler{
		tcp:  tcp,
		udp:  udp,
		icmp: icmp,
	}
}

func (g *gconnhandler) TCP() GTCPConnHandler {
	return g.tcp
}

func (g *gconnhandler) UDP() GUDPConnHandler {
	return g.udp
}

func (g *gconnhandler) ICMP() GICMPHandler {
	return g.icmp
}

// src/dst addrs are flipped
// fdbased.Attach -> ... -> nic.DeliverNetworkPacket -> ... -> nic.DeliverTransportPacket:
// github.com/google/gvisor/blob/be6ffa7/pkg/tcpip/stack/nic.go#L831-L837

func remoteTCPAddr(id stack.TransportEndpointID) *net.TCPAddr {
	return &net.TCPAddr{
		IP:   nsaddr2ip(id.RemoteAddress),
		Port: int(id.RemotePort),
	}
}

func localTCPAddr(id stack.TransportEndpointID) *net.TCPAddr {
	return &net.TCPAddr{
		IP:   nsaddr2ip(id.LocalAddress),
		Port: int(id.LocalPort),
	}
}

func remoteUDPAddr(id stack.TransportEndpointID) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   nsaddr2ip(id.RemoteAddress),
		Port: int(id.RemotePort),
	}
}

func localUDPAddr(id stack.TransportEndpointID) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   nsaddr2ip(id.LocalAddress),
		Port: int(id.LocalPort),
	}
}

func nsaddr2ip(addr tcpip.Address) net.IP {
	b := addr.AsSlice()
	return net.IP(b)
}
