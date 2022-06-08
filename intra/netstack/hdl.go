// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
package netstack

import (
	"net"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

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

func remoteTCPAddr(id stack.TransportEndpointID) *net.TCPAddr {
	return &net.TCPAddr{
		IP:   net.IP(id.RemoteAddress),
		Port: int(id.RemotePort),
	}
}

func localTCPAddr(id stack.TransportEndpointID) *net.TCPAddr {
	return &net.TCPAddr{
		IP:   net.IP(id.LocalAddress),
		Port: int(id.LocalPort),
	}
}

func remoteUDPAddr(id stack.TransportEndpointID) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   net.IP(id.RemoteAddress),
		Port: int(id.RemotePort),
	}
}

func localUDPAddr(id stack.TransportEndpointID) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   net.IP(id.LocalAddress),
		Port: int(id.LocalPort),
	}
}
