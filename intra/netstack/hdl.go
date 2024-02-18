// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package netstack

import (
	"errors"
	"net"
	"net/netip"
	"strings"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type GConnHandler interface {
	TCP() GTCPConnHandler
	UDP() GUDPConnHandler
	ICMP() GICMPHandler
	CloseConns(string) string
	Close() error
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

func (g *gconnhandler) CloseConns(csv string) string {
	cids := strings.Split(csv, ",")
	t := g.tcp.CloseConns(cids)
	u := g.udp.CloseConns(cids)
	i := g.icmp.CloseConns(cids)
	s := make([]string, 0, len(t)+len(u)+len(i))
	s = append(s, t...)
	s = append(s, u...)
	s = append(s, i...)
	return strings.Join(s, ",")
}

func (g *gconnhandler) Close() error {
	var errs error
	if g.tcp != nil {
		err := g.tcp.End()
		errs = errors.Join(errs, err)
	}
	if g.udp != nil {
		err := g.udp.End()
		errs = errors.Join(errs, err)
	}
	if g.icmp != nil {
		err := g.icmp.End()
		errs = errors.Join(errs, err)
	}
	return errs
}

// src/dst addrs are flipped
// fdbased.Attach -> ... -> nic.DeliverNetworkPacket -> ... -> nic.DeliverTransportPacket:
// github.com/google/gvisor/blob/be6ffa7/pkg/tcpip/stack/nic.go#L831-L837

func localAddrPort(id stack.TransportEndpointID) netip.AddrPort {
	return localUDPAddr(id).AddrPort()
}

func remoteAddrPort(id stack.TransportEndpointID) netip.AddrPort {
	return remoteUDPAddr(id).AddrPort()
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
