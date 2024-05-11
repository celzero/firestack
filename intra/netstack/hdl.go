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
	TCP() GTCPConnHandler         // TCP returns the TCP handler.
	UDP() GUDPConnHandler         // UDP returns the UDP handler.
	ICMP() GICMPHandler           // ICMP returns the ICMP handler.
	CloseConns(csv string) string // CloseConns closes the connections with the given IDs, or all if empty.
	Close() error                 // Close closes TCP, UDP, ICMP handlers and its resources.
}

type gconnhandler struct {
	tcp  GTCPConnHandler
	udp  GUDPConnHandler
	icmp GICMPHandler
}

const allconns = ""

var _ GConnHandler = (*gconnhandler)(nil)

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
	var cids []string = nil // nil closes all conns
	if len(csv) > 0 {
		// split returns [""] (slice of length 1) if csv is empty
		// and so, avoid splitting on empty csv, and let cids be nil
		cids = strings.Split(csv, ",")
	}

	var t []string
	var u []string
	var i []string
	if tcp := g.tcp; tcp != nil {
		t = tcp.CloseConns(cids)
	}
	if udp := g.udp; udp != nil {
		u = udp.CloseConns(cids)
	}
	if icmp := g.icmp; icmp != nil {
		i = icmp.CloseConns(cids)
	}
	s := make([]string, 0, len(t)+len(u)+len(i))
	s = append(s, t...)
	s = append(s, u...)
	s = append(s, i...)
	return strings.Join(s, ",")
}

func (g *gconnhandler) Close() error {
	var errs error
	g.CloseConns(allconns)
	if t := g.tcp; t != nil {
		err := t.End()
		errs = errors.Join(errs, err)
	}
	if u := g.udp; u != nil {
		err := u.End()
		errs = errors.Join(errs, err)
	}
	if i := g.icmp; i != nil {
		err := i.End()
		errs = errors.Join(errs, err)
	}
	return errs
}

// src/dst addrs are flipped
// fdbased.Attach -> ... -> nic.DeliverNetworkPacket -> ... -> nic.DeliverTransportPacket:
// github.com/google/gvisor/blob/be6ffa7/pkg/tcpip/stack/nic.go#L831-L837

func localAddrPort(id stack.TransportEndpointID) netip.AddrPort {
	// todo: unmap?
	return localUDPAddr(id).AddrPort()
}

func remoteAddrPort(id stack.TransportEndpointID) netip.AddrPort {
	// todo: unmap?
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
