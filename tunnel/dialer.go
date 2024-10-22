// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package tunnel

import (
	"net"
	"net/netip"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
)

var _ protect.RDialer = (*gtunnel)(nil)

// Handle implements protect.RDialer.
func (h *gtunnel) Handle() uintptr {
	return core.Loc(h)
}

// Dial implements protect.RDialer.
func (t *gtunnel) Dial(network, addr string) (protect.Conn, error) {
	taddr, proto := fulladdr(addr) // taddr may be nil
	switch network {
	case "tcp", "tcp4", "tcp6":
		if taddr == nil {
			taddr = &tcpip.FullAddress{}
		}
		return gonet.DialTCP(t.stack, *taddr, proto)
	case "udp", "udp4", "udp6":
		return gonet.DialUDP(t.stack, nil, taddr, proto)
	}

	log.E("tun: dial: invalid network: %s to %s", network, addr)
	return nil, &net.OpError{
		Op:     "tun: dial",
		Net:    network,
		Source: netaddr(addr),
		Addr:   nil,
		Err:    net.UnknownNetworkError(network),
	}
}

// Announce implements protect.RDialer.
func (t *gtunnel) Announce(network, local string) (protect.PacketConn, error) {
	taddr, proto := fulladdr(local) // taddr may be nil
	switch network {
	case "udp", "udp4", "udp6":
		return gonet.DialUDP(t.stack, taddr, nil, proto)
	}

	log.E("tun: announce: invalid network: %s to %s", network, local)
	return nil, &net.OpError{
		Op:     "tun: announce",
		Net:    network,
		Addr:   netaddr(local),
		Source: nil,
		Err:    net.UnknownNetworkError(network),
	}
}

// Accept implements protect.RDialer.
func (t *gtunnel) Accept(network, local string) (protect.Listener, error) {
	taddr, proto := fulladdr(local) // taddr may be nil
	if taddr == nil {
		log.E("tun: accept: invalid addr: %s", local)
		return nil, &net.AddrError{Err: "tun: dial: invalid addr", Addr: local}
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
		return gonet.ListenTCP(t.stack, *taddr, proto)
	}

	log.E("tun: accept: invalid network: %s to %s", network, local)
	return nil, &net.OpError{
		Op:     "tun: accept",
		Net:    network,
		Addr:   netaddr(local),
		Source: nil,
		Err:    net.UnknownNetworkError(network),
	}
}

// Probe implements protect.RDialer.
func (t *gtunnel) Probe(network, local string) (protect.PacketConn, error) {
	// TODO: implement probe
	return nil, &net.OpError{Op: "probe",
		Net:    network,
		Addr:   netaddr(local),
		Source: nil,
		Err:    net.UnknownNetworkError(network),
	}
}

func fulladdr(addr string) (a *tcpip.FullAddress, pn tcpip.NetworkProtocolNumber) {
	ipp, err := netip.ParseAddrPort(addr)
	if ipp.Addr().Is4() {
		pn = ipv4.ProtocolNumber
	} else {
		pn = ipv6.ProtocolNumber
	}
	if err != nil || !ipp.IsValid() || ipp.Addr().IsUnspecified() {
		log.V("tun: dial: invalid addr: proto(%d) %s; err? %v", pn, addr, err)
		return nil, pn
	}
	return fullAddrFrom(ipp), pn
}

func fullAddrFrom(ipp netip.AddrPort) *tcpip.FullAddress {
	var nsdaddr tcpip.Address
	if !ipp.IsValid() {
		return nil
	}
	if ipp.Addr().Is4() {
		nsdaddr = tcpip.AddrFrom4(ipp.Addr().As4())
	} else {
		nsdaddr = tcpip.AddrFrom16(ipp.Addr().As16())
	}
	log.V("tun: dial: translate ipp: %v -> %v", ipp, nsdaddr)
	return &tcpip.FullAddress{
		NIC:  settings.NICID,
		Addr: nsdaddr,
		Port: ipp.Port(), // may be 0
	}
}

// netaddr is a net.Addr that returns "any" as its network.
// Only used for error reporting.
type netaddr string

func (n netaddr) Network() string {
	return "any"
}

func (n netaddr) String() string {
	return string(n)
}
