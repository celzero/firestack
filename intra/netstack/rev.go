// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package netstack

import (
	"net"
	"net/netip"

	"github.com/celzero/firestack/intra/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type revbase[T gconns] struct{}

type revtcp struct {
	*revbase[*GTCPConn]
	revstack *stack.Stack
	reverser GTCPConnHandler
	stackip4 netip.Addr
	stackip6 netip.Addr
}

type revudp struct {
	*revbase[*GUDPConn]
	revstack *stack.Stack
	reverser GUDPConnHandler
	stackip4 netip.Addr
	stackip6 netip.Addr
}

type revicmp struct {
	*revbase[*GUDPConn]
	revstack *stack.Stack
	revep    stack.LinkEndpoint
	reverser GICMPHandler
}

var _ GTCPConnHandler = (*revtcp)(nil)
var _ GUDPConnHandler = (*revudp)(nil)
var _ GICMPHandler = (*revicmp)(nil)

func NewReverseGConnHandler(to *stack.Stack, of tcpip.NICID, ep stack.LinkEndpoint, via GConnHandler) *gconnhandler {
	return &gconnhandler{
		tcp:  newReverseTCP(to, of, via.TCP()),
		udp:  newReverseUDP(to, of, via.UDP()),
		icmp: newReverseICMP(to, ep, via.ICMP()),
	}
}

func newReverseTCP(s *stack.Stack, nic tcpip.NICID, h GTCPConnHandler) *revtcp {
	ip4, ip6 := StackAddrs(s, nic)
	log.I("rev: nic %d newReverseTCP %v %v", nic, ip4, ip6)
	return &revtcp{
		revstack: s,
		reverser: h,
		stackip4: ip4,
		stackip6: ip6,
	}
}

func newReverseUDP(s *stack.Stack, nic tcpip.NICID, h GUDPConnHandler) *revudp {
	ip4, ip6 := StackAddrs(s, nic)
	log.I("rev: nic %d newReverseUDP %v %v", nic, ip4, ip6)
	return &revudp{
		revstack: s,
		reverser: h,
		stackip4: ip4,
		stackip6: ip6,
	}
}

func newReverseICMP(s *stack.Stack, ep stack.LinkEndpoint, h GICMPHandler) *revicmp {
	return &revicmp{revstack: s, revep: ep, reverser: h}
}

// Base

func (t *revbase[T]) ReverseProxy(out T, in net.Conn, src, dst netip.AddrPort) bool {
	// TODO: stub
	log.E("revbase: %T ReverseProxy not implemented %v <= %v", out, src, dst)
	return false
}

func (u *revbase[T]) Error(in T, src, dst netip.AddrPort, err error) {
	log.E("revbase: %T Error %v <= %v: %v", in, src, dst, err)
}

func (*revbase[T]) OpenConns() string {
	// TODO: stub
	return ""
}

func (*revbase[T]) CloseConns([]string) []string {
	// TODO: stub
	return nil
}

func (*revbase[T]) End() error {
	// TODO: stub
	return nil
}

// TCP

func (t *revtcp) Proxy(in *GTCPConn, src, dst netip.AddrPort) bool {
	// dst is local (just the port number assuming listening sockets)
	// to t.revstack to dial into; src is remote to t.revstack
	// ex: src 1.1.1.1:5555 / dst 10.0.1.1:1111
	err := InboundTCP(t.revstack, in, t.revipp(dst), src, t.reverser)
	logeif(err)("revtcp: Proxy %v <= %v; err? %v", src, dst, err)
	return err == nil
}

// ip local to revstack
func (r *revtcp) revipp(ipp netip.AddrPort) netip.AddrPort {
	if ipp.Addr().Is6() {
		return netip.AddrPortFrom(r.stackip6, ipp.Port())
	}
	return netip.AddrPortFrom(r.stackip4, ipp.Port())
}

// UDP

func (u *revudp) Proxy(in *GUDPConn, src, dst netip.AddrPort) bool {
	// see: revtcp.Proxy
	err := InboundUDP(u.revstack, in, u.revipp(dst), src, u.reverser)
	logeif(err)("revudp: Proxy %v <= %v; err? %v", src, dst, err)
	return err == nil
}

func (u *revudp) ProxyMux(in *GUDPConn, src, dst netip.AddrPort, mux DemuxerFn) bool {
	// TODO: impl mux/demux
	err := InboundUDP(u.revstack, in, u.revipp(dst), src, u.reverser)
	logeif(err)("revudp: ProxyMux %v <= %v; err? %v", src, dst, err)
	return err == nil
}

// ip local to revstack
func (r *revudp) revipp(ipp netip.AddrPort) netip.AddrPort {
	if ipp.Addr().Is6() {
		return netip.AddrPortFrom(r.stackip6, ipp.Port())
	}
	return netip.AddrPortFrom(r.stackip4, ipp.Port())
}

// ICMP

func (i *revicmp) Ping(msg []byte, src, dst netip.AddrPort) bool {
	// TODO: stub
	log.E("revicmp: Ping not implemented %v <= %v; err? %v", src, dst)
	return false
}

func logeif(err error) log.LogFn {
	if err != nil {
		return log.E
	}
	return log.V
}

func StackAddrs(s *stack.Stack, nic tcpip.NICID) (netip.Addr, netip.Addr) {
	zeromainaddr := tcpip.AddressWithPrefix{}
	ip4 := netip.IPv4Unspecified()
	ip6 := netip.IPv6Unspecified()
	mainaddr4, err4 := s.GetMainNICAddress(nic, header.IPv4ProtocolNumber)
	mainaddr6, err6 := s.GetMainNICAddress(nic, header.IPv6ProtocolNumber)
	if err4 != nil || err6 != nil {
		log.E("rev: StackAddrs %v; err: %v", nic, err4)
	}
	// comparable? github.com/google/gvisor/blob/1e97c039b/pkg/tcpip/adapters/gonet/gonet.go#L509
	if !mainaddr4.Address.Equal(zeromainaddr.Address) {
		ip4 = netip.AddrFrom4(mainaddr4.Address.As4())
	}
	if !mainaddr6.Address.Equal(zeromainaddr.Address) {
		ip6 = netip.AddrFrom16(mainaddr6.Address.As16())
	}
	log.V("rev: StackAddrs %v %v", ip4, ip6)
	return ip4, ip6
}
