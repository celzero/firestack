// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package netstack

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/celzero/firestack/intra/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type revbase[T gconns] struct {
	o     string // owner
	ended atomic.Bool
}

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
	*revbase[*GICMPConn]
	revstack *stack.Stack
	revep    stack.LinkEndpoint
	reverser GICMPHandler
}

var _ GTCPConnHandler = (*revtcp)(nil)
var _ GUDPConnHandler = (*revudp)(nil)
var _ GICMPHandler = (*revicmp)(nil)

func NewReverseGConnHandler(id string, pctx context.Context, to *stack.Stack, of tcpip.NICID, ep stack.LinkEndpoint, via GConnHandler) *gconnhandler {
	h := &gconnhandler{
		tcp:  newReverseTCP(id, to, of, via.TCP()),
		udp:  newReverseUDP(id, to, of, via.UDP()),
		icmp: newReverseICMP(id, to, ep, via.ICMP()),
	}
	log.I("rev: %s: newReverseGConnHandler %d @ %x", id, of, to)
	context.AfterFunc(pctx, h.end)
	return h
}

func newReverseTCP(id string, s *stack.Stack, nic tcpip.NICID, h GTCPConnHandler) *revtcp {
	ip4, ip6 := StackAddrs(s, nic)
	log.I("rev: %s: nic %d newReverseTCP %v %v", id, nic, ip4, ip6)
	return &revtcp{
		revbase:  &revbase[*GTCPConn]{o: id},
		revstack: s,
		reverser: h,
		stackip4: ip4,
		stackip6: ip6,
	}
}

func newReverseUDP(id string, s *stack.Stack, nic tcpip.NICID, h GUDPConnHandler) *revudp {
	ip4, ip6 := StackAddrs(s, nic)
	log.I("rev: %s: nic %d newReverseUDP %v %v", id, nic, ip4, ip6)
	return &revudp{
		revbase:  &revbase[*GUDPConn]{o: id},
		revstack: s,
		reverser: h,
		stackip4: ip4,
		stackip6: ip6,
	}
}

func newReverseICMP(id string, s *stack.Stack, ep stack.LinkEndpoint, h GICMPHandler) *revicmp {
	return &revicmp{
		revbase:  &revbase[*GICMPConn]{o: id},
		revstack: s,
		revep:    ep,
		reverser: h,
	}
}

// GConnHandler

func (g *gconnhandler) end() {
	if t := g.tcp; t != nil {
		t.End()
	}
	if u := g.udp; u != nil {
		u.End()
	}
	if i := g.icmp; i != nil {
		i.End()
	}
	log.I("rev: gconnhandler end")
}

// Base

func (b *revbase[T]) ReverseProxy(out T, in net.Conn, src, dst netip.AddrPort) bool {
	// TODO: stub
	log.E("rev: %s: revbase: %T ReverseProxy not implemented %v <= %v", b.o, out, src, dst)
	return false
}

func (b *revbase[T]) Error(in T, src, dst netip.AddrPort, err error) {
	log.E("rev: %s: revbase: %T Error %v <= %v: %v", b.o, in, src, dst, err)
}

func (*revbase[T]) OpenConns() string {
	// TODO: stub
	return ""
}

func (*revbase[T]) CloseConns([]string) []string {
	// TODO: stub
	return nil
}

func (r *revbase[T]) End() {
	r.ended.Store(true)
}

// TCP

func (t *revtcp) Proxy(in *GTCPConn, src, dst netip.AddrPort) bool {
	end := t.ended.Load()
	log.D("rev: %s: revtcp: Proxy %v <= %v; end? %t", t.o, src, dst, end)
	if end {
		return false
	}
	// dst is local (just the port number assuming listening sockets)
	// to t.revstack to dial into; src is remote to t.revstack
	// ex: src 1.1.1.1:5555 / dst 10.0.1.1:1111
	err := InboundTCP(t.o, t.revstack, in, t.revipp(dst), src, t.reverser)
	logeif(err)("rev: %s: revtcp: Proxy %v <= %v; err? %v", t.o, src, dst, err)
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
	end := u.ended.Load()
	log.D("rev: %s: revudp: Proxy %v <= %v; end? %t", u.o, src, dst, end)
	if end {
		return false
	}
	// see: revtcp.Proxy
	err := InboundUDP(u.o, u.revstack, in, u.revipp(dst), src, u.reverser)
	logeif(err)("rev: %s: revudp: Proxy %v <= %v; err? %v", u.o, src, dst, err)
	return err == nil
}

func (u *revudp) ProxyMux(in *GUDPConn, src, dst netip.AddrPort, mux DemuxerFn) bool {
	end := u.ended.Load()
	log.D("rev: %s: revudp: ProxyMux %v <= %v; end? %t", u.o, src, dst, end)
	if end {
		return false
	}
	// TODO: impl mux/demux
	err := InboundUDP(u.o, u.revstack, in, u.revipp(dst), src, u.reverser)
	logeif(err)("rev: %s: revudp: ProxyMux %v <= %v; err? %v", u.o, src, dst, err)
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
	log.E("rev: %s: revicmp: Ping not implemented %v <= %v; err? %v", i.o, src, dst)
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
