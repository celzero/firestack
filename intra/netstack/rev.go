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
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type revtcp struct {
	revstack *stack.Stack
	reverser GTCPConnHandler
}

type revudp struct {
	revstack *stack.Stack
	reverser GUDPConnHandler
}

type revicmp struct {
	revstack *stack.Stack
	revep    stack.LinkEndpoint
	reverser GICMPHandler
}

var _ GTCPConnHandler = (*revtcp)(nil)
var _ GUDPConnHandler = (*revudp)(nil)
var _ GICMPHandler = (*revicmp)(nil)

func NewReverseGConnHandler(to *stack.Stack, ep stack.LinkEndpoint, via GConnHandler) *gconnhandler {
	return &gconnhandler{
		tcp:  newReverseTCP(to, via.TCP()),
		udp:  newReverseUDP(to, via.UDP()),
		icmp: newReverseICMP(to, ep, via.ICMP()),
	}
}

func newReverseTCP(s *stack.Stack, h GTCPConnHandler) *revtcp {
	return &revtcp{revstack: s, reverser: h}
}

func newReverseUDP(s *stack.Stack, h GUDPConnHandler) *revudp {
	return &revudp{revstack: s, reverser: h}
}

func newReverseICMP(s *stack.Stack, ep stack.LinkEndpoint, h GICMPHandler) *revicmp {
	return &revicmp{revstack: s, revep: ep, reverser: h}
}

// TCP

func (t *revtcp) Proxy(in *GTCPConn, src, dst netip.AddrPort) bool {
	// dst is local (just the port number assuming listening sockets)
	// to t.revstack to dial into; src is remote to t.revstack
	// ex: src 1.1.1.1:5555 / dst 10.0.1.1:1111
	err := InboundTCP(t.revstack, in, dst, src, t.reverser)
	logeif(err)("revtcp: Proxy %v <= %v; err? %v", src, dst, err)
	return err == nil
}

func (t *revtcp) ReverseProxy(out *GTCPConn, in net.Conn, src, dst netip.AddrPort) bool {
	// TODO: stub
	log.E("revtcp: ReverseProxy not implemented %v <= %v", src, dst)
	return false
}

func (t *revtcp) Error(in *GTCPConn, src, dst netip.AddrPort, err error) {
	log.E("revtcp: error %v => %v: %v", src, dst, err)
}

func (t *revtcp) CloseConns([]string) []string {
	// TODO: stub
	return nil
}

func (t *revtcp) End() error {
	// TODO: stub
	return nil
}

// UDP

func (u *revudp) Proxy(in *GUDPConn, src, dst netip.AddrPort) bool {
	// see: revtcp.Proxy
	err := InboundUDP(u.revstack, in, dst, src, u.reverser)
	logeif(err)("revudp: Proxy %v <= %v; err? %v", src, dst, err)
	return err == nil
}

func (u *revudp) ProxyMux(in *GUDPConn, src, dst netip.AddrPort, mux DemuxerFn) bool {
	// TODO: impl mux/demux
	err := InboundUDP(u.revstack, in, src, dst, u.reverser)
	logeif(err)("revudp: ProxyMux %v <= %v; err? %v", src, dst, err)
	return err == nil
}

func (u *revudp) ReverseProxy(out *GUDPConn, in net.Conn, src, dst netip.AddrPort) bool {
	// TODO: stub
	log.E("revudp: ReverseProxy not implemented %v <= %v", src, dst)
	return false
}

func (u *revudp) Error(in *GUDPConn, src, dst netip.AddrPort, err error) {
	log.E("revudp: error %v <= %v: %v", src, dst, err)
}

func (u *revudp) CloseConns([]string) []string {
	// TODO: stub
	return nil
}

func (u *revudp) End() error {
	// TODO: stub
	return nil
}

// ICMP

func (i *revicmp) Ping(src, dst netip.AddrPort, msg []byte) bool {
	// TODO: stub
	log.E("revicmp: Ping not implemented %v <= %v; err? %v", src, dst)
	return false
}

func (*revicmp) CloseConns([]string) []string {
	// TODO: stub
	return nil
}

func (*revicmp) End() error {
	// TODO: stub
	return nil
}

func logeif(err error) log.LogFn {
	if err != nil {
		return log.E
	}
	return log.V
}
