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
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"gvisor.dev/gvisor/pkg/tcpip"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var errMissingEp = errors.New("udp not connected to any endpoint")

type GUDPConnHandler interface {
	// Proxy proxies data between conn (src) and dst.
	Proxy(conn *GUDPConn, src, dst netip.AddrPort) bool
	// ProxyMux proxies data between conn and multiple destinations.
	ProxyMux(conn *GUDPConn, src netip.AddrPort) bool
	// CloseConns closes conns by ids, or all if ids is empty.
	CloseConns([]string) []string
	// End closes the handler and all its connections.
	End() error
}

var _ core.UDPConn = (*GUDPConn)(nil)

type GUDPConn struct {
	conn *gonet.UDPConn
	ep   tcpip.Endpoint
	src  netip.AddrPort
	dst  netip.AddrPort
	req  *udp.ForwarderRequest
}

// ref: github.com/google/gvisor/blob/e89e736f1/pkg/tcpip/adapters/gonet/gonet_test.go#L373
func MakeGUDPConn(r *udp.ForwarderRequest, src, dst netip.AddrPort) *GUDPConn {
	return &GUDPConn{
		ep:  nil,
		src: src,
		dst: dst,
		req: r,
	}
}

func setupUdpHandler(s *stack.Stack, h GUDPConnHandler) {
	s.SetTransportProtocolHandler(udp.ProtocolNumber, NewUDPForwarder(s, h).HandlePacket)
}

// Perhaps udp conns shouldn't be closed as eagerly as its tcp counterpart
// Netstack's udp conn is apparently a 'connected udp' socket and it goes through a
// lot of motions, from what I can tell, to support both unconnected and connected
// udp sockets. This is untested and unconfirmed speculation from us, but unless
// intra/udp.go refrains from closing this udp conn, we'll never find out I guess.
// ref: github.com/google/gvisor/blob/be6ffa7/pkg/tcpip/stack/transport_demuxer.go#L590
// and: github.com/google/gvisor/blob/be6ffa7/pkg/tcpip/stack/transport_demuxer.go#L75
// and: github.com/google/gvisor/blob/be6ffa7/pkg/tcpip/transport/udp/endpoint.go#L903
// via: github.com/google/gvisor/blob/be6ffa7/pkg/tcpip/adapters/gonet/gonet.go#L315
// fin: github.com/google/gvisor/blob/be6ffa7/pkg/tcpip/transport/udp/endpoint.go#L220
// but: github.com/google/gvisor/blob/be6ffa7/pkg/tcpip/transport/udp/endpoint.go#L180
func NewUDPForwarder(s *stack.Stack, h GUDPConnHandler) *udp.Forwarder {
	return udp.NewForwarder(s, func(request *udp.ForwarderRequest) {
		if request == nil {
			log.E("ns: udp: forwarder: nil request")
			return
		}
		id := request.ID()

		// src 10.111.222.1:20716; same as endpoint.GetRemoteAddress
		src := remoteAddrPort(id)
		// dst 10.111.222.3:53; same as endpoint.GetLocalAddress
		// but it may not always be the true dst (for now it is),
		// especially if the resulting udp-conn is setup to handle
		// multiple dst in the unconnected udp case.
		dst := localAddrPort(id)

		gc := MakeGUDPConn(request, src, dst)

		// if gc is a connected udp socket; proxy it like a stream
		if !dst.Addr().IsUnspecified() {
			h.Proxy(gc, src, dst)
		} else {
			h.ProxyMux(gc, src)
		}
	})
}

func (g *GUDPConn) ok() bool {
	return g.ep != nil && g.conn != nil
}

func (g *GUDPConn) StatefulTeardown() (fin bool) {
	if !g.ok() {
		_ = g.Connect(false) // establish circuit then teardown
	}

	return g.Close() == nil // then fin
}

func (g *GUDPConn) Connect(fin bool) error {
	if fin {
		return e(&tcpip.ErrHostUnreachable{})
	}

	wq := new(waiter.Queue)
	// use gonet.DialUDP instead?
	if endpoint, err := g.req.CreateEndpoint(wq); err != nil {
		// ex: CONNECT endpoint for [fd66:f83a:c650::1]:15753 => [fd66:f83a:c650::3]:53; err(no route to host)
		log.E("ns: udp: connect: endpoint for %v => %v; err(%v)", g.src, g.dst, err)
		return e(err)
	} else {
		g.ep = endpoint
		g.conn = gonet.NewUDPConn(wq, endpoint)
	}
	return nil
}

func (g *GUDPConn) LocalAddr() (addr net.Addr) {
	if g.ok() {
		addr = g.conn.RemoteAddr()
	}
	if addr == nil { // remoteaddr may be nil, even if g.ok()
		addr = net.UDPAddrFromAddrPort(g.src)
	}
	return
}

func (g *GUDPConn) RemoteAddr() (addr net.Addr) {
	if g.ok() {
		addr = g.conn.LocalAddr()
	}
	if addr == nil { // localaddr may be nil, even if g.ok()
		addr = net.UDPAddrFromAddrPort(g.dst)
	}
	return
}

func (g *GUDPConn) Write(data []byte) (int, error) {
	if !g.ok() {
		return 0, errMissingEp
	}
	// nb: write-deadlines set by intra.udp
	// addr: 10.111.222.3:17711; g.LocalAddr(g.udp.remote): 10.111.222.3:17711; g.RemoteAddr(g.udp.local): 10.111.222.1:53
	// ep(state 3 / info &{2048 17 {53 10.111.222.3 17711 10.111.222.1} 1 10.111.222.3 1} / stats &{{{1}} {{0}} {{{0}} {{0}} {{0}} {{0}}} {{{0}} {{0}} {{0}}} {{{0}} {{0}}} {{{0}} {{0}} {{0}}}})
	// 3: status:datagram-connected / {2048=>proto, 17=>transport, {53=>local-port localip 17711=>remote-port remoteip}=>endpoint-id, 1=>bind-nic-id, ip=>bind-addr, 1=>registered-nic-id}
	// g.ep may be nil: log.V("ns: writeFrom: from(%v) / ep(state %v / info %v / stats %v)", addr, g.ep.State(), g.ep.Info(), g.ep.Stats())
	return g.conn.Write(data)
}

func (g *GUDPConn) Read(data []byte) (int, error) {
	if !g.ok() {
		return 0, errMissingEp
	}
	return g.conn.Read(data)
}

func (g *GUDPConn) WriteTo(data []byte, addr net.Addr) (int, error) {
	if !g.ok() {
		return 0, errMissingEp
	}
	return g.conn.WriteTo(data, addr)
}

func (g *GUDPConn) ReadFrom(data []byte) (int, net.Addr, error) {
	if !g.ok() {
		return 0, nil, errMissingEp
	}
	return g.conn.ReadFrom(data)
}

func (g *GUDPConn) SetDeadline(t time.Time) error {
	if !g.ok() {
		return errMissingEp
	}
	return g.conn.SetDeadline(t)
}

func (g *GUDPConn) SetReadDeadline(t time.Time) error {
	if !g.ok() {
		return errMissingEp
	}
	return g.conn.SetReadDeadline(t)
}

func (g *GUDPConn) SetWriteDeadline(t time.Time) error {
	if !g.ok() {
		return errMissingEp
	}
	return g.conn.SetWriteDeadline(t)
}

// Close closes the connection.
func (g *GUDPConn) Close() error {
	if !g.ok() {
		_ = g.Connect(true)
		return nil
	}
	ep := g.ep
	if ep != nil {
		ep.Abort()
	}
	core.Close(g.conn)
	return nil
}
