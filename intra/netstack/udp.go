// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package netstack

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"gvisor.dev/gvisor/pkg/tcpip"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var errMissingEp = errors.New("not connected to any endpoint")

type GUDPConnHandler interface {
	// Proxy proxies data between conn (src) and dst.
	Proxy(conn *GUDPConn, src, dst netip.AddrPort) bool
	// ProxyMux proxies data between conn and multiple destinations.
	ProxyMux(conn *GUDPConn, src netip.AddrPort) bool
	// Error notes the error in connecting src to dst.
	Error(conn *GUDPConn, src, dst netip.AddrPort, err error)
	// CloseConns closes conns by ids, or all if ids is empty.
	CloseConns([]string) []string
	// End closes the handler and all its connections.
	End() error
}

var _ core.UDPConn = (*GUDPConn)(nil)

type GUDPConn struct {
	c   *core.Volatile[*gonet.UDPConn] // conn exposes UDP semantics atop endpoint
	ep  *core.Volatile[tcpip.Endpoint] // ep is the endpoint for netstack io
	src netip.AddrPort                 // local addr (remote addr in netstack)
	dst netip.AddrPort                 // remote addr (local addr in netstack)
	req *udp.ForwarderRequest          // egress request as UDP
}

// ref: github.com/google/gvisor/blob/e89e736f1/pkg/tcpip/adapters/gonet/gonet_test.go#L373
func makeGUDPConn(r *udp.ForwarderRequest, src, dst netip.AddrPort) *GUDPConn {
	return &GUDPConn{
		c:   core.NewZeroVolatile[*gonet.UDPConn](),
		ep:  core.NewZeroVolatile[tcpip.Endpoint](),
		src: src,
		dst: dst,
		req: r,
	}
}

func setupUdpHandler(s *stack.Stack, h GUDPConnHandler) {
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder(s, h).HandlePacket)
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
func udpForwarder(s *stack.Stack, h GUDPConnHandler) *udp.Forwarder {
	return udp.NewForwarder(s, func(req *udp.ForwarderRequest) {
		if req == nil {
			log.E("ns: udp: forwarder: nil request")
			return
		}
		id := req.ID()
		// src 10.111.222.1:20716; same as endpoint.GetRemoteAddress
		src := remoteAddrPort(id)
		// dst 10.111.222.3:53; same as endpoint.GetLocalAddress
		// but it may not always be the true dst (for now it is),
		// especially if the resulting udp-conn is setup to handle
		// multiple dst in the unconnected udp case.
		dst := localAddrPort(id)

		gc := makeGUDPConn(req, src, dst)
		// setup to recv right away, so that netstack's internal state is consistent
		// in case there are multiple forwarders dispatching from the TUN device.
		if !settings.SingleThreadedTUNForwarder {
			if err := gc.tryConnect(); err != nil {
				log.E("ns: udp: forwarder: connect: %v; src(%v) dst(%v)", err, src, dst)
				go h.Error(gc, src, dst, err)
				return
			}
		}

		// proxy in a separate gorountine; return immediately
		// why? netstack/dispatcher.go:newReadvDispatcher
		if gc.connected() { // gc is connected udp; proxy it like a stream
			go h.Proxy(gc, src, dst)
		} else {
			go h.ProxyMux(gc, src)
		}
	})
}

func (g *GUDPConn) ok() bool {
	return g.conn() != nil
}

func (g *GUDPConn) conn() *gonet.UDPConn {
	return g.c.Load()
}

func (g *GUDPConn) endpoint() tcpip.Endpoint {
	return g.ep.Load()
}

func (g *GUDPConn) StatefulTeardown() (fin bool) {
	_ = g.tryConnect() // establish circuit then teardown
	_ = g.Close()      // then shutdown
	return true        // always fin
}

func (g *GUDPConn) Connect() error {
	return g.tryConnect()
}

func (g *GUDPConn) tryConnect() error {
	if g.ok() { // already setup
		return nil
	}

	wq := new(waiter.Queue)
	// use gonet.DialUDP instead?
	if endpoint, err := g.req.CreateEndpoint(wq); err != nil {
		// ex: CONNECT endpoint for [fd66:f83a:c650::1]:15753 => [fd66:f83a:c650::3]:53; err(no route to host)
		log.E("ns: udp: connect: endpoint for %v => %v; err(%v)", g.src, g.dst, err)
		return e(err)
	} else {
		g.ep.Store(endpoint)
		g.c.Store(gonet.NewUDPConn(wq, endpoint))
	}
	return nil
}

func (g *GUDPConn) LocalAddr() (addr net.Addr) {
	if c := g.conn(); c != nil {
		addr = c.RemoteAddr()
	}
	if addr == nil { // remoteaddr may be nil, even if g.ok()
		addr = net.UDPAddrFromAddrPort(g.src)
	}
	return
}

func (g *GUDPConn) RemoteAddr() (addr net.Addr) {
	if c := g.conn(); c != nil {
		addr = c.LocalAddr()
	}
	if addr == nil { // localaddr may be nil, even if g.ok()
		addr = net.UDPAddrFromAddrPort(g.dst)
	}
	return
}

func (g *GUDPConn) Write(data []byte) (int, error) {
	if c := g.conn(); c != nil {
		// nb: write-deadlines set by intra.udp
		// addr: 10.111.222.3:17711; g.LocalAddr(g.udp.remote): 10.111.222.3:17711; g.RemoteAddr(g.udp.local): 10.111.222.1:53
		// ep(state 3 / info &{2048 17 {53 10.111.222.3 17711 10.111.222.1} 1 10.111.222.3 1} / stats &{{{1}} {{0}} {{{0}} {{0}} {{0}} {{0}}} {{{0}} {{0}} {{0}}} {{{0}} {{0}}} {{{0}} {{0}} {{0}}}})
		// 3: status:datagram-connected / {2048=>proto, 17=>transport, {53=>local-port localip 17711=>remote-port remoteip}=>endpoint-id, 1=>bind-nic-id, ip=>bind-addr, 1=>registered-nic-id}
		// g.ep may be nil: log.V("ns: writeFrom: from(%v) / ep(state %v / info %v / stats %v)", addr, g.ep.State(), g.ep.Info(), g.ep.Stats())
		return c.Write(data)
	}
	return 0, netError(g, "udp", "write", io.ErrClosedPipe)
}

func (g *GUDPConn) Read(data []byte) (int, error) {
	if c := g.conn(); c != nil {
		return c.Read(data)
	}
	return 0, netError(g, "udp", "read", io.ErrNoProgress)
}

func (g *GUDPConn) WriteTo(data []byte, addr net.Addr) (int, error) {
	if c := g.conn(); c != nil {
		return c.WriteTo(data, addr)
	}
	return 0, netError(g, "udp", "writeTo", net.ErrWriteToConnected)
}

func (g *GUDPConn) ReadFrom(data []byte) (int, net.Addr, error) {
	if c := g.conn(); c != nil {
		return c.ReadFrom(data)
	}
	return 0, nil, netError(g, "udp", "readFrom", io.ErrNoProgress)
}

func (g *GUDPConn) SetDeadline(t time.Time) error {
	if c := g.conn(); c != nil {
		return c.SetDeadline(t)
	} // else: no-op as with netstack's gonet impl
	return nil
}

func (g *GUDPConn) SetReadDeadline(t time.Time) error {
	if c := g.conn(); c != nil {
		return c.SetReadDeadline(t)
	} // else: no-op as with netstack's gonet impl
	return nil
}

func (g *GUDPConn) SetWriteDeadline(t time.Time) error {
	if c := g.conn(); c != nil {
		return c.SetWriteDeadline(t)
	} // else: no-op as with netstack's gonet impl
	return nil
}

// Close closes the connection.
func (g *GUDPConn) Close() error {
	if ep := g.endpoint(); ep != nil {
		ep.Abort()
	}
	if c := g.conn(); c != nil {
		_ = c.Close()
	}
	return nil
}

func (g *GUDPConn) connected() bool {
	return !g.dst.Addr().IsUnspecified()
}
