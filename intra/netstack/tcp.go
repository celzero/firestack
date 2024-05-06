// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package netstack

import (
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// ref: github.com/tailscale/tailscale/blob/cfb5bd0559/wgengine/netstack/netstack.go#L236-L237
const rcvwnd = 0

const maxInFlight = 512 // arbitrary

type GTCPConnHandler interface {
	// Proxy copies data between src and dst.
	Proxy(conn *GTCPConn, src, dst netip.AddrPort) bool
	// CloseConns closes conns by cids, or all conns if cids is empty.
	CloseConns([]string) []string
	// End closes all conns and releases resources.
	End() error
}

var _ core.TCPConn = (*GTCPConn)(nil)

type GTCPConn struct {
	conn *gonet.TCPConn
	ep   tcpip.Endpoint
	src  netip.AddrPort
	dst  netip.AddrPort
	req  *tcp.ForwarderRequest
}

func setupTcpHandler(s *stack.Stack, h GTCPConnHandler) {
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, NewTCPForwarder(s, h).HandlePacket)
}

// nic.deliverNetworkPacket -> no existing matching endpoints -> NewTCPForwarder.HandlePacket
// ref: github.com/google/gvisor/blob/e89e736f1/pkg/tcpip/adapters/gonet/gonet_test.go#L189
func NewTCPForwarder(s *stack.Stack, h GTCPConnHandler) *tcp.Forwarder {
	return tcp.NewForwarder(s, rcvwnd, maxInFlight, func(request *tcp.ForwarderRequest) {
		if request == nil {
			log.E("ns: tcp: forwarder: nil request")
			return
		}
		id := request.ID()
		// src 10.111.222.1:38312
		src := remoteAddrPort(id)
		// dst 213.188.195.179:80
		dst := localAddrPort(id)

		// read/writes are routed using 5-tuple to the same conn (endpoint)
		// demuxer.handlePacket -> find matching endpoint -> queue-packet -> send/recv conn (ep)
		// ref: github.com/google/gvisor/blob/be6ffa7/pkg/tcpip/stack/transport_demuxer.go#L180
		gtcp := MakeGTCPConn(request, src, dst)
		go h.Proxy(gtcp, src, dst)
	})
}

func MakeGTCPConn(req *tcp.ForwarderRequest, src, dst netip.AddrPort) *GTCPConn {
	// set sock-opts? github.com/xjasonlyu/tun2socks/blob/31468620e/core/tcp.go#L82
	return &GTCPConn{
		conn: nil,
		ep:   nil,
		src:  src,
		dst:  dst,
		req:  req,
	}
}

func (g *GTCPConn) ok() bool {
	return g.conn != nil
}

func (g *GTCPConn) StatefulTeardown() (rst bool) {
	if g.ok() {
		_ = g.Close() // g.TCPConn.Close error always nil
	} else {
		_, _ = g.synack()    // establish circuit
		g.req.Complete(true) // then rst
	}
	return true // always rst
}

func (g *GTCPConn) Connect(rst bool) (open bool, err error) {
	if rst {
		g.req.Complete(rst)
		return false, nil // closed
	}

	if g.ok() { // already setup
		return true, nil // open
	}

	rst, err = g.synack()
	g.req.Complete(rst)

	log.VV("ns: tcp: forwarder: proxy src(%v) => dst(%v); fin? %t", g.LocalAddr(), g.RemoteAddr(), rst)
	return !rst, err // open or closed
}

func (g *GTCPConn) synack() (rst bool, err error) {
	wq := new(waiter.Queue)
	// the passive-handshake (SYN) may not successful for a non-existent route (say, ipv6)
	if ep, err := g.req.CreateEndpoint(wq); err != nil {
		log.E("ns: tcp: forwarder: data src(%v) => dst(%v); err(%v)", g.LocalAddr(), g.RemoteAddr(), err)
		// prevent potential half-open TCP connection leak.
		// hopefully doesn't break happy-eyeballs datatracker.ietf.org/doc/html/rfc8305#section-5
		// ie, apps that expect network-unreachable ICMP msgs instead of TCP RSTs?
		// TCP RST here is indistinguishable to an app from being firewalled.
		return true, e(err)
	} else {
		g.ep = ep
		g.conn = gonet.NewTCPConn(wq, ep)
		return false, nil
	}
}

// gonet conn local and remote addresses may be nil
// ref: github.com/tailscale/tailscale/blob/8c5c87be2/wgengine/netstack/netstack.go#L768-L775
// and: github.com/google/gvisor/blob/ffabadf0/pkg/tcpip/transport/tcp/endpoint.go#L2759
func (g *GTCPConn) LocalAddr() net.Addr {
	if !g.ok() {
		return net.TCPAddrFromAddrPort(g.src)
	}
	// client local addr is remote to the gonet adapter
	if addr := g.conn.RemoteAddr(); addr != nil {
		return addr
	}
	return net.TCPAddrFromAddrPort(g.src)
}

func (g *GTCPConn) RemoteAddr() net.Addr {
	if !g.ok() {
		return net.TCPAddrFromAddrPort(g.dst)
	}
	// client remote addr is local to the gonet adapter
	if addr := g.conn.LocalAddr(); addr != nil {
		return addr
	}
	return net.TCPAddrFromAddrPort(g.dst)
}

func (g *GTCPConn) Write(data []byte) (int, error) {
	if !g.ok() {
		return 0, g.netError("write", io.EOF)
	}
	return g.conn.Write(data)
}

func (g *GTCPConn) Read(data []byte) (int, error) {
	if !g.ok() {
		return 0, g.netError("read", io.EOF)
	}
	return g.conn.Read(data)
}

func (g *GTCPConn) CloseWrite() error {
	if !g.ok() {
		return g.netError("close", net.ErrClosed)
	}
	return g.conn.CloseWrite()
}

func (g *GTCPConn) CloseRead() error {
	if !g.ok() {
		return g.netError("close", net.ErrClosed)
	}
	return g.conn.CloseRead()
}

func (g *GTCPConn) SetDeadline(t time.Time) error {
	if g.ok() {
		return g.conn.SetDeadline(t)
	}
	return nil // no-op to confirm with netstack's gonet impl
}

func (g *GTCPConn) SetReadDeadline(t time.Time) error {
	if g.ok() {
		return g.conn.SetReadDeadline(t)
	}
	return nil // no-op to confirm with netstack's gonet impl
}

func (g *GTCPConn) SetWriteDeadline(t time.Time) error {
	if g.ok() {
		return g.conn.SetWriteDeadline(t)
	}
	return nil // no-op to confirm with netstack's gonet impl
}

// Abort aborts the connection by sending a RST segment.
func (g *GTCPConn) Abort() {
	ep := g.ep
	c := g.conn
	if ep != nil {
		ep.Abort()
	}
	if c != nil {
		_ = c.Close()
	}
}

func (g GTCPConn) Close() error {
	ep := g.ep
	c := g.conn
	if ep != nil {
		ep.Abort()
	}
	if c != nil {
		_ = c.SetDeadline(time.Now().Add(-1))
		return c.Close() // always returns nil; see gonet.TCPConn.Close
	}
	return nil
}

// from: netstack gonet
func (c *GTCPConn) netError(op string, err error) *net.OpError {
	return &net.OpError{
		Op:     op,
		Net:    "tcp",
		Source: c.LocalAddr(),
		Addr:   c.RemoteAddr(),
		Err:    err,
	}
}
