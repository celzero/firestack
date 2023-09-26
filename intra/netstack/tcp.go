// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package netstack

import (
	"errors"
	"net"
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
const maxInFlight = 128

var (
	errNoOp = errors.New("unimpl for gtcpconn")
)

type GTCPConnHandler interface {
	Proxy(conn *GTCPConn, src, dst *net.TCPAddr) bool
	End() error
}

var _ core.TCPConn = (*GTCPConn)(nil)

type GTCPConn struct {
	*gonet.TCPConn
	ep  tcpip.Endpoint
	src *net.TCPAddr
	dst *net.TCPAddr
	req *tcp.ForwarderRequest
}

func setupTcpHandler(s *stack.Stack, h GTCPConnHandler) {
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, NewTCPForwarder(s, h).HandlePacket)
}

// nic.deliverNetworkPacket -> no existing matching endpoints -> NewTCPForwarder.HandlePacket
// ref: github.com/google/gvisor/blob/e89e736f1/pkg/tcpip/adapters/gonet/gonet_test.go#L189
func NewTCPForwarder(s *stack.Stack, h GTCPConnHandler) *tcp.Forwarder {
	return tcp.NewForwarder(s, rcvwnd, maxInFlight, func(request *tcp.ForwarderRequest) {
		id := request.ID()
		// src 10.111.222.1:38312
		src := remoteTCPAddr(id)
		// dst 213.188.195.179:80
		dst := localTCPAddr(id)

		// read/writes are routed using 5-tuple to the same conn (endpoint)
		// demuxer.handlePacket -> find matching endpoint -> queue-packet -> send/recv conn (ep)
		// ref: github.com/google/gvisor/blob/be6ffa7/pkg/tcpip/stack/transport_demuxer.go#L180
		gtcp := MakeGTCPConn(request, src, dst)
		go h.Proxy(gtcp, src, dst)
	})
}

func MakeGTCPConn(req *tcp.ForwarderRequest, src, dst *net.TCPAddr) *GTCPConn {
	// set sock-opts? github.com/xjasonlyu/tun2socks/blob/31468620e/core/tcp.go#L82
	return &GTCPConn{
		TCPConn: nil,
		ep:      nil,
		src:     src,
		dst:     dst,
		req:     req,
	}
}

func (g *GTCPConn) ok() bool {
	return g.TCPConn != nil
}

func (g *GTCPConn) StatefulTeardown() (rst bool) {
	if g.ok() {
		return g.Close() == nil
	}
	g.synack()           // establish circuit
	g.req.Complete(true) // then rst
	return true
}

func (g *GTCPConn) Connect(rst bool) (open bool) {
	if rst {
		g.req.Complete(rst)
		return false // closed
	}

	if g.ok() { // already setup
		return true // open
	}

	rst = g.synack()
	g.req.Complete(rst)

	log.V("ns.tcp.forwarder: proxy src(%v) => dst(%v); fin? %t", g.LocalAddr(), g.RemoteAddr(), rst)
	return !rst // open or closed
}

func (g *GTCPConn) synack() (rst bool) {
	wq := new(waiter.Queue)
	// the passive-handshake (SYN) may not successful for a non-existent route (say, ipv6)
	if ep, err := g.req.CreateEndpoint(wq); err != nil {
		log.E("ns.tcp.forwarder: data src(%v) => dst(%v); err(%v)", g.LocalAddr(), g.RemoteAddr(), err)
		// prevent potential half-open TCP connection leak.
		// hopefully doesn't break happy-eyeballs datatracker.ietf.org/doc/html/rfc8305#section-5
		// ie, apps that expect network-unreachable ICMP msgs instead of TCP RSTs?
		// TCP RST here is indistinguishable to an app from being firewalled.
		return true
	} else {
		g.ep = ep
		g.TCPConn = gonet.NewTCPConn(wq, ep)
		return false
	}
}

// gonet conn local and remote addresses may be nil
// ref: github.com/tailscale/tailscale/blob/8c5c87be2/wgengine/netstack/netstack.go#L768-L775
// and: github.com/google/gvisor/blob/ffabadf0/pkg/tcpip/transport/tcp/endpoint.go#L2759
func (g *GTCPConn) LocalAddr() net.Addr {
	if !g.ok() {
		return g.src
	}
	// client local addr is remote to the gonet adapter
	if addr := g.TCPConn.RemoteAddr(); addr != nil {
		return addr
	}
	return g.src
}

func (g *GTCPConn) RemoteAddr() net.Addr {
	if !g.ok() {
		return g.dst
	}
	// client remote addr is local to the gonet adapter
	if addr := g.TCPConn.LocalAddr(); addr != nil {
		return addr
	}
	return g.dst
}

// Sent will be called when sent data has been acknowledged by peer.
func (tcp *GTCPConn) Sent(len uint16) error {
	// no-op
	return errNoOp
}

// Receive will be called when data arrives from TUN.
func (tcp *GTCPConn) Receive(data []byte) error {
	// no-op
	return errNoOp
}

// Err will be called when a fatal error has occurred on the connection.
// The corresponding pcb is already freed when this callback is called
func (tcp *GTCPConn) Err(err error) {
	// no-op
}

// LocalClosed will be called when underlying stack
// receives a FIN segment on a connection.
func (tcp *GTCPConn) LocalClosed() error {
	// no-op
	return nil
}

// Poll will be periodically called by TCP timers.
func (tcp *GTCPConn) Poll() error {
	// no-op
	return nil
}

// Abort aborts the connection by sending a RST segment.
func (tcp *GTCPConn) Abort() {
	tcp.ep.Abort()
	tcp.Close()
}

func (g GTCPConn) Close() error {
	g.ep.Close()
	g.SetDeadline(time.Now().Add(-1))
	return g.Close()
}
