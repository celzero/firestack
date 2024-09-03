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
	"sync"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// ref: github.com/tailscale/tailscale/blob/cfb5bd0559/wgengine/netstack/netstack.go#L236-L237
const rcvwnd = 0

const maxInFlight = 512 // arbitrary

var (
	// defaults: github.com/google/gvisor/blob/fa49677e141db/pkg/tcpip/transport/tcp/protocol.go#L73
	// idle: 2h; count: 9; interval: 75s
	defaultKeepAliveIdle     = tcpip.KeepaliveIdleOption(10 * time.Minute)
	defaultKeepAliveInterval = tcpip.KeepaliveIntervalOption(5 * time.Second)
	defaultKeepAliveCount    = 4 // unacknowledged probes
	// github.com/tailscale/tailscale/blob/65fe0ba7b5/cmd/derper/derper.go#L75-L78
	defaultUserTimeout = tcpip.TCPUserTimeoutOption(60 * time.Second)
)

type GTCPConnHandler interface {
	// Proxy copies data between src and dst.
	Proxy(conn *GTCPConn, src, dst netip.AddrPort) bool
	// Error notes the error in connecting src to dst; retrying if necessary.
	Error(conn *GTCPConn, src, dst netip.AddrPort, err error)
	// CloseConns closes conns by cids, or all conns if cids is empty.
	CloseConns([]string) []string
	// End closes all conns and releases resources.
	End() error
}

var _ core.TCPConn = (*GTCPConn)(nil)

type GTCPConn struct {
	c    *core.Volatile[*gonet.TCPConn] // conn exposes TCP semantics atop endpoint
	src  netip.AddrPort                 // local addr (remote addr in netstack)
	dst  netip.AddrPort                 // remote addr (local addr in netstack)
	req  *tcp.ForwarderRequest          // egress request as a TCP state machine
	once sync.Once
}

func setupTcpHandler(s *stack.Stack, h GTCPConnHandler) {
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder(s, h).HandlePacket)
}

// nic.deliverNetworkPacket -> no existing matching endpoints -> tcpForwarder.HandlePacket
// ref: github.com/google/gvisor/blob/e89e736f1/pkg/tcpip/adapters/gonet/gonet_test.go#L189
func tcpForwarder(s *stack.Stack, h GTCPConnHandler) *tcp.Forwarder {
	return tcp.NewForwarder(s, rcvwnd, maxInFlight, func(req *tcp.ForwarderRequest) {
		if req == nil {
			log.E("ns: tcp: forwarder: nil request")
			return
		}
		id := req.ID()
		// src 10.111.222.1:38312
		src := remoteAddrPort(id)
		// dst 213.188.195.179:80
		dst := localAddrPort(id)

		// read/writes are routed using 5-tuple to the same conn (endpoint)
		// demuxer.handlePacket -> find matching endpoint -> queue-packet -> send/recv conn (ep)
		// ref: github.com/google/gvisor/blob/be6ffa7/pkg/tcpip/stack/transport_demuxer.go#L180
		gtcp := makeGTCPConn(req, src, dst)
		// setup endpoint right away, so that netstack's internal state is consistent
		// in case there are multiple forwarders dispatching from the TUN device.
		if !settings.SingleThreaded.Load() {
			if open, err := gtcp.tryConnect(); err != nil || !open {
				log.E("ns: tcp: forwarder: tryConnect err src(%v) => dst(%v); open? %t, err(%v)", src, dst, open, err)
				if err == nil {
					err = errMissingEp
				}
				go h.Error(gtcp, src, dst, err) // error
				return
			}
		}

		// must always handle it in a separate goroutine as it may block netstack
		// see: netstack/dispatcher.go:newReadvDispatcher
		go h.Proxy(gtcp, src, dst)
	})
}

func makeGTCPConn(req *tcp.ForwarderRequest, src, dst netip.AddrPort) *GTCPConn {
	// set sock-opts? github.com/xjasonlyu/tun2socks/blob/31468620e/core/tcp.go#L82
	return &GTCPConn{
		c:   core.NewZeroVolatile[*gonet.TCPConn](),
		src: src,
		dst: dst,
		req: req,
	}
}

func (g *GTCPConn) ok() bool {
	return g.conn() != nil
}

func (g *GTCPConn) conn() *gonet.TCPConn {
	return g.c.Load()
}

func (g *GTCPConn) Establish() (open bool, err error) {
	rst, err := g.synack(true)

	log.VV("ns: tcp: forwarder: connect src(%v) => dst(%v); fin? %t", g.LocalAddr(), g.RemoteAddr(), rst)
	return !rst, err
}

func (g *GTCPConn) tryConnect() (open bool, err error) {
	rst, err := g.synack(false)

	log.VV("ns: tcp: forwarder: proxy src(%v) => dst(%v); fin? %t", g.LocalAddr(), g.RemoteAddr(), rst)
	return !rst, err // open or closed
}

// complete must be called at least once, otherwise the conn counts towards
// maxInFlight and may cause silent tcp conn drops.
func (g *GTCPConn) complete(rst bool) {
	g.once.Do(func() {
		log.D("ns: tcp: forwarder: complete src(%v) => dst(%v); rst? %t", g.LocalAddr(), g.RemoteAddr(), rst)
		g.req.Complete(rst)
	})
}

func (g *GTCPConn) synack(complete bool) (rst bool, err error) {
	if g.ok() { // already setup
		return false, nil // open, err free
	}

	defer func() {
		// complete when either g is opened or complete is set
		if complete || !rst {
			g.complete(rst)
		}
	}()

	wq := new(waiter.Queue)
	// the passive-handshake (SYN) may not successful for a non-existent route (say, ipv6)
	if ep, err := g.req.CreateEndpoint(wq); err != nil {
		log.E("ns: tcp: forwarder: synack(complete? %t) src(%v) => dst(%v); err(%v)", complete, g.LocalAddr(), g.RemoteAddr(), err)
		// prevent potential half-open TCP connection leak.
		// hopefully doesn't break happy-eyeballs datatracker.ietf.org/doc/html/rfc8305#section-5
		// ie, apps that expect network-unreachable ICMP msgs instead of TCP RSTs?
		// TCP RST here is indistinguishable to an app from being firewalled.
		return true, e(err) // close, err
	} else {
		g.c.Store(gonet.NewTCPConn(wq, ep))
		keepalive(ep)
		return false, nil // open, err free
	}
}

func keepalive(ep tcpip.Endpoint) {
	if settings.GetDialerOpts().LowerKeepAlive {
		sockopt(ep, &defaultKeepAliveIdle, &defaultKeepAliveInterval, &defaultUserTimeout)
		ep.SetSockOptInt(tcpip.KeepaliveCountOption, defaultKeepAliveCount)
		ep.SocketOptions().SetKeepAlive(true)
	}
}

func sockopt(ep tcpip.Endpoint, opts ...tcpip.SettableSocketOption) {
	for _, opt := range opts {
		if opt != nil {
			_ = ep.SetSockOpt(opt)
		}
	}
}

// gonet conn local and remote addresses may be nil
// ref: github.com/tailscale/tailscale/blob/8c5c87be2/wgengine/netstack/netstack.go#L768-L775
// and: github.com/google/gvisor/blob/ffabadf0/pkg/tcpip/transport/tcp/endpoint.go#L2759
func (g *GTCPConn) LocalAddr() net.Addr {
	if c := g.conn(); c != nil {
		// client local addr is remote to the gonet adapter
		if addr := c.RemoteAddr(); addr != nil {
			return addr
		}
	}
	return net.TCPAddrFromAddrPort(g.src)
}

func (g *GTCPConn) RemoteAddr() net.Addr {
	if c := g.conn(); c != nil {
		// client remote addr is local to the gonet adapter
		if addr := c.LocalAddr(); addr != nil {
			return addr
		}
	}
	return net.TCPAddrFromAddrPort(g.dst)
}

func (g *GTCPConn) Write(data []byte) (int, error) {
	if c := g.conn(); c != nil {
		return c.Write(data)
	}
	return 0, netError(g, "tcp", "write", io.ErrClosedPipe)
}

func (g *GTCPConn) Read(data []byte) (int, error) {
	if c := g.conn(); c != nil {
		return c.Read(data)
	}
	return 0, netError(g, "tcp", "read", io.ErrNoProgress)
}

func (g *GTCPConn) CloseWrite() error {
	if c := g.conn(); c != nil {
		return c.CloseWrite()
	}
	return netError(g, "tcp", "close", net.ErrClosed)
}

func (g *GTCPConn) CloseRead() error {
	if c := g.conn(); c != nil {
		return c.CloseRead()
	}
	return netError(g, "tcp", "close", net.ErrClosed)
}

func (g *GTCPConn) SetDeadline(t time.Time) error {
	if c := g.conn(); c != nil {
		return c.SetDeadline(t)
	} else {
		return nil // no-op to confirm with netstack's gonet impl
	}
}

func (g *GTCPConn) SetReadDeadline(t time.Time) error {
	if c := g.conn(); c != nil {
		return c.SetReadDeadline(t)
	}
	return nil // no-op to confirm with netstack's gonet impl
}

func (g *GTCPConn) SetWriteDeadline(t time.Time) error {
	if c := g.conn(); c != nil {
		return c.SetWriteDeadline(t)
	}
	return nil // no-op to confirm with netstack's gonet impl
}

// Abort aborts the connection by sending a RST segment.
func (g *GTCPConn) Abort() {
	g.complete(true) // complete if needed
	core.Close(g.conn())
}

func (g *GTCPConn) Close() error {
	g.Abort()
	return nil // g.conn.Close always returns nil; see gonet.TCPConn.Close
}

// from: netstack gonet
func netError(c net.Conn, proto, op string, err error) *net.OpError {
	return &net.OpError{
		Op:     op,
		Net:    proto,
		Source: c.LocalAddr(),
		Addr:   c.RemoteAddr(),
		Err:    err,
	}
}
