// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package netstack

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
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

// tcpFwdWatchdog is the max time a forwarder request may stay "in-flight"
// (uncompleted) before it is aborted (RST) to free up its slot. A stalled
// handler goroutine that never completes its ForwarderRequest leaks an
// in-flight slot; once maxInFlight slots are leaked, gvisor silently drops all
// new SYNs (ForwardMaxInFlightDrop) and egress TCP stalls with no error.
const tcpFwdWatchdog = 60 * time.Second

// retry connect when early connect (done when no happy eyeballs) fails?
const retryLateConnect = false

var (
	// defaults: github.com/google/gvisor/blob/fa49677e141db/pkg/tcpip/transport/tcp/protocol.go#L73
	// idle: 2h; count: 9; interval: 75s
	defaultKeepAliveIdle     = tcpip.KeepaliveIdleOption(10 * time.Minute)
	defaultKeepAliveInterval = tcpip.KeepaliveIntervalOption(5 * time.Second)
	defaultKeepAliveCount    = 4 // unacknowledged probes
	// github.com/tailscale/tailscale/blob/65fe0ba7b5/cmd/derper/derper.go#L75-L78
	// blog.cloudflare.com/when-tcp-sockets-refuse-to-die => Idle + (Interval * Count)
	usrTimeout = tcpip.TCPUserTimeoutOption(10*time.Minute + (4 * 5 * time.Second))
)

type GTCPConnHandler interface {
	GSpecConnHandler[*GTCPConn]
}

var _ core.TCPConn = (*GTCPConn)(nil)

type GTCPConn struct {
	o     string // owner
	stack *stack.Stack
	c     atomic.Pointer[gonet.TCPConn] // conn exposes TCP semantics atop endpoint
	src   netip.AddrPort                // local addr (remote addr in netstack)
	dst   netip.AddrPort                // remote addr (local addr in netstack)
	req   *tcp.ForwarderRequest         // egress request as a TCP state machine
	once  sync.Once
	// watchdog, when armed, aborts (RST) the request if it is not completed
	// within tcpFwdWatchdog, freeing the forwarder's in-flight slot. Stopped
	// in complete(); safe to leave unset for non-forwarder conns.
	watchdog *time.Timer
}

// s is the netstack to use for dialing (reads/writes).
// in is the incoming connection to netstack, s.
// to (src) is remote.
// from (dst) is local (to netstack, s).
// h is the handler that handles connection in into netstack, s, by
// dialing to from (dst) from to (src).
func InboundTCP(who string, s *stack.Stack, in net.Conn, to, from netip.AddrPort, h GTCPConnHandler) error {
	newgc := makeGTCPConn(who, s, nil /*not a forwarder req*/, to, from)

	// early syn/ack is okay if happy eyeballs isn't strictly required
	if !settings.HappyEyeballs.Load() {
		open, err := newgc.tryConnect()

		if log.Debug {
			logeif(err)("ns: tcp: %s: inbound: tryConnect err src(%v) => dst(%v); open? %t / retry? %t, err(%v)",
				newgc.o, to, from, open, retryLateConnect, err)
		}
		// TODO: call in a go routine if settings.SingleThreaded is set
		if !retryLateConnect && (err != nil || !open) {
			if err == nil {
				err = errMissingEp
			}
			h.Error(newgc, to, from, err) // error
			return err
		}
	}
	h.ReverseProxy(newgc, in, to, from)
	return nil
}

// OutboundTCP sets up a TCP forwarder h to handle TCP packets.
// If h is nil, s uses the (built-in) default TCP forwarding logic.
func OutboundTCP(who string, s *stack.Stack, h GTCPConnHandler) {
	if fwd := tcpForwarder(who, s, h); fwd != nil {
		s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	} else { // unset
		log.I("ns: tcp: %s: forwarder: nil handler; unsetting forwarder...", who)
		s.SetTransportProtocolHandler(tcp.ProtocolNumber, nil)
	}
}

// nic.deliverNetworkPacket -> no existing matching endpoints -> tcpForwarder.HandlePacket
// ref: github.com/google/gvisor/blob/e89e736f1/pkg/tcpip/adapters/gonet/gonet_test.go#L189
func tcpForwarder(who string, s *stack.Stack, h GTCPConnHandler) *tcp.Forwarder {
	if h == nil {
		return nil
	}

	return tcp.NewForwarder(s, rcvwnd, maxInFlight, func(req *tcp.ForwarderRequest) {
		if req == nil {
			log.E("ns: tcp: %s: forwarder: nil request", who)
			return
		}
		id := req.ID()
		// src 10.111.222.1:38312 / [fd66:f83a:c650::1]:15753
		src := remoteAddrPort(id)
		// dst 213.188.195.179:80
		dst := localAddrPort(id)

		// read/writes are routed using 5-tuple to the same conn (endpoint)
		// demuxer.handlePacket -> find matching endpoint -> queue-packet -> send/recv conn (ep)
		// ref: github.com/google/gvisor/blob/be6ffa7/pkg/tcpip/stack/transport_demuxer.go#L180
		gtcp := makeGTCPConn(who, s, req, src, dst)

		// arm an abort watchdog: gvisor frees the forwarder's in-flight slot
		// only when ForwarderRequest.Complete is called; if the handler
		// goroutine below stalls before establishing/completing the request
		// (onFlow, dials, etc.), the slot leaks and, once maxInFlight slots
		// are leaked, all new SYNs are silently dropped. Abort() completes the
		// request (RST) so the app retries; a late Establish/complete by the
		// handler is a no-op (sync.Once).
		gtcp.watchdog = time.AfterFunc(tcpFwdWatchdog, func() {
			log.W("ns: tcp: %s: forwarder: watchdog: aborting stale req src(%v) => dst(%v)",
				who, src, dst)
			gtcp.Abort()
		})

		// setup endpoint right away, so that netstack's internal state is consistent
		// in case there are multiple forwarders dispatching from the TUN device.
		if !settings.HappyEyeballs.Load() { // syn-ack before delivering to handler?
			opened, err := gtcp.tryConnect()

			if log.Debug {
				logeif(err)("ns: tcp: %s: forwarder: tryConnect err src(%v) => dst(%v); open? %t, err(%v)",
					who, src, dst, opened, err)
			}
			// TODO: call in a go routine if settings.SingleThreaded is set
			if !retryLateConnect && (err != nil || !opened) {
				h.Error(gtcp, src, dst, core.OneErr(err, errMissingEp)) // error
			} else { // gtcp may be connected
				h.Proxy(gtcp, src, dst)
			}
		} else {
			// call the handler in-line, blocking the netstack "processor",
			// however; handler must r/w to/from src/dst async after connect.
			h.Proxy(gtcp, src, dst)
		}
	})
}

func makeGTCPConn(who string, s *stack.Stack, req *tcp.ForwarderRequest, src, dst netip.AddrPort) *GTCPConn {
	// set sock-opts? github.com/xjasonlyu/tun2socks/blob/31468620e/core/tcp.go#L82
	return &GTCPConn{
		o:     who,
		stack: s,
		src:   src,
		dst:   dst,
		req:   req, // may be nil
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

	log.VV("ns: tcp: %s: forwarder: connect src(%v) => dst(%v); fin? %t",
		g.o, g.LocalAddr(), g.RemoteAddr(), rst)
	return !rst, err
}

func (g *GTCPConn) tryConnect() (open bool, err error) {
	rst, err := g.synack(false)

	log.VV("ns: tcp: %s: forwarder: proxy src(%v) => dst(%v); fin? %t", g.o, g.LocalAddr(), g.RemoteAddr(), rst)
	return !rst, err // open or closed
}

// complete must be called at least once, otherwise the conn counts towards
// maxInFlight and may cause silent tcp conn drops.
func (g *GTCPConn) complete(rst bool) {
	g.once.Do(func() {
		if g.watchdog != nil {
			g.watchdog.Stop() // request is done; disarm the abort timer
		}
		req := g.req
		log.D("ns: tcp: %s: forwarder: complete src(%v) => dst(%v); req? %t, rst? %t",
			g.o, g.LocalAddr(), g.RemoteAddr(), req != nil, rst)
		if req != nil {
			req.Complete(rst)
		}
	})
}

func (g *GTCPConn) synack(complete bool) (rst bool, err error) {
	if g.ok() { // already setup
		return false, nil // open, err free
	}

	defer func() {
		if rst {
			// always complete on error: free the forwarder's in-flight slot
			// (keyed by the 5-tuple) and send RST so the app's TCP stack
			// doesn't keep this half-open, stale, or conflicting on retry.
			g.complete(true)
		} else if complete {
			// complete when g is opened and caller requested completion.
			g.complete(false)
		}
		// when rst=false and complete=false, leave the request open
		// for the caller to complete later (e.g. happy-eyeballs).
	}()

	if g.req != nil { // egressing (process netstack's req from tun)
		wq := new(waiter.Queue)
		// the passive-handshake (SYN) may not successful for a non-existent route (say, ipv6)
		if ep, err := g.req.CreateEndpoint(wq); err != nil || ep == nil {
			log.E("ns: tcp: %s: connect: (outbound) synack(complete? %t / ep? %t) src(%v) => dst(%v); err(%v)",
				g.o, complete, ep != nil, g.LocalAddr(), g.RemoteAddr(), err)
			// prevent potential half-open TCP connection leak.
			// hopefully doesn't break happy-eyeballs datatracker.ietf.org/doc/html/rfc8305#section-5
			// TCP RST here is indistinguishable to an app from being firewalled.
			return true, e(err) // close, err
		} else {
			keepalive(ep)
			conn := gonet.NewTCPConn(wq, ep)
			g.c.Store(conn)
		}
	} else { // ingressing (process a conn into tun)
		if log.Verbose {
			log.V("ns: tcp: %s: dial: (inbound) creating endpoint for %v => %v", g.o, g.LocalAddr(), g.RemoteAddr())
		}
		src, proto := addrport2nsaddr(g.dst) // remote addr is local addr in netstack
		dst, _ := addrport2nsaddr(g.src)     // local addr is remote addr in netstack
		bg := context.Background()
		if conn, err := gonet.DialTCPWithBind(bg, g.stack, src, dst, proto); err != nil {
			log.E("ns: tcp: %s: dial: (inbound) synack(complete? %t) src(%v) => dst(%v); err(%v)",
				g.o, complete, g.LocalAddr(), g.RemoteAddr(), err)
			return true, err // close, err
		} else {
			g.c.Store(conn)
		}
	}

	return false, nil // open, err free
}

func keepalive(ep tcpip.Endpoint) {
	if settings.GetDialerOpts().LowerKeepAlive {
		// github.com/tailscale/tailscale/issues/4522 (low keepalive)
		// github.com/tailscale/tailscale/pull/6147 (high keepalive)
		// github.com/tailscale/tailscale/issues/6148 (other changes)
		sockopt(ep, &defaultKeepAliveIdle, &defaultKeepAliveInterval, &usrTimeout)
		ep.SetSockOptInt(tcpip.KeepaliveCountOption, defaultKeepAliveCount)
		// github.com/tailscale/tailscale/commit/1aa75b1c9ea2
		ep.SocketOptions().SetKeepAlive(true) // applies netstack defaults
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
	return 0, netError(g, "tcp", g.o+":write", io.ErrClosedPipe)
}

func (g *GTCPConn) Read(data []byte) (int, error) {
	if c := g.conn(); c != nil {
		return c.Read(data)
	}
	return 0, netError(g, "tcp", g.o+":read", io.ErrNoProgress)
}

func (g *GTCPConn) CloseWrite() error {
	if c := g.conn(); c != nil {
		return c.CloseWrite()
	}
	return netError(g, "tcp", g.o+":close", net.ErrClosed)
}

func (g *GTCPConn) CloseRead() error {
	if c := g.conn(); c != nil {
		return c.CloseRead()
	}
	return netError(g, "tcp", g.o+":close", net.ErrClosed)
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
	go core.Close(g.conn())
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
