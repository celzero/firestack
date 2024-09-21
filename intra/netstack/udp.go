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

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var (
	errMissingEp   = errors.New("not connected to any endpoint")
	errFilteredOut = errors.New("no eif; filtered out")
)

type DemuxerFn func(in net.Conn, to netip.AddrPort) error

type GUDPConnHandler interface {
	GSpecConnHandler[*GUDPConn]
	GMuxConnHandler[*GUDPConn]
}

var _ core.UDPConn = (*GUDPConn)(nil)

type GUDPConn struct {
	stack *stack.Stack

	// conn exposes UDP semantics atop endpoint
	c *core.Volatile[*gonet.UDPConn]
	// local addr (remote addr in netstack)
	// ex: 10.111.222.1:20716; same as endpoint.GetRemoteAddress
	src netip.AddrPort
	// remote addr (local addr in netstack)
	// ex: 10.111.222.3:53; same as endpoint.GetLocalAddress
	dst netip.AddrPort

	req *udp.ForwarderRequest // egress request as UDP

	eim bool // endpoint is muxed
	eif bool // endpoint is transparent
}

// ref: github.com/google/gvisor/blob/e89e736f1/pkg/tcpip/adapters/gonet/gonet_test.go#L373
func makeGUDPConn(s *stack.Stack, r *udp.ForwarderRequest, src, dst netip.AddrPort) *GUDPConn {
	return &GUDPConn{
		stack: s,
		c:     core.NewZeroVolatile[*gonet.UDPConn](),
		src:   src,
		dst:   dst,
		req:   r,
		eim:   settings.EndpointIndependentMapping.Load(),
		eif:   settings.EndpointIndependentFiltering.Load(),
	}
}

func OutboundUDP(s *stack.Stack, h GUDPConnHandler) {
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder(s, h).HandlePacket)
}

func InboundUDP(s *stack.Stack, in net.Conn, to, from netip.AddrPort, h GUDPConnHandler) error {
	newgc := makeGUDPConn(s, nil /*not a forwarder req*/, to, from)
	if !settings.SingleThreaded.Load() {
		if err := newgc.Establish(); err != nil {
			log.E("ns: udp: inbound: dial: %v; src(%v) dst(%v)", err, to, from)
			go h.Error(newgc, to, from, err)
			return err
		}
	}
	go h.ReverseProxy(newgc, in, to, from)
	return nil
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

		// owner           app               tun                ns                h
		// repr            socket            packet             endpoint          socket
		// type            udp               fd                 gudpconn          core.minconn
		//
		// (src, dst)      :1111, :53        :1111, :53         :53, :1111        :9999, :53
		//
		// write           :1111 => :53      :1111, :53         :53 => :1111      :9999 => :53
		//                                                                 \      /
		//                                                                  \    /
		// (pipe)                                                            \  /
		//                                                                   / \
		//                                                                  /   \
		//                                                                 /     \
		// read            :1111 <= :53     :1111, :53         :53 <= :1111     :9999 <= :53
		id := req.ID()
		// src 10.111.222.1:20716; same as endpoint.GetRemoteAddress
		src := remoteAddrPort(id)
		// dst 10.111.222.3:53; same as endpoint.GetLocalAddress
		// but it may not always be the true dst (for now it is),
		// especially if the resulting udp-conn is setup to handle
		// multiple dst in the unconnected udp case.
		dst := localAddrPort(id)

		gc := makeGUDPConn(s, req, src, dst)
		// setup to recv right away, so that netstack's internal state is consistent
		// in case there are multiple forwarders dispatching from the TUN device.
		if !settings.SingleThreaded.Load() {
			if err := gc.Establish(); err != nil {
				log.E("ns: udp: forwarder: connect: %v; src(%v) dst(%v)", err, src, dst)
				go h.Error(gc, src, dst, err)
				return
			}
		}

		demux := func(ingress net.Conn, newdst netip.AddrPort) error {
			if newdst.Compare(dst) == 0 {
				log.D("ns: udp: demuxer: no-op; src(%v) same as dst(%v)", src, newdst)
				return nil
			}
			if !gc.eif {
				return errFilteredOut
			}
			return InboundUDP(s, ingress, src, newdst, h)
		}

		// proxy in a separate gorountine; return immediately
		// why? netstack/dispatcher.go:newReadvDispatcher
		if gc.eim {
			go h.ProxyMux(gc, src, dst, demux)
		} else {
			go h.Proxy(gc, src, dst)
		}
	})
}

func (g *GUDPConn) ok() bool {
	return g.conn() != nil
}

func (g *GUDPConn) conn() *gonet.UDPConn {
	return g.c.Load()
}

func (g *GUDPConn) StatefulTeardown() (fin bool) {
	_ = g.Establish() // establish circuit then teardown
	_ = g.Close()     // then shutdown
	return true       // always fin
}

func (g *GUDPConn) Establish() error {
	if g.ok() { // already setup
		return nil
	}

	if g.req == nil { // ingressing (process a conn into tun)
		src, proto := addrport2nsaddr(g.dst) // remote addr is local addr in netstack
		dst, _ := addrport2nsaddr(g.src)     // local addr is remote addr in netstack
		// ingress socket w/ gonet.DialUDP
		if conn, err := gonet.DialUDP(g.stack, &src, &dst, proto); err != nil {
			log.E("ns: udp: dial: endpoint for %v => %v; err(%v)", g.src, g.dst, err)
			return err
		} else {
			g.c.Store(conn)
		}
	} else { // egressing (process netstack's req from tun)
		wq := new(waiter.Queue)
		if ep, err := g.req.CreateEndpoint(wq); err != nil || ep == nil {
			// ex: CONNECT endpoint for [fd66:f83a:c650::1]:15753 => [fd66:f83a:c650::3]:53; err(no route to host)
			log.E("ns: udp: connect: endpoint(ok? %t) for %v => %v; err(%v)", ep != nil, g.src, g.dst, err)
			return e(err)
		} else {
			g.c.Store(gonet.NewUDPConn(wq, ep))
		}
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
	if c := g.conn(); c != nil {
		_ = c.Close()
	}
	return nil
}
