// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package netstack

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"gvisor.dev/gvisor/pkg/tcpip"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const readDeadline = 30 * time.Second // FIXME: Udp.Timeout

var (
	ErrNoEndpoint = errors.New("udp not connected to any endpoint")
)

type GUDPConnHandler interface {
	OnNewConn(conn *GUDPConn, src, dst *net.UDPAddr)
	HandleData(conn *GUDPConn, data []byte, addr net.Addr) error
	End() error
}

var _ core.UDPConn = (*GUDPConn)(nil)

type GUDPConn struct {
	*gonet.UDPConn
	ep    tcpip.Endpoint
	src   *net.UDPAddr
	dst   *net.UDPAddr
	wg    *sync.WaitGroup // waits for endpoint to be ready
	stack *stack.Stack
	req   *udp.ForwarderRequest
}

// ref: github.com/google/gvisor/blob/e89e736f1/pkg/tcpip/adapters/gonet/gonet_test.go#L373
func MakeGUDPConn(s *stack.Stack, r *udp.ForwarderRequest, src, dst *net.UDPAddr) *GUDPConn {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	return &GUDPConn{
		ep:    nil,
		src:   src,
		dst:   dst,
		wg:    wg,
		stack: s,
		req:   r,
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
		id := request.ID()

		// src 10.111.222.1:20716; same as endpoint.GetRemoteAddress
		src := remoteUDPAddr(id)
		// dst 10.111.222.3:53; same as endpoint.GetLocalAddress
		// but it may not always be the true dst (for now it is),
		// especially if the resulting udp-conn is setup to handle
		// multiple dst in the unconnected udp case.
		dst := localUDPAddr(id)

		gc := MakeGUDPConn(s, request, src, dst)

		h.OnNewConn(gc, src, dst)

		// TODO: on stack.close, mop these goroutines up; just too many of them
		// hanging around with failing dns queries (esp with happy-eyeballs)
		if gc.ok() {
			go loop(h, gc, src, dst)
		} // else: connection refused / failed
	})
}

func loop(h GUDPConnHandler, gc *GUDPConn, src, dst *net.UDPAddr) {
	log.V("ns.udp.forwarder: NEW src(%v) => dst(%v)", src, dst)

	// assign a big enough buffer since netstack does assemble fragmented packets
	// which could go as big as max-packet-size (65K?)
	// also: github.com/cloudflare/slirpnetstack/blob/41e49c3294/proxy.go#L73
	// and: github.com/cloudflare/slirpnetstack/blob/41e49c3294/proxy.go#L114
	// max: github.com/google/gvisor/blob/be6ffa78/pkg/tcpip/transport/udp/protocol.go#L43
	// though, we never expect to exceed mtu, so we can use a smaller buffer?
	// TODO: MTU
	bptr := core.Alloc()
	q := *bptr
	q = q[:cap(q)]
	defer func() {
		*bptr = q
		core.Recycle(bptr)
	}()
	for {
		gc.SetDeadline(time.Now().Add(readDeadline))
		// addr is gc.RemoteAddr() ie gc.LocalAddr()
		// github.com/google/gvisor/blob/be6ffa78e/pkg/tcpip/transport/udp/endpoint.go#L298
		if n, addr, err := gc.ReadFrom(q[:]); err == nil {
			// who(10.111.222.3:17711)
			// dst(l:10.111.222.3:17711 / r:10.111.222.1:53)
			who := addr.(*net.UDPAddr)
			l := gc.LocalAddr()
			r := gc.RemoteAddr()
			if who.String() != l.String() {
				log.W("ns.udp.forwarder: MISMATCH expected-src(%v) => actual(l:%v)", who, l)
			}

			log.V("ns.udp.forwarder: DATA src(%v) => dst(l:%v / r:%v)", who, l, r)
			if errh := h.HandleData(gc, q[:n], r); errh != nil {
				gc.Close()
				break
			}
		} else {
			// TODO: handle temporary errors?
			log.D("ns.udp.forwarder: DONE err(%v)", err)
			// leave gc open?
			break
		}
	}
}

func (g *GUDPConn) Ready() bool {
	g.wg.Wait()
	return g.ok()
}

func (g *GUDPConn) ok() bool {
	return g.ep != nil && g.UDPConn != nil
}

func (g *GUDPConn) StatefulTeardown() (fin bool) {
	if g.ok() {
		return g.Close() == nil
	}

	g.Connect(false)        // establish circuit
	return g.Close() == nil // then fin
}

func (g *GUDPConn) Connect(fin bool) tcpip.Error {
	defer g.wg.Done()

	if fin {
		return &tcpip.ErrHostUnreachable{}
	}

	wq := new(waiter.Queue)
	// use gonet.DialUDP instead?
	if endpoint, err := g.req.CreateEndpoint(wq); err != nil {
		// ex: CONNECT endpoint for [fd66:f83a:c650::1]:15753 => [fd66:f83a:c650::3]:53; err(no route to host)
		log.E("ns.udp.forwarder: CONNECT endpoint for %v => %v; err(%v)", g.src, g.dst, err)
		return err
	} else {
		g.ep = endpoint
		g.UDPConn = gonet.NewUDPConn(g.stack, wq, endpoint)
	}
	return nil
}

func (g *GUDPConn) LocalAddr() (addr net.Addr) {
	if g.ok() {
		addr = g.UDPConn.RemoteAddr()
	}
	if addr == nil { // remoteaddr may be nil, even if g.ok()
		addr = g.src
	}
	return
}

func (g *GUDPConn) RemoteAddr() (addr net.Addr) {
	if g.ok() {
		addr = g.UDPConn.LocalAddr()
	}
	if addr == nil { // localaddr may be nil, even if g.ok()
		addr = g.dst
	}
	return
}

// ReceiveTo will be called when data arrives from TUN, and the received
// data should be sent to addr.
func (g *GUDPConn) ReceiveTo(_ []byte, addr *net.UDPAddr) error {
	// no-op; forwarder.HandlePacket takes care of this
	log.W("ns.udp.rcv: addr(%v); no-op", addr)
	return nil
}

// WriteFrom writes data to TUN, addr will be set as source address of
// UDP packets that output to TUN.
func (g *GUDPConn) WriteFrom(data []byte, addr *net.UDPAddr) (int, error) {
	if !g.ok() {
		return 0, ErrNoEndpoint
	}
	// nb: write-deadlines set by intra.udp
	// addr: 10.111.222.3:17711; g.LocalAddr(g.udp.remote): 10.111.222.3:17711; g.RemoteAddr(g.udp.local): 10.111.222.1:53
	// ep(state 3 / info &{2048 17 {53 10.111.222.3 17711 10.111.222.1} 1 10.111.222.3 1} / stats &{{{1}} {{0}} {{{0}} {{0}} {{0}} {{0}}} {{{0}} {{0}} {{0}}} {{{0}} {{0}}} {{{0}} {{0}} {{0}}}})
	// 3: status:datagram-connected / {2048=>proto, 17=>transport, {53=>local-port localip 17711=>remote-port remoteip}=>endpoint-id, 1=>bind-nic-id, ip=>bind-addr, 1=>registered-nic-id}
	// g.ep may be nil: log.V("ns.udp.writeFrom: from(%v) / ep(state %v / info %v / stats %v)", addr, g.ep.State(), g.ep.Info(), g.ep.Stats())
	log.V("ns.udp.writeFrom: from(%v)", addr)
	return g.UDPConn.Write(data)
}

func (g *GUDPConn) Write(data []byte) (int, error) {
	if !g.ok() {
		return 0, ErrNoEndpoint
	}
	return g.UDPConn.Write(data)
}

func (g *GUDPConn) Read(data []byte) (int, error) {
	if !g.ok() {
		return 0, ErrNoEndpoint
	}
	return g.UDPConn.Read(data)
}

// Close closes the connection.
func (g *GUDPConn) Close() error {
	ep := g.ep
	c := g.UDPConn
	if ep != nil {
		ep.Abort()
	}
	if c != nil {
		c.SetDeadline(time.Now().Add(-1))
		return c.Close()
	}
	return nil
}
