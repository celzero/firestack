// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package netstack

import (
	"net"
	"time"

	"github.com/celzero/firestack/intra/log"
	"github.com/eycorsican/go-tun2socks/core"
	"gvisor.dev/gvisor/pkg/tcpip"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const readDeadline = 30 * time.Second // FIXME: Udp.Timeout
const K64 = 64 * 1024                 // 64K bytes

var _ core.UDPConn = (*GUDPConn)(nil)

type GUDPConnHandler interface {
	OnNewConn(conn *GUDPConn, src, dst *net.UDPAddr) bool
	HandleData(conn *GUDPConn, data []byte, addr *net.UDPAddr) error
}
type GUDPConn struct {
	core.UDPConn
	ep   tcpip.Endpoint
	gudp *gonet.UDPConn
	src  *net.UDPAddr
	dst  *net.UDPAddr
}

// ref: github.com/google/gvisor/blob/e89e736f1/pkg/tcpip/adapters/gonet/gonet_test.go#L373
func NewGUDPConn(s *stack.Stack, r *udp.ForwarderRequest, src, dst *net.UDPAddr) *GUDPConn {
	waitQueue := new(waiter.Queue)
	// use gonet.DialUDP instead?
	if endpoint, err := r.CreateEndpoint(waitQueue); err != nil {
		log.Errorf("ns.udp.forwarder: mk endpoint; err(%v)", err)
		return nil
	} else {
		return &GUDPConn{
			ep:   endpoint,
			gudp: gonet.NewUDPConn(s, waitQueue, endpoint),
			src:  src,
			dst:  dst,
		}
	}
}

func setupUdpHandler(s *stack.Stack, ep stack.LinkEndpoint, h GUDPConnHandler) {
	s.SetTransportProtocolHandler(udp.ProtocolNumber, NewUDPForwarder(s, h, ep.MTU()).HandlePacket)
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
func NewUDPForwarder(s *stack.Stack, h GUDPConnHandler, mtu uint32) *udp.Forwarder {
	return udp.NewForwarder(s, func(request *udp.ForwarderRequest) {
		id := request.ID()

		// src 10.111.222.1:20716; same as endpoint.GetRemoteAddress
		src := remoteUDPAddr(id)
		// dst 10.111.222.3:53; same as endpoint.GetLocalAddress
		// but it may not always be the true dst (for now it is),
		// especially if the resulting udp-conn is setup to handle
		// multiple dst in the unconnected udp case.
		dst := localUDPAddr(id)

		gc := NewGUDPConn(s, request, src, dst)

		if gc == nil {
			return
		}

		// TODO: on stack.close, mop these goroutines up; just too many of them
		// hanging around with failing dns queries (esp with happy-eyeballs)
		go func() {
			log.Debugf("ns.udp.forwarder: NEW src(%v) => dst(%v)", src, dst)

			ok := h.OnNewConn(gc, src, dst)
			if !ok {
				return
			}

			// assign a big enough buffer since netstack does assemble fragmented packets
			// which could go as big as max-packet-size (65K?)
			// also: github.com/cloudflare/slirpnetstack/blob/41e49c3294/proxy.go#L73
			// and: github.com/cloudflare/slirpnetstack/blob/41e49c3294/proxy.go#L114
			// max: github.com/google/gvisor/blob/be6ffa78/pkg/tcpip/transport/udp/protocol.go#L43
			// though, we never expect to exceed mtu, so we can use a smaller buffer?
			q := make([]byte, K64)
			for {
				gc.gudp.SetDeadline(time.Now().Add(readDeadline))
				// addr is gc.gudp.RemoteAddr() ie gc.LocalAddr()
				// github.com/google/gvisor/blob/be6ffa78e/pkg/tcpip/transport/udp/endpoint.go#L298
				if n, addr, err := gc.gudp.ReadFrom(q); err == nil {
					data := append([]byte{}, q[:n]...)
					// who(10.111.222.3:17711)
					// dst(l:10.111.222.3:17711 / r:10.111.222.1:53)
					who := addr.(*net.UDPAddr)
					l := gc.LocalAddr()
					r := gc.RemoteAddr()
					log.Debugf("ns.udp.forwarder: DATA src(%v) => dst(l:%v / r:%v)", who, l, r)
					if errh := h.HandleData(gc, data[:n], r); errh != nil {
						break
					}
				} else {
					log.Debugf("ns.udp.forwarder: DONE err(%v)", err)
					break
				}
			}
		}()
	})
}

func (g *GUDPConn) LocalAddr() *net.UDPAddr {
	if g.gudp != nil && g.gudp.RemoteAddr() != nil {
		if addr, ok := g.gudp.RemoteAddr().(*net.UDPAddr); ok {
			return addr
		}
	}
	return g.src
}

func (g *GUDPConn) RemoteAddr() *net.UDPAddr {
	if g.gudp != nil && g.gudp.LocalAddr() != nil {
		if addr, ok := g.gudp.LocalAddr().(*net.UDPAddr); ok {
			return addr
		}
	}
	return g.dst
}

// ReceiveTo will be called when data arrives from TUN, and the received
// data should be sent to addr.
func (g *GUDPConn) ReceiveTo(_ []byte, addr *net.UDPAddr) error {
	// no-op; forwarder.HandlePacket takes care of this
	log.Warnf("ns.udp.rcv: addr(%v); no-op", addr)
	return nil
}

// WriteFrom writes data to TUN, addr will be set as source address of
// UDP packets that output to TUN.
func (g *GUDPConn) WriteFrom(data []byte, addr *net.UDPAddr) (int, error) {
	// nb: write-deadlines set by intra.udp
	// addr: 10.111.222.3:17711; g.LocalAddr(g.udp.remote): 10.111.222.3:17711; g.RemoteAddr(g.udp.local): 10.111.222.1:53
	// ep(state 3 / info &{2048 17 {53 10.111.222.3 17711 10.111.222.1} 1 10.111.222.3 1} / stats &{{{1}} {{0}} {{{0}} {{0}} {{0}} {{0}}} {{{0}} {{0}} {{0}}} {{{0}} {{0}}} {{{0}} {{0}} {{0}}}})
	// 3: status:datagram-connected / {2048=>proto, 17=>transport, {53=>local-port localip 17711=>remote-port remoteip}=>endpoint-id, 1=>bind-nic-id, ip=>bind-addr, 1=>registered-nic-id}
	log.Debugf("ns.udp.writeFrom: ep(state %v / info %v / stats %v)", g.ep.State(), g.ep.Info(), g.ep.Stats())
	return g.gudp.Write(data)
}

// Close closes the connection.
func (g *GUDPConn) Close() error {
	g.ep.Close()
	return g.gudp.Close()
}
