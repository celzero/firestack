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

	"github.com/celzero/firestack/intra/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// ref: github.com/tailscale/tailscale/blob/cfb5bd0559/wgengine/netstack/netstack.go#L236-L237
const rcvwnd = 0
const maxInFlight = 16

type GTCPConnHandler interface {
	OnNewConn(conn *GTCPConn, src, dst *net.TCPAddr)
}

func setupTcpHandler(s *stack.Stack, h GTCPConnHandler) {
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, NewTCPForwarder(s, h).HandlePacket)
}

func NewTCPForwarder(s *stack.Stack, h GTCPConnHandler) *tcp.Forwarder {
	return tcp.NewForwarder(s, rcvwnd, maxInFlight, func(request *tcp.ForwarderRequest) {
		id := request.ID()
		// src 10.111.222.1:38312
		src := remoteTCPAddr(id)
		// dst 213.188.195.179:80
		dst := localTCPAddr(id)
		waitQueue := new(waiter.Queue)
		endpoint, err := request.CreateEndpoint(waitQueue)
		if err != nil {
			log.Errorf("ns.tcp.forwarder: data src(%v) => dst(%v); err(%v)", src, dst, err)
			// prevent potential half-open TCP connection leak.
			request.Complete(true)
			return
		}

		request.Complete(false)
		log.Debugf("ns.tcp.forwarder: data src(%v) => dst(%v)", src, dst)

		go h.OnNewConn(NewGTCPConn(waitQueue, endpoint), src, dst)
	})
}

type GTCPConn struct {
	*gonet.TCPConn
	ep tcpip.Endpoint
}

func NewGTCPConn(wq *waiter.Queue, ep tcpip.Endpoint) *GTCPConn {
	return &GTCPConn{gonet.NewTCPConn(wq, ep), ep}
}

func (g *GTCPConn) LocalAddr() net.Addr {
	// client local addr is remote to the gonet adapter
	return g.TCPConn.RemoteAddr()
}

func (g *GTCPConn) RemoteAddr() net.Addr {
	// client remote addr is local to the gonet adapter
	return g.TCPConn.LocalAddr()
}

// Sent will be called when sent data has been acknowledged by peer.
func (tcp *GTCPConn) Sent(len uint16) error {
	// no-op
	return errors.New("unimpl for gtcpconn")
}

// Receive will be called when data arrives from TUN.
func (tcp *GTCPConn) Receive(data []byte) error {
	// no-op
	return errors.New("unimpl for gtcpconn")
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
	tcp.TCPConn.Close()
}

func (g GTCPConn) Close() error {
	g.ep.Close()
	g.TCPConn.SetDeadline(time.Now().Add(-1))
	return g.TCPConn.Close()
}
