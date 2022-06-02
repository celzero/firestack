// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package netstack

import (
	"fmt"
	"net"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type GTCPConnHandler interface {
	NewTCPConnection(conn GTCPConn, src, dst net.TCPAddr)
}

func setupTcpHandler(s *stack.Stack, handler GTCPConnHandler) {
	forwarder := tcp.NewForwarder(s, 0, 1024, func(request *tcp.ForwarderRequest) {
		id := request.ID()
		waitQueue := new(waiter.Queue)
		endpoint, errT := request.CreateEndpoint(waitQueue)
		if errT != nil {
			fmt.Errorf("failed to create TCP connection")
			// prevent potential half-open TCP connection leak.
			request.Complete(true)
			return
		}
		request.Complete(false)
		src := net.TCPAddr{
			IP:   net.IP(id.RemoteAddress),
			Port: int(id.RemotePort),
		}

		dst := net.TCPAddr{
			IP:   net.IP(id.LocalAddress),
			Port: int(id.LocalPort),
		}

		go handler.NewTCPConnection(GTCPConn{endpoint, gonet.NewTCPConn(waitQueue, endpoint)}, src, dst)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, forwarder.HandlePacket)
}

type GTCPConn struct {
	ep tcpip.Endpoint
	*gonet.TCPConn
}

func (g GTCPConn) Close() error {
	g.ep.Close()
	g.TCPConn.SetDeadline(time.Now().Add(-1))
	return g.TCPConn.Close()
}
