// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package netstack

import (
	"net"
	"strconv"
	"time"

	"github.com/eycorsican/go-tun2socks/core"
	"gvisor.dev/gvisor/pkg/tcpip"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var _ core.UDPConn = (*GUDPConn)(nil)

type GUDPConnHandler interface {
	NewUDPConnection(conn *GUDPConn, src, dst *net.UDPAddr) bool
	HandleData(conn *GUDPConn, data []byte, addr *net.UDPAddr) error
}
type GUDPConn struct {
	core.UDPConn
	ep   tcpip.Endpoint
	gudp *gonet.UDPConn
}

func setupUdpHandler(s *stack.Stack, handler GUDPConnHandler) {
	forwarder := udp.NewForwarder(s, func(request *udp.ForwarderRequest) {
		id := request.ID()
		waitQueue := new(waiter.Queue)
		endpoint, errT := request.CreateEndpoint(waitQueue)
		if errT != nil {

			return
		}

		src := &net.UDPAddr{
			IP:   net.IP(id.RemoteAddress),
			Port: int(id.RemotePort),
		}

		dst := &net.UDPAddr{
			IP:   net.IP(id.LocalAddress),
			Port: int(id.LocalPort),
		}

		gc := &GUDPConn{
			ep:   endpoint,
			gudp: gonet.NewUDPConn(s, waitQueue, endpoint),
		}

		go func() {
			ok := handler.NewUDPConnection(gc, src, dst)

			if !ok {
				gc.gudp.Close()
				return
			}
			const maxUDPReqSize = 1600            // FIXME: MTU
			const readDeadline = 30 * time.Second // FIXME: Udp.Timeout
			q := make([]byte, maxUDPReqSize)
			for {
				gc.gudp.SetReadDeadline(time.Now().Add(readDeadline))
				if n, addr, err := gc.gudp.ReadFrom(q); err == nil {
					ipstr, portstr, _ := net.SplitHostPort(addr.String())
					port, _ := strconv.Atoi(portstr)
					udpaddr := &net.UDPAddr{
						IP:   net.ParseIP(ipstr),
						Port: port,
					}
					handler.HandleData(gc, q[:n], udpaddr)
				} else {
					break
				}
			}
		}()
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, forwarder.HandlePacket)
}

func (g *GUDPConn) LocalAddr() *net.UDPAddr {
	return g.gudp.LocalAddr().(*net.UDPAddr)
}

// ReceiveTo will be called when data arrives from TUN, and the received
// data should be sent to addr.
func (g *GUDPConn) ReceiveTo(_ []byte, _ *net.UDPAddr) error {
	return nil
	// no-op; forwarder.HandlePacket takes care of this
}

// WriteFrom writes data to TUN, addr will be set as source address of
// UDP packets that output to TUN.
func (g *GUDPConn) WriteFrom(data []byte, addr *net.UDPAddr) (int, error) {
	// nb: write-deadlines set by intra.udp
	return g.gudp.WriteTo(data, addr)
}

// Close closes the connection.
func (g *GUDPConn) Close() error {
	return g.gudp.Close()
}
