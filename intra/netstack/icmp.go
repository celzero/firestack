// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package netstack

import (
	"fmt"
	"net"

	"github.com/celzero/firestack/intra/log"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
)

type Pong func(reply []byte) error
type GICMPHandler interface {
	// Multi ping handler
	Ping(source *net.UDPAddr, destination *net.UDPAddr, msg []byte, pong Pong) bool
	// Single ping handler
	PingOnce(source *net.UDPAddr, destination *net.UDPAddr, msg []byte) bool
	CloseConns([]string) []string
	End() error
}

// ref: github.com/SagerNet/LibSagerNetCore/blob/632d6b892e/gvisor/icmp.go
func setupIcmpHandler(nstk *stack.Stack, ep stack.LinkEndpoint, handler GICMPHandler) {
	// remove default handlers
	nstk.SetTransportProtocolHandler(icmp.ProtocolNumber4, nil)
	nstk.SetTransportProtocolHandler(icmp.ProtocolNumber6, nil)

	if handler == nil {
		log.E("icmp: no handler")
		return
	}

	// ICMPv4
	nstk.SetTransportProtocolHandler(icmp.ProtocolNumber4, func(id stack.TransportEndpointID, packet stack.PacketBufferPtr) bool {
		log.V("icmp: v4 packet? %v", packet)

		if !ep.IsAttached() {
			log.D("icmp: endpoint not attached")
			return false
		}

		// ref: github.com/google/gvisor/blob/acf460d0d735/pkg/tcpip/stack/conntrack.go#L933
		l4bytes := packet.TransportHeader().Slice()
		icmpin := header.ICMPv4(l4bytes)
		if icmpin.Type() != header.ICMPv4Echo {
			// netstack handles other msgs except echo / ping
			log.D("icmp: v4 type %v passthrough", icmpin.Type())
			return false
		}

		src := remoteUDPAddr(id)
		dst := localUDPAddr(id)

		log.D("icmp: v4 type %v src %v dst %v", icmpin.Type(), src, dst)

		b := make([]byte, 0, ep.MTU())
		din8 := buffer.MakeWithData(b)
		din8.Append(packet.NetworkHeader().View())
		l4 := packet.TransportHeader().View()
		if l4.Size() > 8 {
			l4.CapLength(8)
		}
		din8.Append(l4)
		req := din8.Flatten()

		// github.com/google/gvisor/blob/9b4a7aa00/pkg/tcpip/network/ipv6/icmp.go#L1180
		r := make([]byte, 0, ep.MTU())
		din := buffer.MakeWithData(r)
		din.Append(packet.TransportHeader().View())
		l7 := packet.Data().ToBuffer()
		din.Merge(&l7)
		data := din.Flatten()
		datalen := len(data)

		l3 := packet.NetworkHeader().View()
		log.D("icmp: v4 type %v/%v sz [%v]; src(%v) -> dst(%v)", icmpin.Type(), icmpin.Code(), datalen, src, dst)
		if !handler.Ping(src, dst, data, func(reply []byte) error {
			log.V("icmp: v4 reply %v", reply)
			// sendICMP: github.com/google/gvisor/blob/8035cf9ed/pkg/tcpip/transport/tcp/testing/context/context.go#L404
			// parseICMP: github.com/google/gvisor/blob/8035cf9ed/pkg/tcpip/header/parse/parse.go#L194
			// makeICMP: github.com/google/gvisor/blob/8035cf9ed/pkg/tcpip/tests/integration/iptables_test.go#L2100
			// Allocate a buffer data and headers.
			icmpout := header.ICMPv4(reply)
			if icmpout.Type() == header.ICMPv4DstUnreachable {
				const ICMPv4HeaderSize = 4
				d := make([]byte, len(req)+header.ICMPv4MinimumErrorPayloadSize)
				icmpunreach := header.ICMPv4(d)
				copy(icmpunreach[:ICMPv4HeaderSize], reply)
				copy(icmpunreach[header.ICMPv4MinimumErrorPayloadSize:], req)
				log.D("icmp: v4 unreachable %v/%v sz[%d] from %v <- %v", icmpunreach.Type(), icmpunreach.Code(), len(icmpunreach), src, dst)
				icmpout = icmpunreach
			}

			x := make([]byte, 0, ep.MTU())
			res := buffer.MakeWithData(x)
			if len(icmpout) != datalen {
				ip := header.IPv4(l3.AsSlice())
				l3len := ip.TotalLength()
				ip.SetTotalLength(uint16(l3.Size() + len(reply)))
				ip.SetChecksum(^checksum.Combine(^ip.Checksum(), checksum.Combine(ip.TotalLength(), ^l3len)))
				payloadview := buffer.NewViewWithData(ip.Payload())
				res.Append(payloadview)
			} else {
				res.Append(l3)
			}
			icmpoutview := buffer.NewViewWithData(icmpout.Payload())
			res.Append(icmpoutview)

			respkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: res})
			defer respkt.DecRef()

			log.D("icmp: v4 response: type %v/%v sz[%d] from %v <- %v", icmpout.Type(), icmpout.Code(), res.Size(), src, dst)

			var pout stack.PacketBufferList
			pout.PushBack(respkt)
			if _, err := ep.WritePackets(pout); err != nil {
				log.E("icmp: v4 err writing upstream res [%v <- %v] to tun %v", src, dst, err)
				return fmt.Errorf("icmp: v4 err writing upstream res to tun: %v", err)
			}

			if icmpout.Type() == header.ICMPv4DstUnreachable {
				return unix.ENETUNREACH
			}
			// inform the client that it can continue to listen for more packets
			return nil
		}) {
			// if unhandled by the handler, send a reply ourselves
			icmpin.SetType(header.ICMPv4EchoReply)
			icmpin.SetChecksum(0)
			icmpin.SetChecksum(header.ICMPv4Checksum(icmpin, packet.Data().Checksum()))
			var pout stack.PacketBufferList
			pout.PushBack(packet)
			_, err := ep.WritePackets(pout)
			if err != nil {
				log.E("icmp: v4 err writing default reply to tun: %v", err)
				return false
			}
		}

		return true
	})

	// ICMPv6
	nstk.SetTransportProtocolHandler(icmp.ProtocolNumber6, func(id stack.TransportEndpointID, packet stack.PacketBufferPtr) bool {
		log.V("icmp: v6 packet? %v", packet)

		if !ep.IsAttached() {
			log.D("icmp: endpoint not attached")
			return false
		}

		l4bytes := packet.TransportHeader().Slice()
		icmpin := header.ICMPv6(l4bytes)
		if icmpin.Type() != header.ICMPv6EchoRequest {
			log.D("icmp: v6 type %v/%v passthrough", icmpin.Type(), icmpin.Code())
			// netstack handles other msgs except echo / ping
			return false
		}

		src := remoteUDPAddr(id)
		dst := localUDPAddr(id)

		log.D("icmp: v6 type %v src %v dst %v", icmpin.Type(), src, dst)

		b := make([]byte, 0, ep.MTU())
		din8 := buffer.MakeWithData(b)
		din8.Append(packet.NetworkHeader().View())
		l4 := packet.TransportHeader().View()
		if l4.Size() > 8 {
			l4.CapLength(8)
		}
		din8.Append(l4)
		req := din8.Flatten()

		// github.com/google/gvisor/blob/9b4a7aa00/pkg/tcpip/network/ipv6/icmp.go#L1180
		r := make([]byte, 0, ep.MTU())
		din := buffer.MakeWithData(r)
		din.Append(packet.TransportHeader().View())
		l7 := packet.Data().ToBuffer()
		din.Merge(&l7)
		data := din.Flatten()
		dlen := len(data)

		l3 := packet.NetworkHeader().View()
		log.D("icmp: v6 type %v/%v sz[%d] from %v -> %v", icmpin.Type(), icmpin.Code(), dlen, src, dst)
		if !handler.Ping(src, dst, data, func(reply []byte) error {
			log.V("icmp: v4 reply %v", reply)

			icmpout := header.ICMPv6(reply)
			if icmpout.Type() == header.ICMPv6DstUnreachable {
				d := make([]byte, len(req)+header.ICMPv6DstUnreachableMinimumSize)
				icmpunreach := header.ICMPv6(d)
				copy(icmpunreach[:header.ICMPv6HeaderSize], reply)
				copy(icmpunreach[header.ICMPv6DstUnreachableMinimumSize:], req)
				log.D("icmp: v6 unreachable %v/%v sz[%d] from %v <- %v", icmpunreach.Type(), icmpunreach.Code(), len(icmpunreach), src, dst)
				icmpout = icmpunreach
			}

			x := make([]byte, 0, ep.MTU())
			res := buffer.MakeWithData(x)
			if len(icmpout) != dlen {
				ip := header.IPv6(l3.AsSlice())
				ip.SetPayloadLength(uint16(len(icmpout)))
				payloadview := buffer.NewViewWithData(ip.Payload())
				res.Append(payloadview)
			} else {
				res.Append(l3)
			}
			icmpoutview := buffer.NewViewWithData(icmpout)
			res.Append(icmpoutview)

			icmpout.SetChecksum(0)
			icmpout.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
				Header: icmpout,
				Src:    id.RemoteAddress, // src
				Dst:    id.LocalAddress,  // dst
			}))

			log.D("icmp: v6 response: type %v/%v sz[%d] from %v <- %v", icmpout.Type(), icmpout.Code(), res.Size(), src, dst)

			respkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: res})
			defer respkt.DecRef()

			var pout stack.PacketBufferList
			pout.PushBack(respkt)
			if _, err := ep.WritePackets(pout); err != nil {
				log.E("icmp: v6 err writing upstream res [%v <- %v] to tun %v", src, dst, err)
				return fmt.Errorf("icmp: v6 err writing upstream res to tun %v", err)
			}

			if icmpout.Type() == header.ICMPv6DstUnreachable {
				return unix.ENETUNREACH
			}
			return nil
		}) {
			icmpin.SetType(header.ICMPv6EchoReply)
			icmpin.SetChecksum(0)
			dst := id.LocalAddress
			src := id.RemoteAddress
			icmpin.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
				Header:      icmpin,
				Src:         dst, // from dst
				Dst:         src, // to src
				PayloadCsum: packet.Data().Checksum(),
				PayloadLen:  packet.Data().Size(),
			}))

			log.D("icmp: v6 default response: type %v/%v sz[%d] from %v <- %v", icmpin.Type(), icmpin.Code(), len(icmpin), src, dst)
			var pout stack.PacketBufferList
			pout.PushBack(packet)
			if _, err := ep.WritePackets(pout); err != nil {
				log.E("icmp: v6 err writing default echo pkt to tun [%v <- %v] %v", src, dst, err)
				return false
			}
		}
		return true
	})
}
