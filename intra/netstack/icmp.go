// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package netstack

import (
	"errors"
	"net/netip"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
)

// Pong is a callback function to send a reply to the client
type Pong func(reply []byte) error

type GICMPHandler interface {
	// Ping informs if ICMP Echo from src to dst is replied to
	Ping(src, dst netip.AddrPort, msg []byte) bool
	// CloseConns closes all connections
	CloseConns([]string) []string
	// End closes the handler and all its connections
	End() error
}

type icmpForwarder struct {
	ep stack.LinkEndpoint
	h  GICMPHandler
}

var errMissingIcmpPacket = errors.New("icmp: nil packet")

// ref: github.com/SagerNet/LibSagerNetCore/blob/632d6b892e/gvisor/icmp.go
func setupIcmpHandler(s *stack.Stack, ep stack.LinkEndpoint, hdl GICMPHandler) {
	// remove default handlers
	s.SetTransportProtocolHandler(icmp.ProtocolNumber4, nil)
	s.SetTransportProtocolHandler(icmp.ProtocolNumber6, nil)

	if hdl == nil {
		log.E("icmp: no handler")
		return
	}

	forwarder := newIcmpForwarder(ep, hdl)
	s.SetTransportProtocolHandler(icmp.ProtocolNumber4, forwarder.reply4)
	s.SetTransportProtocolHandler(icmp.ProtocolNumber6, forwarder.reply6)
}

func newIcmpForwarder(ep stack.LinkEndpoint, h GICMPHandler) *icmpForwarder {
	return &icmpForwarder{ep, h}
}

// sendICMP: github.com/google/gvisor/blob/8035cf9ed/pkg/tcpip/transport/tcp/testing/context/context.go#L404
// parseICMP: github.com/google/gvisor/blob/8035cf9ed/pkg/tcpip/header/parse/parse.go#L194
// makeICMP: github.com/google/gvisor/blob/8035cf9ed/pkg/tcpip/tests/integration/iptables_test.go#L2100
func (f *icmpForwarder) reply4(id stack.TransportEndpointID, pkt *stack.PacketBuffer) (handled bool) {
	var err tcpip.Error

	log.VV("icmp: v4: packet? %v", pkt)

	if pkt == nil {
		log.E("icmp: v4: nil packet")
		return // not handled
	}
	if !f.ep.IsAttached() {
		log.D("icmp: v4: endpoint not attached")
		return // not handled
	}

	src := remoteAddrPort(id)
	dst := localAddrPort(id)

	// ref: github.com/google/gvisor/blob/acf460d0d735/pkg/tcpip/stack/conntrack.go#L933
	hdr := header.ICMPv4(pkt.TransportHeader().Slice())
	if hdr.Type() != header.ICMPv4Echo {
		// netstack handles other msgs except echo / ping
		log.D("icmp: v4: type %v passthrough", hdr.Type())
		return // not handled
	}

	// github.com/google/gvisor/blob/9b4a7aa00/pkg/tcpip/network/ipv6/icmp.go#L1180
	data, derr := l4l7(pkt, f.ep.MTU())
	if derr != nil {
		log.E("icmp: v4: err getting payload: %v", derr)
		return // not handled
	}

	log.D("icmp: v4: type %v/%v sz [%v]; src(%v) -> dst(%v)", hdr.Type(), hdr.Code(), len(data), src, dst)

	// always forward in a goroutine to avoid blocking netstack
	// see: netstack/dispatcher.go:newReadvDispatcher
	core.Go("icmp4.pinger", func() {
		if !f.h.Ping(src, dst, data) { // unreachable
			// make unreachable icmp packet for req and l7
			err = f.icmpErr4(pkt, header.ICMPv4DstUnreachable, header.ICMPv4HostUnreachable)
		} else { // reachable
			// if unhandled by the handler, send a reply ourselves
			hdr.SetType(header.ICMPv4EchoReply)
			hdr.SetChecksum(0)
			hdr.SetChecksum(header.ICMPv4Checksum(hdr, pkt.Data().Checksum()))
			log.D("icmp: v4: ok type %v/%v sz[%d] from %v <- %v", hdr.Type(), hdr.Code(), len(hdr), src, dst)
			var pout stack.PacketBufferList
			pout.PushBack(pkt)
			_, err = f.ep.WritePackets(pout)
		}
		loge(err, "icmp: v4: wrote reply to tun; err? %v", err)
	})

	return true // handled
}

func (f *icmpForwarder) reply6(id stack.TransportEndpointID, packet *stack.PacketBuffer) (handled bool) {
	log.VV("icmp: v6 packet? %v", packet)

	if packet == nil {
		log.E("icmp: v6: nil packet")
		return // not handled
	}
	if !f.ep.IsAttached() {
		log.D("icmp: v6: endpoint not attached")
		return // not handled
	}

	hdr := header.ICMPv6(packet.TransportHeader().Slice())
	if hdr.Type() != header.ICMPv6EchoRequest {
		log.D("icmp: v6: type %v/%v passthrough", hdr.Type(), hdr.Code())
		return false // netstack to handle other msgs except echo / ping
	}

	src := remoteAddrPort(id)
	dst := localAddrPort(id)
	// github.com/google/gvisor/blob/9b4a7aa00/pkg/tcpip/network/ipv6/icmp.go#L1180
	data, derr := l4l7(packet, f.ep.MTU())
	if derr != nil {
		log.E("icmp: v6: err getting payload: %v", derr)
		return // not handled
	}

	log.D("icmp: v6: type %v/%v sz[%d] from src(%v) -> dst(%v)", hdr.Type(), hdr.Code(), len(data), src, dst)
	// always forward in a goroutine to avoid blocking netstack
	// see: netstack/dispatcher.go:newReadvDispatcher
	core.Go("icmp4.pinger", func() {
		var err tcpip.Error
		if !f.h.Ping(src, dst, data) { // unreachable
			err = f.icmpErr6(id, packet, header.ICMPv6DstUnreachable, header.ICMPv6NetworkUnreachable)
		} else { // reachable
			hdr.SetType(header.ICMPv6EchoReply)
			hdr.SetChecksum(0)
			hdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
				Header:      hdr,
				Src:         id.LocalAddress,  // from dst
				Dst:         id.RemoteAddress, // to src
				PayloadCsum: packet.Data().Checksum(),
				PayloadLen:  packet.Data().Size(),
			}))
			log.D("icmp: v6: ok type %v/%v sz[%d] from %v <- %v", hdr.Type(), hdr.Code(), len(hdr), src, dst)
			var pout stack.PacketBufferList
			pout.PushBack(packet)
			_, err = f.ep.WritePackets(pout)
		}
		loge(err, "icmp: v6: wrote reply to tun; err? %v", err)
	})

	return true
}

// from: github.com/google/gvisor/blob/19ab27f98/pkg/tcpip/network/ipv4/icmp.go#L609
func (f *icmpForwarder) icmpErr4(pkt *stack.PacketBuffer, icmpType header.ICMPv4Type, icmpCode header.ICMPv4Code) tcpip.Error {
	origIPHdr := header.IPv4(pkt.NetworkHeader().Slice())
	origIPHdrSrc := origIPHdr.SourceAddress()
	origIPHdrDst := origIPHdr.DestinationAddress()

	// TODO(gvisor.dev/issues/4058): Make sure we don't send ICMP errors in
	// response to a non-initial fragment, but it currently can not happen.
	if pkt.NetworkPacketInfo.LocalAddressBroadcast || header.IsV4MulticastAddress(origIPHdrDst) || origIPHdrSrc == header.IPv4Any {
		log.W("icmp: v4: skip broadcast/multicast dst(%s) <- src(%s)", origIPHdrDst, origIPHdrSrc)
		return &tcpip.ErrAddressFamilyNotSupported{}
	}

	transportHeader := pkt.TransportHeader().Slice()

	// Don't respond to icmp error packets.
	if origIPHdr.Protocol() == uint8(header.ICMPv4ProtocolNumber) {
		// We need to decide to explicitly name the packets we can respond to or
		// the ones we can not respond to. The decision is somewhat arbitrary and
		// if problems arise this could be reversed. It was judged less of a breach
		// of protocol to not respond to unknown non-error packets than to respond
		// to unknown error packets so we take the first approach.
		if len(transportHeader) < header.ICMPv4MinimumSize {
			log.D("icmp: v4: l4 header too small: %d", len(transportHeader))
			return &tcpip.ErrMalformedHeader{}
		}
		x := header.ICMPv4(transportHeader)
		switch x.Type() {
		case
			header.ICMPv4EchoReply,
			header.ICMPv4Echo,
			header.ICMPv4Timestamp,
			header.ICMPv4TimestampReply,
			header.ICMPv4InfoRequest,
			header.ICMPv4InfoReply:
		default:
			// Assume any type we don't know about may be an error type.
			log.W("icmp: v4: skip ICMP error packet %d", x.Type())
			return &tcpip.ErrNotSupported{}
		}
	}

	var pointer byte = 0 // only needed for param problem packets
	switch icmpCode {
	case header.ICMPv4NetProhibited:
	case header.ICMPv4HostProhibited:
	case header.ICMPv4AdminProhibited:
	case header.ICMPv4PortUnreachable:
	case header.ICMPv4ProtoUnreachable:
	case header.ICMPv4NetUnreachable: // or:  header.ICMPv4TTLExceeded, header.ICMPv4CodeUnused
	case header.ICMPv4HostUnreachable: // or: header.ICMPv4ReassemblyTimeout
	case header.ICMPv4FragmentationNeeded:
	default:
		log.W("icmp: v4: unsupported code %d", icmpCode)
		return &tcpip.ErrNotSupported{}
	}

	// Now work out how much of the triggering packet we should return.
	// As per RFC 1812 Section 4.3.2.3
	//
	//   ICMP datagram SHOULD contain as much of the original
	//   datagram as possible without the length of the ICMP
	//   datagram exceeding 576 bytes.
	//
	// NOTE: The above RFC referenced is different from the original
	// recommendation in RFC 1122 and RFC 792 where it mentioned that at
	// least 8 bytes of the payload must be included. Today linux and other
	// systems implement the RFC 1812 definition and not the original
	// requirement. We treat 8 bytes as the minimum but will try send more.
	mtu := int(f.ep.MTU())
	const maxIPData = header.IPv4MinimumProcessableDatagramSize - header.IPv4MinimumSize
	if mtu > maxIPData {
		mtu = maxIPData
	}
	available := mtu - header.ICMPv4MinimumSize
	needed := len(origIPHdr) + header.ICMPv4MinimumErrorPayloadSize
	payloadLen := len(origIPHdr) + len(transportHeader) + pkt.Data().Size()

	if available < needed {
		log.W("icmp: v4: no space for orig IP header has: %d < want: %d; total %d", available, needed, payloadLen)
		return &tcpip.ErrNoBufferSpace{}
	}

	if payloadLen > available {
		payloadLen = available
	}

	// The buffers used by pkt may be used elsewhere in the system.
	// For example, an AF_RAW or AF_PACKET socket may use what the transport
	// protocol considers an unreachable destination. Thus we deep copy pkt to
	// prevent multiple ownership and SR errors. The new copy is a vectorized
	// view with the entire incoming IP packet reassembled and truncated as
	// required. This is now the payload of the new ICMP packet and no longer
	// considered a packet in its own right.

	payload := buffer.MakeWithView(pkt.NetworkHeader().View())
	payload.Append(pkt.TransportHeader().View())
	if dataCap := payloadLen - int(payload.Size()); dataCap > 0 {
		buf := pkt.Data().ToBuffer()
		buf.Truncate(int64(dataCap))
		payload.Merge(&buf)
	} else {
		payload.Truncate(int64(payloadLen))
	}

	icmpPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(f.ep.MaxHeaderLength()) + header.ICMPv4MinimumSize,
		Payload:            payload,
	})
	defer icmpPkt.DecRef()

	icmpPkt.TransportProtocolNumber = header.ICMPv4ProtocolNumber

	icmpHdr := header.ICMPv4(icmpPkt.TransportHeader().Push(header.ICMPv4MinimumSize))
	icmpHdr.SetCode(icmpCode)
	icmpHdr.SetType(icmpType)
	icmpHdr.SetPointer(pointer)
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, icmpPkt.Data().Checksum()))

	var pout stack.PacketBufferList
	pout.PushBack(icmpPkt)

	n, err := f.ep.WritePackets(pout)

	loge(err, "icmp: v4: sent %d bytes to tun; err? %v", n, err)

	return err
}

// from: github.com/google/gvisor/blob/19ab27f98/pkg/tcpip/network/ipv6/icmp.go#L1055
func (f *icmpForwarder) icmpErr6(id stack.TransportEndpointID, pkt *stack.PacketBuffer, icmpType header.ICMPv6Type, icmpCode header.ICMPv6Code) tcpip.Error {
	origIPHdr := header.IPv6(pkt.NetworkHeader().Slice())
	origIPHdrSrc := origIPHdr.SourceAddress()
	origIPHdrDst := origIPHdr.DestinationAddress()

	// Only send ICMP error if the address is not a multicast v6
	// address and the source is not the unspecified address.
	//
	// There are exceptions to this rule.
	// See: point e.3) RFC 4443 section-2.4
	//
	//	 (e) An ICMPv6 error message MUST NOT be originated as a result of
	//       receiving the following:
	//
	//       (e.1) An ICMPv6 error message.
	//
	//       (e.2) An ICMPv6 redirect message [IPv6-DISC].
	//
	//       (e.3) A packet destined to an IPv6 multicast address.  (There are
	//             two exceptions to this rule: (1) the Packet Too Big Message
	//             (Section 3.2) to allow Path MTU discovery to work for IPv6
	//             multicast, and (2) the Parameter Problem Message, Code 2
	//             (Section 3.4) reporting an unrecognized IPv6 option (see
	//             Section 4.2 of [IPv6]) that has the Option Type highest-
	//             order two bits set to 10).
	//
	allowResponseToMulticast := false // TODO: reason.respondsToMulticast()
	isOrigDstMulticast := header.IsV6MulticastAddress(origIPHdrDst)
	if (!allowResponseToMulticast && isOrigDstMulticast) || origIPHdrSrc == header.IPv6Any {
		log.W("icmp: v6: skip multicast dst(%s) <- src(%s)", origIPHdrDst, origIPHdrSrc)
		return &tcpip.ErrAddressFamilyNotSupported{}
	}

	if pkt.TransportProtocolNumber == header.ICMPv6ProtocolNumber {
		if typ := header.ICMPv6(pkt.TransportHeader().Slice()).Type(); typ.IsErrorType() || typ == header.ICMPv6RedirectMsg {
			log.W("icmp: v6: skip ICMP error packet %d", typ)
			return nil
		}
	}

	var pointer uint32 = 0 // TODO: must be set for param problem packets
	switch icmpCode {
	// TODO: handle ICMPv6ParamProblem; determine reason.code, reason.pointer
	case header.ICMPv6Prohibited: // ICMPv6DstUnreachable
	case header.ICMPv6PortUnreachable: // ICMPv6DstUnreachable
	case header.ICMPv6NetworkUnreachable: // ICMPv6DstUnreachable
		// or: ICMPv6HopLimitExceeded/ICMPv6UnusedCode -> ICMPv6TimeLimitExceeded
		// or: ICMPv6ReassemblyTimeout -> ICMPv6PacketTooBig
	case header.ICMPv6AddressUnreachable: // ICMPv6DstUnreachable
	default:
		log.W("icmp: v6: unsupported code %d", icmpCode)
		return &tcpip.ErrNotSupported{}
	}

	network, transport := pkt.NetworkHeader().View(), pkt.TransportHeader().View()

	// As per RFC 4443 section 2.4
	//
	//    (c) Every ICMPv6 error message (type < 128) MUST include
	//    as much of the IPv6 offending (invoking) packet (the
	//    packet that caused the error) as possible without making
	//    the error message packet exceed the minimum IPv6 MTU
	//    [IPv6].
	mtu := int(f.ep.MTU())
	const maxIPv6Data = header.IPv6MinimumMTU - header.IPv6FixedHeaderSize
	if mtu > maxIPv6Data {
		mtu = maxIPv6Data
	}
	available := mtu - header.ICMPv6ErrorHeaderSize
	needed := header.IPv6MinimumSize
	payloadLen := network.Size() + transport.Size() + pkt.Data().Size()
	if available < needed {
		log.W("icmp: v6: no space for orig IP header has: %d < want: %d; total %d", available, needed, payloadLen)
		return &tcpip.ErrNoBufferSpace{}
	}
	if payloadLen > available {
		payloadLen = available
	}

	payload, err := l3l4(pkt, int64(payloadLen))
	if err != nil {
		log.E("icmp: v6: err getting payload: %v", err)
		return &tcpip.ErrNoBufferSpace{}
	}

	newPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(f.ep.MaxHeaderLength()) + header.ICMPv6ErrorHeaderSize,
		Payload:            payload,
	})
	defer newPkt.DecRef()
	newPkt.TransportProtocolNumber = header.ICMPv6ProtocolNumber

	icmpHdr := header.ICMPv6(newPkt.TransportHeader().Push(header.ICMPv6DstUnreachableMinimumSize))
	icmpHdr.SetType(icmpType)
	icmpHdr.SetCode(icmpCode)
	icmpHdr.SetTypeSpecific(pointer)

	pktData := newPkt.Data()
	icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      icmpHdr,
		Src:         id.LocalAddress,
		Dst:         id.RemoteAddress,
		PayloadCsum: pktData.Checksum(),
		PayloadLen:  pktData.Size(),
	}))

	var pout stack.PacketBufferList
	pout.PushBack(newPkt)
	n, werr := f.ep.WritePackets(pout)

	loge(werr, "icmp: v6: sent %d bytes to tun; err? %v", n, werr)

	return werr
}

func loge(err tcpip.Error, format string, args ...any) {
	f := log.D
	if err == nil {
		f = log.V
	}
	f(format, args)
}

func l4l7(pkt *stack.PacketBuffer, sz uint32) ([]byte, error) {
	r := make([]byte, 0, sz)
	din := buffer.MakeWithData(r)
	l4 := pkt.TransportHeader().View()
	err := din.Append(l4)
	if err != nil {
		log.E("icmp: l4l7: err appending transport header: %v", err)
		return nil, err
	}
	l7 := pkt.Data().ToBuffer()
	din.Merge(&l7) // l4 + l7
	return din.Flatten(), nil
}

func l3l4(pkt *stack.PacketBuffer, sz int64) (b buffer.Buffer, err error) {
	l3 := pkt.NetworkHeader().View()
	l4 := pkt.TransportHeader().View()
	v := buffer.MakeWithView(l3)
	if err = v.Append(l4); err == nil {
		b = pkt.Data().ToBuffer()
		b.Merge(&b)
		b.Truncate(sz)
	}
	return
}
