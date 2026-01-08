// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package netstack

import (
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
)

type GICMPHandler interface {
	GBaseConnHandler
	GEchoConnHandler
}

type icmpForwarder struct {
	o string
	s *stack.Stack
	h GICMPHandler
}

// github.com/google/gvisor/blob/738e1d995f/pkg/tcpip/network/ipv4/icmp.go
// github.com/google/gvisor/blob/738e1d995f/pkg/tcpip/network/ipv6/icmp.go
func OutboundICMP(id string, s *stack.Stack, hdl GICMPHandler) {
	// remove default handlers
	s.SetTransportProtocolHandler(icmp.ProtocolNumber4, nil)
	s.SetTransportProtocolHandler(icmp.ProtocolNumber6, nil)

	if hdl == nil {
		log.E("icmp: %s: no handler", id)
		return
	}

	forwarder := newIcmpForwarder(id, s, hdl)
	s.SetTransportProtocolHandler(icmp.ProtocolNumber4, forwarder.reply4)
	s.SetTransportProtocolHandler(icmp.ProtocolNumber6, forwarder.reply6)
	setICMPEchoHandler(forwarder)
}

func newIcmpForwarder(owner string, s *stack.Stack, h GICMPHandler) *icmpForwarder {
	return &icmpForwarder{owner, s, h}
}

// sendICMP: github.com/google/gvisor/blob/8035cf9ed/pkg/tcpip/transport/tcp/testing/context/context.go#L404
// parseICMP: github.com/google/gvisor/blob/8035cf9ed/pkg/tcpip/header/parse/parse.go#L194
// makeICMP: github.com/google/gvisor/blob/8035cf9ed/pkg/tcpip/tests/integration/iptables_test.go#L2100
func (f *icmpForwarder) reply4(id stack.TransportEndpointID, pkt *stack.PacketBuffer) (handled bool) {
	var err tcpip.Error

	if settings.Debug {
		log.VV("icmp: v4: %s: packet? %v", f.o, pkt)
	}

	if pkt == nil {
		log.E("icmp: v4: %s: nil packet", f.o)
		return // not handled
	}

	src := remoteAddrPort(id)
	dst := localAddrPort(id)

	// ref: github.com/google/gvisor/blob/acf460d0d735/pkg/tcpip/stack/conntrack.go#L933
	hdr := header.ICMPv4(pkt.TransportHeader().Slice())
	if hdr.Type() != header.ICMPv4Echo {
		// netstack handles other msgs except echo / ping
		log.D("icmp: v4: %s: type %v passthrough", f.o, hdr.Type())
		return // not handled
	}
	ipHdr := header.IPv4(pkt.NetworkHeader().Slice())

	replyData := stack.PayloadSince(pkt.TransportHeader())
	localAddressBroadcast := pkt.NetworkPacketInfo.LocalAddressBroadcast

	// see: github.com/google/gvisor/blob/738e1d995f/pkg/tcpip/network/ipv4/icmp.go#L371
	// As per RFC 1122 section 3.2.1.3, when a host sends any datagram, the IP
	// source address MUST be one of its own IP addresses (but not a broadcast
	// or multicast address).
	localAddr := ipHdr.DestinationAddress()
	if localAddressBroadcast || header.IsV4MulticastAddress(localAddr) {
		localAddr = tcpip.Address{}
	}

	l3 := pkt.Network() // same as ipHdr; l3.Dst == id.LocalAddr and l3.Src == id.RemoteAddr
	route, err := f.s.FindRoute(pkt.NICID, localAddr, l3.SourceAddress(), pkt.NetworkProtocolNumber, false /* multicastLoop */)
	if err != nil {
		log.W("icmp: v4: %s: no route on %v to %s <= %s", f.o, pkt.NICID, l3.DestinationAddress(), l3.SourceAddress())
		return false // not handled
	}

	// github.com/google/gvisor/blob/9b4a7aa00/pkg/tcpip/network/ipv6/icmp.go#L1180
	data, derr := l4l7(pkt, route.MTU())
	if derr != nil {
		log.E("icmp: v4: %s: err getting payload: %v", f.o, derr)
		return // not handled
	}

	if settings.Debug {
		log.D("icmp: v4: %s: type %v/%v sz [%v]; src(%v) => dst(%v)",
			f.o, hdr.Type(), hdr.Code(), len(data), src, dst)
	}

	// always forward in a goroutine to avoid blocking netstack
	// see: netstack/dispatcher.go:newReadvDispatcher
	pkt.IncRef()

	core.Go("icmp4.pinger."+f.o, func() {
		defer replyData.Release()
		defer route.Release()
		defer pkt.DecRef()

		if !f.h.Ping(data, src, dst) { // unreachable
			err = f.icmpErr4(pkt, header.ICMPv4DstUnreachable, header.ICMPv4HostUnreachable)
		} else { // reachable
			originRef := replyData.AsSlice()
			replyBuf := buffer.NewViewSize(len(originRef))
			replyRef := replyBuf.AsSlice()

			copy(replyRef[4:], originRef[4:])
			replyICMPHdr := header.ICMPv4(replyRef)
			replyICMPHdr.SetType(header.ICMPv4EchoReply)
			replyICMPHdr.SetCode(0) // EchoReply must have Code=0.
			replyICMPHdr.SetChecksum(^checksum.Checksum(replyRef, 0))

			var replyPkt *stack.PacketBuffer = stack.NewPacketBuffer(stack.PacketBufferOptions{
				ReserveHeaderBytes: int(route.MaxHeaderLength()),
				Payload:            buffer.MakeWithView(replyBuf),
			})
			replyPkt.NICID = pkt.NICID
			defer replyPkt.DecRef()

			if settings.Debug {
				log.D("icmp: v4: %s: ok type %v/%v sz[%d] from %v <= %v",
					f.o, replyICMPHdr.Type(), replyICMPHdr.Code(), len(replyICMPHdr), src, dst)
			}
			// github.com/google/gvisor/blob/738e1d995f/pkg/tcpip/network/ipv4/icmp.go#L794
			err = route.WritePacket(stack.NetworkHeaderParams{
				Protocol: header.ICMPv4ProtocolNumber,
				TTL:      route.DefaultTTL(),
			}, replyPkt)
		}
		loge(err)("icmp: v4: %s: wrote reply to tun; err? %v", f.o, err)
	})

	return true // handled
}

func (f *icmpForwarder) reply6(id stack.TransportEndpointID, pkt *stack.PacketBuffer) (handled bool) {
	if settings.Debug {
		log.VV("icmp: v6: %s: packet? %v", f.o, pkt)
	}

	if pkt == nil {
		log.E("icmp: v6: %s: nil packet", f.o)
		return // not handled
	}

	hdr := header.ICMPv6(pkt.TransportHeader().Slice())
	if hdr.Type() != header.ICMPv6EchoRequest {
		log.D("icmp: v6: %s: type %v/%v passthrough", f.o, hdr.Type(), hdr.Code())
		return // netstack to handle other msgs except echo / ping
	}

	l3 := pkt.Network() // l3.Dst == id.LocalAddr and l3.Src == id.RemoteAddr
	route, err := f.s.FindRoute(pkt.NICID, l3.DestinationAddress(), l3.SourceAddress(), pkt.NetworkProtocolNumber, false)
	if err != nil {
		log.W("icmp: v6: %s: no route on %v to %s <= %s", f.o, pkt.NICID, l3.DestinationAddress(), l3.SourceAddress())
		return // not handled
	}

	src := remoteAddrPort(id)
	dst := localAddrPort(id)
	// github.com/google/gvisor/blob/9b4a7aa00/pkg/tcpip/network/ipv6/icmp.go#L1180
	data, derr := l4l7(pkt, route.MTU())
	if derr != nil {
		log.E("icmp: v6: %s: err getting payload: %v", f.o, derr)
		return // not handled
	}

	if settings.Debug {
		log.D("icmp: v6: %s: type %v/%v sz[%d] from src(%v) => dst(%v)",
			f.o, hdr.Type(), hdr.Code(), len(data), src, dst)
	}

	// always forward in a goroutine to avoid blocking netstack
	// see: netstack/dispatcher.go:newReadvDispatcher
	pkt.IncRef()

	core.Go("icmp6.pinger."+f.o, func() {
		defer route.Release()
		defer pkt.DecRef()

		var err tcpip.Error
		if !f.h.Ping(data, src, dst) { // unreachable
			err = f.icmpErr6(id, pkt, header.ICMPv6DstUnreachable, header.ICMPv6NetworkUnreachable)
		} else { // reachable
			replyPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				ReserveHeaderBytes: int(route.MaxHeaderLength()) + header.ICMPv6EchoMinimumSize,
				Payload:            pkt.Data().ToBuffer(),
			})
			defer replyPkt.DecRef()
			replyHdr := header.ICMPv6(replyPkt.TransportHeader().Push(header.ICMPv6EchoMinimumSize))
			replyPkt.TransportProtocolNumber = header.ICMPv6ProtocolNumber
			copy(replyHdr, hdr)
			replyHdr.SetType(header.ICMPv6EchoReply)
			replyData := replyPkt.Data()
			replyHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
				Header:      replyHdr,
				Src:         route.LocalAddress(),  // or id.LocalAddress
				Dst:         route.RemoteAddress(), // or id.RemoteAddress
				PayloadCsum: replyData.Checksum(),
				PayloadLen:  replyData.Size(),
			}))

			if settings.Debug {
				log.D("icmp: v6: %s: ok type %v/%v sz[%d] from %v <= %v",
					f.o, replyHdr.Type(), replyHdr.Code(), len(replyHdr), src, dst)
			}
			// github.com/google/gvisor/blob/738e1d995f/pkg/tcpip/network/ipv6/icmp.go#L694
			replyclass, _ := l3.TOS()
			err = route.WritePacket(stack.NetworkHeaderParams{
				Protocol: header.ICMPv6ProtocolNumber,
				TTL:      route.DefaultTTL(),
				TOS:      replyclass,
			}, replyPkt)
		}
		loge(err)("icmp: v6: %s: wrote reply to tun; err? %v", f.o, err)
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
		log.W("icmp: v4: %s: skip broadcast/multicast dst(%s) <= src(%s)", f.o, origIPHdrDst, origIPHdrSrc)
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
			log.D("icmp: v4: %s: l4 header too small: %d", f.o, len(transportHeader))
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
			log.W("icmp: v4: %s: skip ICMP error packet %d", f.o, x.Type())
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
		log.W("icmp: v4: %s: unsupported code %d", f.o, icmpCode)
		return &tcpip.ErrNotSupported{}
	}

	// origIPDst == id.LocalAddr and origIPSrc == id.RemoteAddr
	route, err := f.s.FindRoute(pkt.NICID, origIPHdrDst, origIPHdrSrc, pkt.NetworkProtocolNumber, false)
	if err != nil {
		log.W("icmp: v4: %s: no route on %v to %s <= %s", f.o, pkt.NICID, origIPHdrDst, origIPHdrSrc)
		return &tcpip.ErrNoNet{}
	}
	defer route.Release()

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
	mtu := int(route.MTU())
	const maxIPData = header.IPv4MinimumProcessableDatagramSize - header.IPv4MinimumSize
	if mtu > maxIPData {
		mtu = maxIPData
	}
	available := mtu - header.ICMPv4MinimumSize
	needed := len(origIPHdr) + header.ICMPv4MinimumErrorPayloadSize
	payloadLen := len(origIPHdr) + len(transportHeader) + pkt.Data().Size()

	if available < needed {
		log.W("icmp: v4: %s: no space for orig IP header has: %d < want: %d; total %d",
			f.o, available, needed, payloadLen)
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

	payload, perr := l3l4(pkt, int64(payloadLen))
	if perr != nil {
		log.E("icmp: v4: %s: err getting payload: %v", f.o, perr)
		return &tcpip.ErrNoBufferSpace{}
	}

	icmpPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(route.MaxHeaderLength()) + header.ICMPv4MinimumSize,
		Payload:            payload,
	})
	icmpPkt.IncRef()
	defer icmpPkt.DecRef()

	icmpPkt.TransportProtocolNumber = header.ICMPv4ProtocolNumber

	icmpHdr := header.ICMPv4(icmpPkt.TransportHeader().Push(header.ICMPv4MinimumSize))
	icmpHdr.SetCode(icmpCode)
	icmpHdr.SetType(icmpType)
	icmpHdr.SetPointer(pointer)
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, icmpPkt.Data().Checksum()))

	werr := route.WriteHeaderIncludedPacket(icmpPkt)

	loge(werr)("icmp: v4: %s: sent %d bytes to tun; err? %v", f.o, icmpPkt.Size(), werr)

	return werr
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
		log.W("icmp: v6: %s: skip multicast dst(%s) <= src(%s)", f.o, origIPHdrDst, origIPHdrSrc)
		return &tcpip.ErrAddressFamilyNotSupported{}
	}

	if pkt.TransportProtocolNumber == header.ICMPv6ProtocolNumber {
		if typ := header.ICMPv6(pkt.TransportHeader().Slice()).Type(); typ.IsErrorType() || typ == header.ICMPv6RedirectMsg {
			log.W("icmp: v6: %s: skip ICMP error packet %d", f.o, typ)
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
		log.W("icmp: v6: %s: unsupported code %d", f.o, icmpCode)
		return &tcpip.ErrNotSupported{}
	}

	// origIPDst == id.LocalAddr and origIPSrc == id.RemoteAddr
	route, err := f.s.FindRoute(pkt.NICID, origIPHdrDst, origIPHdrSrc, pkt.NetworkProtocolNumber, false)
	if err != nil {
		log.W("icmp: v6: %s: no route on %v to %s <= %s", f.o, pkt.NICID, origIPHdrDst, origIPHdrSrc)
		return &tcpip.ErrNoNet{}
	}
	defer route.Release()

	network, transport := pkt.NetworkHeader().View(), pkt.TransportHeader().View()

	// As per RFC 4443 section 2.4
	//
	//    (c) Every ICMPv6 error message (type < 128) MUST include
	//    as much of the IPv6 offending (invoking) packet (the
	//    packet that caused the error) as possible without making
	//    the error message packet exceed the minimum IPv6 MTU
	//    [IPv6].
	mtu := int(route.MTU())
	const maxIPv6Data = header.IPv6MinimumMTU - header.IPv6FixedHeaderSize
	if mtu > maxIPv6Data {
		mtu = maxIPv6Data
	}
	available := mtu - header.ICMPv6ErrorHeaderSize
	needed := header.IPv6MinimumSize
	payloadLen := network.Size() + transport.Size() + pkt.Data().Size()
	if available < needed {
		log.W("icmp: v6: %s: no space for orig IP header; has: %d < want: %d; total %d",
			f.o, available, needed, payloadLen)
		return &tcpip.ErrNoBufferSpace{}
	}
	if payloadLen > available {
		payloadLen = available
	}

	payload, perr := l3l4(pkt, int64(payloadLen))
	if perr != nil {
		log.E("icmp: v6: %s: err getting payload: %v", f.o, perr)
		return &tcpip.ErrNoBufferSpace{}
	}

	icmpPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(route.MaxHeaderLength()) + header.ICMPv6ErrorHeaderSize,
		Payload:            payload,
	})
	icmpPkt.TransportProtocolNumber = header.ICMPv6ProtocolNumber
	icmpPkt.IncRef()
	defer icmpPkt.DecRef()

	icmpHdr := header.ICMPv6(icmpPkt.TransportHeader().Push(header.ICMPv6DstUnreachableMinimumSize))
	icmpHdr.SetType(icmpType)
	icmpHdr.SetCode(icmpCode)
	icmpHdr.SetTypeSpecific(pointer)

	pktData := icmpPkt.Data()
	icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      icmpHdr,
		Src:         id.LocalAddress,
		Dst:         id.RemoteAddress,
		PayloadCsum: pktData.Checksum(),
		PayloadLen:  pktData.Size(),
	}))

	werr := route.WriteHeaderIncludedPacket(icmpPkt)

	loge(werr)("icmp: v6: %s: sent %d bytes to tun; err? %v", f.o, icmpPkt.Size(), werr)

	return werr
}

func loge(err tcpip.Error) (f log.LogFn) {
	f = log.E
	if err == nil {
		f = log.V
	}
	return
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
	combined := buffer.MakeWithView(l3)
	if err = combined.Append(l4); err == nil {
		payload := pkt.Data().ToBuffer()
		combined.Merge(&payload)
		combined.Truncate(sz)
		b = combined
	}
	return
}
