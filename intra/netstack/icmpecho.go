package netstack

import (
	"fmt"
	"net/netip"
	"sync/atomic"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/core/wire"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const minICMPPacketSize = header.ICMPv4MinimumSize + header.IPv4MinimumSize
const typicalICMPEchoPayloadSize = 64 // or 56
const expectedICMPPacketSize = header.IPv6MinimumSize + header.ICMPv6MinimumSize + typicalICMPEchoPayloadSize
const useIcmpForwarder = true

// TODO: get rid of the global in favor of passing the handler via the responder.
// hdlEcho stores the ICMP handler used by the dispatcher-level ICMP
// interception path.
var hdlEcho = core.NewZeroVolatile[*icmpForwarder]()

func setICMPEchoHandler(h *icmpForwarder) {
	hdlEcho.Store(h)
}

// icmpResponder handles ICMP packets directly from the TUN dispatcher,
// bypassing gVisor netstack when possible.
//
// The responder uses the existing ICMP handler (which ultimately uses the core
// ICMP implementation) to forward the ping and then injects the response back
// into the TUN device.
type icmpResponder struct {
	ep   *endpoint
	open atomic.Bool
}

func (r *icmpResponder) stop() {
	r.ep = nil
	r.open.Store(false)
}

func newICMPResponder(ep *endpoint) (r icmpResponder) {
	if ep == nil {
		return
	}
	r.ep = ep
	r.open.Store(true)
	return
}

func (r *icmpResponder) ok() bool {
	return r != nil && r.open.Load() && r.ep != nil
}

func (r *icmpResponder) respond(pkt *stack.PacketBuffer) (handled bool) {
	if !r.ok() {
		return
	}
	defer pkt.DecRef()

	return r.handle(pkt.NICID, pkt.IncRef())
}

// handle returns true if the packet is ICMP and is handled (or dropped) by the
// bypass path.
func (r *icmpResponder) handle(nic tcpip.NICID, pkt *stack.PacketBuffer) (handled bool) {
	if !r.ok() {
		return
	}

	inSize := pkt.Size()
	if inSize <= minICMPPacketSize {
		// too verbose: log.VV("icmp: responder: packet too small: %d", inSize)
		// Too small to be a valid ICMP echo request.
		return
	}

	b := pkt.ToBuffer()
	h := hdlEcho.Load()
	var w core.ByteWriter
	defer w.Close()
	// lightweight determine if b is ICMP echo request
	// flatten is expensive, so we avoid it if possible
	n, err := b.ReadToWriter(&w, expectedICMPPacketSize)

	if settings.Debug {
		logeif(err)("icmp: responder: read to writer (sz: %d / %d / %d); h? %t / fwd? %t, err? %v",
			n, w.Len(), inSize, h != nil, useIcmpForwarder, err)
	}
	if err != nil || n == 0 || h == nil || w.Len() == 0 {
		return
	}

	truncated := inSize > w.Len()
	parsed := wire.Pool.Get()
	parsed.DecodeTrunc(w.Copy(), truncated)

	// Only echo requests are handled; other ICMP packets are dropped to avoid
	// feeding them back into netstack.
	if parsed.IPProto != wire.ICMPv4 && parsed.IPProto != wire.ICMPv6 {
		if settings.Debug {
			log.VV("icmp: responder: unsupported proto: %d / echo: %t @ %d; h: %s; content: %x",
				parsed.IPProto, parsed.IsEchoRequest(), parsed.EchoIDSeq(), parsed.ICMPHeaderString(), parsed.Buffer())
		}
		wire.Pool.Put(parsed)
		return
	}

	// Capture fields before spawning the goroutine.
	src := parsed.Src
	dst := parsed.Dst
	has := parsed.HasTransportData()

	logwv(!has)("icmp: responder: request ipv%d; %s => %s; h: %s; trunc? %t, ok? %t",
		parsed.IPVersion, src, dst, parsed.ICMPHeaderString(), truncated, has)

	if !has {
		wire.Pool.Put(parsed)
		return
	}

	if truncated {
		// There is more data beyond the minimum ICMP echo request.
		// Reconstruct the full packet.
		w.Reset()
		b.ReadToWriter(&w, int64(inSize))
		parsed.Decode(w.Copy())
	}

	if !parsed.IsEchoRequest() {
		if settings.Debug {
			log.VV("icmp: responder: not echo request ipv%d (trunc? %t); %s => %s; h: %s; %x",
				parsed.IPVersion, truncated, src, dst, parsed.ICMPHeaderString(), parsed.Buffer())
		}
		wire.Pool.Put(parsed)
		return
	}

	if useIcmpForwarder {
		wire.Pool.Put(parsed)
		return r.forward(h, pkt, src, dst)
	} else {
		// Process asynchronously to avoid blocking the dispatcher loop.
		core.Go("icmp.responder", func() {
			r.process(h, nic, parsed, src, dst)
		})
	}

	return true
}

func (r *icmpResponder) forward(h *icmpForwarder, pkt *stack.PacketBuffer, src, dst netip.AddrPort) bool {
	pkt.IncRef()
	defer pkt.DecRef()

	var id stack.TransportEndpointID
	// local is dst / remote is src; see: netstack/icmp/icmp.go:func (h *icmpForwarder) reply4
	// and netstack/icmp/icmp.go:func (h *icmpForwarder) reply6
	id.LocalAddress = tcpip.AddrFrom16Slice(dst.Addr().AsSlice())
	id.RemoteAddress = tcpip.AddrFrom16Slice(src.Addr().AsSlice())
	// ICMP does not use ports, so they remain zero.
	id.LocalPort = 0
	id.RemotePort = 0

	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		return h.reply4(id, pkt)
	case header.IPv6ProtocolNumber:
		return h.reply6(id, pkt)
	}

	log.W("icmp: responder: unsupported proto: %d; %s => %s",
		pkt.NetworkProtocolNumber, src, dst)
	return false
}

// process handles the ICMP echo request and injects the reply back into the TUN.
// The parsed packet is released back to the pool after processing.
func (r *icmpResponder) process(h *icmpForwarder, nic tcpip.NICID, pkt *wire.Parsed, src, dst netip.AddrPort) {
	defer wire.Pool.Put(pkt)

	icmpMsg := pkt.Transport()
	payload, truncated := pkt.Payload()
	notok := truncated || len(icmpMsg) <= 0

	if notok || settings.Debug {
		logwv(notok)("icmp: responder: truncated? %t or missing? %t ICMPv%d; %s => %s; id: %d; h: %s; sz: %d",
			truncated, len(icmpMsg) <= 0, pkt.IPVersion, src, dst, pkt.EchoIDSeq(), pkt.ICMPHeaderString(), len(payload))
	}

	if notok {
		return
	}

	pinged := h.h.Ping(icmpMsg, src, dst)

	resp, proto, tag, err := r.echoReply(pkt, payload, pinged)
	notok = err != nil || len(resp) == 0

	if notok || settings.Debug {
		logwv(notok)("icmp: responder: reply %s <= %s (sz: %d / id: %d); ping? %t; res: %s; err? %v",
			src, dst, len(resp), pkt.EchoIDSeq(), pinged, tag, err)
	}

	if err != nil || len(resp) == 0 {
		return
	}

	r.inject(nic, proto, resp)
}

func (r *icmpResponder) echoReply(pkt *wire.Parsed, d []byte, ok bool) ([]byte, tcpip.NetworkProtocolNumber, string, error) {
	// github.com/tailscale/tailscale/blob/7de1b0b33082cc/wgengine/netstack/netstack.go#L1201-L1212
	switch pkt.IPVersion {
	case 4:
		icmpHdr := pkt.ICMP4Header()
		(&icmpHdr).ToResponse()
		if !ok {
			(&icmpHdr).Type = wire.ICMP4Unreachable
			(&icmpHdr).Code = wire.ICMP4HostUnreachable
		}
		tag := icmpHdr.Stringer()
		return wire.Generate(&icmpHdr, d), header.IPv4ProtocolNumber, tag, nil
	case 6:
		icmpHdr := pkt.ICMP6Header()
		(&icmpHdr).ToResponse()
		if !ok {
			(&icmpHdr).Type = wire.ICMP6Unreachable
			(&icmpHdr).Code = wire.ICMP6NoRoute
		}
		tag := icmpHdr.Stringer()
		// github.com/tailscale/tailscale/blob/7de1b0b33082cc/wgengine/userspace.go#L577
		return wire.Generate(&icmpHdr, d), header.IPv6ProtocolNumber, tag, nil
	default:
		return nil, 0, "<nil>", fmt.Errorf("unsupported ip version: %d", pkt.IPVersion)
	}
}

func (r *icmpResponder) inject(nic tcpip.NICID, proto tcpip.NetworkProtocolNumber, packet []byte) {
	ep := r.ep
	if ep == nil || !r.ok() {
		return
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(packet),
	})
	pkt.NICID = nic
	defer pkt.DecRef()

	pkt.NetworkProtocolNumber = proto
	var list stack.PacketBufferList
	list.PushBack(pkt)

	sz := pkt.Size()
	n, err := ep.WritePackets(list)
	logeif(e(err))("icmp: responder: inject %d to tun (n: %d; sz: %d); err? %v", proto, n, sz, err)
}
