package netstack

import (
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

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
	ep   stack.LinkEndpoint
	open atomic.Bool
}

func (r *icmpResponder) stop() {
	r.open.Store(false)
}

func newICMPResponder(ep stack.LinkEndpoint) (r icmpResponder) {
	if ep == nil || core.IsNil(ep) {
		return
	}
	r.ep = ep
	r.open.Store(true)
	return
}

func (r *icmpResponder) ok() bool {
	return r != nil && r.open.Load()
}

func (r *icmpResponder) respond(pkt *stack.PacketBuffer) (handled bool) {
	if !r.ok() {
		return
	}
	return r.handle(pkt.NICID, pkt.Clone())
}

// handle returns true if the packet is ICMP and is handled (or dropped) by the
// bypass path.
func (r *icmpResponder) handle(nic tcpip.NICID, pkt *stack.PacketBuffer) (handled bool) {
	defer pkt.DecRef()

	if !r.ok() {
		return
	}

	inSize := pkt.Size()
	if inSize <= minICMPPacketSize {
		// too verbose: log.VV("icmp: responder: packet too small: %d", inSize)
		// Too small to be a valid ICMP echo request.
		return
	}

	v := pkt.ToView()
	b := v.ToSlice()
	h := hdlEcho.Load()
	n := len(b)

	notok := n <= 0 || h == nil
	if settings.Debug || notok {
		logwv(notok)("icmp: responder: read to writer (sz: %d / %d / %d); h? %t / fwd? %t",
			n, v.Size(), inSize, h != nil, useIcmpForwarder)
	}
	if notok {
		return
	}

	truncated := false
	parsed := wire.Pool.Get()
	parsed.DecodeTrunc(b, truncated)

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
		core.Gx("icmp.responder", func() {
			r.process(h, nic, parsed, src, dst)
		})
	}

	return true
}

func (r *icmpResponder) forward(h *icmpForwarder, pkt *stack.PacketBuffer, src, dst netip.AddrPort) bool {
	pkt.IncRef()
	defer pkt.DecRef()

	// local is dst / remote is src; see: netstack/icmp/icmp.go:func (h *icmpForwarder) reply4
	// and netstack/icmp/icmp.go:func (h *icmpForwarder) reply6
	local := dst.Addr().AsSlice()
	remote := src.Addr().AsSlice()

	notok := len(local) == 0 || len(remote) == 0
	logwv(notok)("icmp: responder: forward: (sz: %d) empty addr? %s => %s", pkt.Size(), src, dst)
	if notok {
		return false
	}

	var id stack.TransportEndpointID
	id.LocalAddress = tcpip.AddrFromSlice(local)
	id.RemoteAddress = tcpip.AddrFromSlice(remote)
	// ICMP does not use ports, so they remain zero.

	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		v, got := core.Await1(func() bool { defer pkt.DecRef(); return h.reply4(id, pkt.IncRef()) }, 3*time.Second)
		return got && v
	case header.IPv6ProtocolNumber:
		v, got := core.Await1(func() bool { defer pkt.DecRef(); return h.reply6(id, pkt.IncRef()) }, 3*time.Second)
		return got && v
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
