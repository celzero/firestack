// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//    Copyright 2024 The gVisor Authors.
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//         http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

package netstack

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"sync"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/hash/jenkins"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// adopted from: https://github.com/google/gvisor/blob/a244eff8ad/pkg/tcpip/link/fdbased/processors.go

const (
	maxForwarders = 6
)

type pkts struct {
	num tcpip.NetworkProtocolNumber
	pkt *stack.PacketBuffer
}

type fiveTuple struct {
	srcAddr, dstAddr []byte
	srcPort, dstPort uint16
	proto            tcpip.NetworkProtocolNumber
}

func (t fiveTuple) String() string {
	return fmt.Sprintf("%d | %s:%d -> %s:%d", t.proto, t.srcAddr, t.srcPort, t.dstAddr, t.dstPort)
}

// tcpipConnectionID returns a tcpip connection id tuple based on the data found
// in the packet. It returns true if the packet is not associated with an active
// connection (e.g ARP, NDP, etc). The method assumes link headers have already
// been processed if they were present.
func tcpipConnectionID(pkt *stack.PacketBuffer) (fiveTuple, bool) {
	tup := fiveTuple{}
	h, ok := pkt.Data().PullUp(1)
	if !ok {
		// Skip this packet.
		return tup, true
	}

	const tcpSrcDstPortLen = 4
	switch header.IPVersion(h) {
	case header.IPv4Version:
		hdrLen := header.IPv4(h).HeaderLength()
		h, ok = pkt.Data().PullUp(int(hdrLen) + tcpSrcDstPortLen)
		if !ok {
			return tup, true
		}
		ipHdr := header.IPv4(h[:hdrLen])
		tcpHdr := header.TCP(h[hdrLen:][:tcpSrcDstPortLen])

		tup.srcAddr = ipHdr.SourceAddressSlice()
		tup.dstAddr = ipHdr.DestinationAddressSlice()
		// All fragment packets need to be processed by the same goroutine, so
		// only record the TCP ports if this is not a fragment packet.
		if ipHdr.IsValid(pkt.Data().Size()) && !ipHdr.More() && ipHdr.FragmentOffset() == 0 {
			tup.srcPort = tcpHdr.SourcePort()
			tup.dstPort = tcpHdr.DestinationPort()
		}
		tup.proto = header.IPv4ProtocolNumber
	case header.IPv6Version:
		h, ok = pkt.Data().PullUp(header.IPv6FixedHeaderSize + tcpSrcDstPortLen)
		if !ok {
			return tup, true
		}
		ipHdr := header.IPv6(h)

		var tcpHdr header.TCP
		if tcpip.TransportProtocolNumber(ipHdr.NextHeader()) == header.TCPProtocolNumber {
			tcpHdr = header.TCP(h[header.IPv6FixedHeaderSize:][:tcpSrcDstPortLen])
		} else {
			// Slow path for IPv6 extension headers :(.
			dataBuf := pkt.Data().ToBuffer()
			dataBuf.TrimFront(header.IPv6MinimumSize)
			it := header.MakeIPv6PayloadIterator(header.IPv6ExtensionHeaderIdentifier(ipHdr.NextHeader()), dataBuf)
			defer it.Release()
			for {
				hdr, done, err := it.Next()
				if done || err != nil {
					break
				}
				if hdr != nil {
					hdr.Release()
				} // todo: else, break?
			}
			h, ok = pkt.Data().PullUp(int(it.HeaderOffset()) + tcpSrcDstPortLen)
			if !ok {
				return tup, true
			}
			tcpHdr = header.TCP(h[it.HeaderOffset():][:tcpSrcDstPortLen])
		}
		tup.srcAddr = ipHdr.SourceAddressSlice()
		tup.dstAddr = ipHdr.DestinationAddressSlice()
		tup.srcPort = tcpHdr.SourcePort()
		tup.dstPort = tcpHdr.DestinationPort()
		tup.proto = header.IPv6ProtocolNumber
	default:
		return tup, true
	}
	return tup, false
}

type processor struct {
	mu sync.Mutex
	// +checklocks:mu
	pkts stack.PacketBufferList

	e           *endpoint
	sleeper     sleep.Sleeper
	packetWaker sleep.Waker
	closeWaker  sleep.Waker
}

func (p *processor) start(wg *sync.WaitGroup) {
	// TODO: core.RecoverFn(supervisor.stop)
	defer core.RecoverFn("n.forwaders.start", p.e.notifyRestart)

	defer wg.Done()
	defer p.sleeper.Done()
	for {
		switch w := p.sleeper.Fetch(true); {
		case w == &p.packetWaker:
			p.deliverPackets()
		case w == &p.closeWaker:
			// must unlock via deferred since panics are recovered above
			p.mu.Lock()
			defer p.mu.Unlock()
			p.pkts.Reset()
			return
		}
	}
}

func (p *processor) deliverPackets() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for p.pkts.Len() > 0 {
		pkt := p.pkts.PopFront()
		p.mu.Unlock()
		if pkt != nil {
			p.e.InjectInbound(pkt.NetworkProtocolNumber, pkt)
			pkt.DecRef()
		}
		p.mu.Lock()
	}
}

// supervisor handles starting, closing, and queuing packets on processor
// goroutines.
type supervisor struct {
	processors []processor
	seed       uint32
	wg         sync.WaitGroup
	e          *endpoint
	ready      []bool
}

// newSupervisor creates a new supervisor for the processors of endpoint e.
func newSupervisor(e *endpoint) *supervisor {
	m := &supervisor{
		seed:       rand.Uint32(),
		e:          e,
		ready:      make([]bool, maxForwarders),
		processors: make([]processor, maxForwarders),
		wg:         sync.WaitGroup{},
	}

	m.wg.Add(maxForwarders)

	for i := range m.processors {
		p := &m.processors[i]
		p.sleeper.AddWaker(&p.packetWaker)
		p.sleeper.AddWaker(&p.closeWaker)
		p.e = e
	}

	return m
}

// start starts the processor goroutines if the processor manager is configured
// with more than one processor.
func (m *supervisor) start() {
	if settings.Debug {
		log.D("ns: tun(%d): forwarder: starting %d procs %d", m.e.fd(), len(m.processors), m.seed)
	}
	if m.canDeliverInline() {
		return
	}
	for i := range m.processors {
		p := &m.processors[i]
		go p.start(&m.wg)
	}
}

// id returns a hash value based on the given five tuple.
// Will return 0 if the hash could not be computed.
func (m *supervisor) id(t *fiveTuple) uint32 {
	if t == nil { // never nil, but nilaway complains.
		return 0
	}
	var payload [4]byte
	binary.LittleEndian.PutUint16(payload[0:], t.srcPort)
	binary.LittleEndian.PutUint16(payload[2:], t.dstPort)

	h := jenkins.Sum32(m.seed)
	if _, err := h.Write(payload[:]); err != nil {
		return 0
	}
	if len(t.srcAddr) > 0 {
		if _, err := h.Write(t.srcAddr); err != nil {
			return 0
		}
	} // else: should never happen
	if len(t.dstAddr) > 0 {
		if _, err := h.Write(t.dstAddr); err != nil {
			return 0
		}
	} // else: should never happen
	return h.Sum32()
}

// queuePacket queues a packet to be delivered to the appropriate processor.
func (m *supervisor) queuePacket(pkt *stack.PacketBuffer, hasEthHeader bool) {
	fd := m.e.fd()
	sz := uint32(len(m.processors))
	var pIdx uint32
	tup, nonConnectionPkt := tcpipConnectionID(pkt)
	if !hasEthHeader {
		if nonConnectionPkt {
			log.D("ns: tun(%d): forwarder: drop non-connection pkt (sz: %d)", fd, pkt.Size())
			// If there's no eth header this should be a standard tcpip packet. If
			// it isn't the packet is invalid so drop it.
			return
		}
		pkt.NetworkProtocolNumber = tup.proto
	}
	if m.canDeliverInline() || nonConnectionPkt {
		// If the packet is not associated with an active connection, use the
		// first processor.
		pIdx = 0
	} else {
		pIdx = m.id(&tup) % sz
	}
	// despite uint32, pIdx goes negative? github.com/celzero/firestack/issues/59
	// https://go.dev/ref/spec#Integer_overflow?
	if pIdx > sz {
		log.W("ns: tun(%d): forwarder: invalid processor index %d, %s", fd, pIdx, tup)
		pIdx = 0
	}
	p := &m.processors[pIdx]

	if settings.Debug {
		log.VV("ns: tun(%d): forwarder: q on proc %d, %s", fd, pIdx, tup)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	pkt.IncRef()
	p.pkts.PushBack(pkt) // enqueue.
	m.ready[pIdx] = true // ready to deliver enqueued packets.
}

func (m *supervisor) stop() {
	if settings.Debug {
		log.D("ns: tun(%d): forwarder: stopping %d procs", m.e.fd(), len(m.processors))
	}
	if m.canDeliverInline() {
		return
	}
	for i := range m.processors {
		p := &m.processors[i]
		p.closeWaker.Assert()
	}
}

// wakeReady wakes up all processors that have a packet queued. If there is only
// one processor, the method delivers the packet inline without waking a
// goroutine.
func (m *supervisor) wakeReady() {
	for i, ready := range m.ready {
		if !ready {
			continue
		}
		p := &m.processors[i]
		if m.canDeliverInline() {
			p.deliverPackets()
		} else {
			p.packetWaker.Assert()
		}
		m.ready[i] = false
	}
}

// canDeliverInline returns true if the supervisor is configured to deliver
// packets inline. That is, when only one processor is active, deliver
// packets inline. sleeper/waker are no-ops.
func (m *supervisor) canDeliverInline() bool {
	return len(m.processors) <= 1
}
