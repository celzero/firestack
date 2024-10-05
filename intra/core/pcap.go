// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"encoding"
	"encoding/binary"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// from: github.com/google/gvisor/blob/596e8d22/pkg/tcpip/link/sniffer/pcap.go

type PcapHeader struct {
	MagicNumber  uint32
	VersionMajor uint16
	VersionMinor uint16
	Thiszone     int32
	Sigfigs      uint32
	Snaplen      uint32
	Network      uint32
}

type PcapPacket struct {
	Timestamp     time.Time
	Packet        *stack.PacketBuffer
	MaxCaptureLen int
}

var _ encoding.BinaryMarshaler = (*PcapPacket)(nil)

func (p *PcapPacket) MarshalBinary() ([]byte, error) {
	pkt := TrimmedClone(p.Packet)
	defer pkt.DecRef()
	packetSize := pkt.Size()
	captureLen := p.MaxCaptureLen
	if packetSize < captureLen {
		captureLen = packetSize
	}
	b := make([]byte, 16+captureLen)
	binary.LittleEndian.PutUint32(b[0:4], uint32(p.Timestamp.Unix()))
	binary.LittleEndian.PutUint32(b[4:8], uint32(p.Timestamp.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(b[8:12], uint32(captureLen))
	binary.LittleEndian.PutUint32(b[12:16], uint32(packetSize))
	w := tcpip.SliceWriter(b[16:])
	for _, v := range pkt.AsSlices() {
		if captureLen == 0 {
			break
		}
		if len(v) > captureLen {
			v = v[:captureLen]
		}
		n, err := w.Write(v)
		if err != nil {
			panic(err)
		}
		captureLen -= n
	}
	return b, nil
}

// trimmedClone clones the packet buffer to not modify the original. It trims
// anything before the network header.
func TrimmedClone(pkt *stack.PacketBuffer) *stack.PacketBuffer {
	// We don't clone the original packet buffer so that the new packet buffer
	// does not have any of its headers set.
	//
	// We trim the link headers from the cloned buffer as the sniffer doesn't
	// handle link headers.
	buf := pkt.ToBuffer()
	buf.TrimFront(int64(len(pkt.VirtioNetHeader().Slice())))
	buf.TrimFront(int64(len(pkt.LinkHeader().Slice())))
	return stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buf})
}
