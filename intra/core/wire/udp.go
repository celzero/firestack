// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     SPDX-License-Identifier: BSD-3-Clause
//     Copyright (c) Tailscale Inc & AUTHORS

package wire

import (
	"encoding/binary"
)

// udpHeaderLength is the size of the UDP packet header, not including
// the outer IP header.
const udpHeaderLength = 8

// UDP4Header is an IPv4+UDP header.
type UDP4Header struct {
	IP4Header
	SrcPort uint16
	DstPort uint16
}

// Len implements Header.
func (h UDP4Header) Len() int {
	return h.IP4Header.Len() + udpHeaderLength
}

// Marshal implements Header.
func (h UDP4Header) Marshal(buf []byte) error {
	if len(buf) < h.Len() {
		return errSmallBuffer
	}
	if len(buf) > maxPacketLength {
		return errLargePacket
	}
	// The caller does not need to set this.
	h.IPProto = UDP

	length := len(buf) - h.IP4Header.Len()
	binary.BigEndian.PutUint16(buf[20:22], h.SrcPort)
	binary.BigEndian.PutUint16(buf[22:24], h.DstPort)
	binary.BigEndian.PutUint16(buf[24:26], uint16(length))
	binary.BigEndian.PutUint16(buf[26:28], 0) // blank checksum

	// UDP checksum with IP pseudo header.
	h.IP4Header.marshalPseudo(buf)
	binary.BigEndian.PutUint16(buf[26:28], ip4Checksum(buf[ip4PseudoHeaderOffset:]))

	h.IP4Header.Marshal(buf)

	return nil
}

// ToResponse implements Header.
func (h *UDP4Header) ToResponse() {
	h.SrcPort, h.DstPort = h.DstPort, h.SrcPort
	h.IP4Header.ToResponse()
}

// UDP6Header is an IPv6+UDP header.
type UDP6Header struct {
	IP6Header
	SrcPort uint16
	DstPort uint16
}

// Len implements Header.
func (h UDP6Header) Len() int {
	return h.IP6Header.Len() + udpHeaderLength
}

// Marshal implements Header.
func (h UDP6Header) Marshal(buf []byte) error {
	if len(buf) < h.Len() {
		return errSmallBuffer
	}
	if len(buf) > maxPacketLength {
		return errLargePacket
	}
	// The caller does not need to set this.
	h.IPProto = UDP

	length := len(buf) - h.IP6Header.Len()
	binary.BigEndian.PutUint16(buf[40:42], h.SrcPort)
	binary.BigEndian.PutUint16(buf[42:44], h.DstPort)
	binary.BigEndian.PutUint16(buf[44:46], uint16(length))
	binary.BigEndian.PutUint16(buf[46:48], 0) // blank checksum

	// UDP checksum with IP pseudo header.
	h.IP6Header.marshalPseudo(buf, UDP)
	binary.BigEndian.PutUint16(buf[46:48], ip4Checksum(buf[:]))

	h.IP6Header.Marshal(buf)

	return nil
}

// ToResponse implements Header.
func (h *UDP6Header) ToResponse() {
	h.SrcPort, h.DstPort = h.DstPort, h.SrcPort
	h.IP6Header.ToResponse()
}
