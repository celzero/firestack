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
	"encoding/hex"
	"net/netip"
	"testing"
)

func TestParsedDecodeICMPv6EchoRequest(t *testing.T) {
	// IPv6 ICMP echo request packet (no fragmentation, truncated)
	hexpkt := "600eb68300403a40fd66f83ac65000000000000000000001260647000000000000000000681084e58000c964116c0002832a586900000000f15b030000000000101112131415161718191a1b1c1d1e1f"

	pkt, err := hex.DecodeString(hexpkt)
	if err != nil {
		t.Fatalf("hex decode failed: %v", err)
	}

	expectedLen := int(binary.BigEndian.Uint16(pkt[4:6])) + IP6HeaderLength
	if len(pkt) < expectedLen {
		pkt = append(pkt, make([]byte, expectedLen-len(pkt))...)
	}

	var p Parsed
	p.DecodeTrunc(pkt, true)

	if p.IPVersion != Version6 {
		t.Fatalf("IPVersion got %d, want %d", p.IPVersion, Version6)
	}
	if p.IPProto != ICMPv6 {
		t.Fatalf("IPProto got %v, want %v", p.IPProto, ICMPv6)
	}

	wantSrc := netip.MustParseAddr("fd66:f83a:c650::1")
	wantDst := netip.MustParseAddr("2606:4700::6810:84e5")

	if p.Src.Addr() != wantSrc {
		t.Fatalf("Src got %v, want %v", p.Src.Addr(), wantSrc)
	}
	if p.Dst.Addr() != wantDst {
		t.Fatalf("Dst got %v, want %v", p.Dst.Addr(), wantDst)
	}
	if p.Src.Port() != 0 || p.Dst.Port() != 0 {
		t.Fatalf("expected zero ports for ICMPv6, got src=%d dst=%d", p.Src.Port(), p.Dst.Port())
	}

	if !p.IsEchoRequest() {
		t.Fatalf("expected packet to be ICMPv6 echo request")
	}
	t.Log(p.ICMPHeaderString())
}
