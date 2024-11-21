// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package wg

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/celzero/firestack/intra/log"
	"golang.zx2c4.com/wireguard/device"
)

// https://github.com/amnezia-vpn/amneziawg-go/pull/2/files

const (
	sNoop = 0 // no-op size
)

// Jc (Junk packet count) - number of packets with random data that are sent before the start of the session
// Jmin (Junk packet minimum size) - minimum packet size for Junk packet. That is, all randomly generated packets will have a size no smaller than Jmin.
// Jmax (Junk packet maximum size) - maximum size for Junk packets
// S1 (Init packet junk size) - the size of random data that will be added to the init packet, the size of which is initially fixed.
// S2 (Response packet junk size) - the size of random data that will be added to the response packet, the size of which is initially fixed.
// H1 (Init packet magic header) - the header of the first byte of the handshake
// H2 (Response packet magic header) - header of the first byte of the handshake response
// H4 (Transport packet magic header) - header of the packet of the data packet
// H3 (Underload packet magic header) - UnderLoad packet header."
type Amnezia struct {
	id string

	Jc, Jmin, Jmax uint16 // unused: junk packet count, min, max

	S1, S2         uint16 // handshake init/resp pkt sizes
	H1, H2, H3, H4 uint32 // modified msg types [4]byte
}

func NewAmnezia(id string) *Amnezia {
	return &Amnezia{
		id: id,
	}
}

func (a *Amnezia) String() string {
	if a == nil {
		return "<nil>"
	}
	if !a.Set() {
		return "<unset>"
	}
	return fmt.Sprintf("%s: amnezia: jc(%d), jmin(%d), jmax(%d), s1(%d), s2(%d), h1(%d), h2(%d), h3(%d), h4(%d)",
		a.id, a.Jc, a.Jmin, a.Jmax, a.S1, a.S2, a.H1, a.H2, a.H3, a.H4)
}

func (a *Amnezia) Set() bool {
	if a == nil {
		return false
	}

	return a.S1 > 0 || a.S2 > 0 || a.H1 > 0 || a.H2 > 0 || a.H3 > 0 || a.H4 > 0
}

func (a *Amnezia) Same(b *Amnezia) bool {
	if a == nil && b == nil {
		return false
	} else if a == nil || b == nil {
		return false
	}

	return a.S1 == b.S1 &&
		a.S2 == b.S2 &&
		a.H1 == b.H1 &&
		a.H2 == b.H2 &&
		a.H3 == b.H3 &&
		a.H4 == b.H4
}

func (a *Amnezia) send(pktptr *[]byte) (ok bool) {
	if a == nil || !a.Set() {
		return
	}

	pkt := *pktptr

	n := len(pkt)
	if n < device.MinMessageSize {
		return
	}

	h := uint16(device.MessageTransportOffsetReceiver)
	typ := binary.LittleEndian.Uint32(pkt[:h])

	defer a.logIfNeeded("send", typ, n)

	*pktptr, _ = a.instate(pkt)
	return true
}

func (a *Amnezia) recv(pktptr *[]byte) (ok bool) {
	if a == nil || !a.Set() {
		return
	}

	var typ uint32
	pkt := *pktptr

	if len(pkt) < device.MinMessageSize {
		return
	}
	h := uint16(device.MessageTransportOffsetReceiver)

	pkt, typ = a.strip(pkt)

	switch typ {
	case device.MessageInitiationType, a.H1:
		typ = device.MessageInitiationType
		binary.LittleEndian.PutUint32(pkt[:h], device.MessageInitiationType)
	case device.MessageResponseType, a.H2:
		typ = device.MessageResponseType
		binary.LittleEndian.PutUint32(pkt[:h], device.MessageResponseType)
	case device.MessageCookieReplyType, a.H3:
		typ = device.MessageCookieReplyType
		binary.LittleEndian.PutUint32(pkt[:h], device.MessageCookieReplyType)
	case device.MessageTransportType, a.H4: // must be default?
		typ = device.MessageTransportType
		binary.LittleEndian.PutUint32(pkt[:h], device.MessageTransportType)
	}

	defer a.logIfNeeded("recv", typ, len(pkt))

	*pktptr = pkt
	return true
}

func (a *Amnezia) instate(pkt []byte) ([]byte, uint32) {
	n := len(pkt)

	h := uint16(device.MessageTransportOffsetReceiver)
	defaultType := binary.LittleEndian.Uint32(pkt[:h])

	var pad uint16 = 0
	var obsType uint32 = 0
	maybeInstate := false

	switch defaultType {
	case device.MessageInitiationType:
		if n == device.MessageInitiationSize {
			// github.com/amnezia-vpn/amneziawg-go/blob/2e3f7d122c/device/send.go#L130
			pad = a.S1
			obsType = a.H1
			maybeInstate = obsType > 0
		}
	case device.MessageResponseType:
		if n == device.MessageResponseSize {
			// github.com/amnezia-vpn/amneziawg-go/blob/2e3f7d122c/device/send.go#L198
			pad = a.S2
			obsType = a.H2
			maybeInstate = obsType > 0
		}
	case device.MessageCookieReplyType:
		if n == device.MessageCookieReplySize {
			pad = sNoop
			obsType = a.H3
			maybeInstate = obsType > 0
		}
	case device.MessageTransportType:
		if n >= device.MinMessageSize {
			pad = sNoop
			obsType = a.H4
			maybeInstate = obsType > 0
		}
	}

	if maybeInstate {
		random, err := blob(pad) // pad may be 0
		if err != nil {          // unlikely
			log.E("wg: %s: amnezia: instate: %v", a.id, err)
			return pkt, defaultType
		}
		binary.LittleEndian.PutUint32(pkt[:h], obsType)
		if len(random) <= 0 {
			return pkt, obsType
		} else {
			return append(random, pkt...), obsType
		}
	}

	return pkt, defaultType
}

func (a *Amnezia) strip(pkt []byte) ([]byte, uint32) {
	size := uint16(len(pkt))
	h := uint16(device.MessageTransportOffsetReceiver)
	// assume the correct msg type is in just the first byte:
	// github.com/WireGuard/wireguard-go/blob/12269c2761/device/noise-protocol.go#L56
	defaultType := uint8(pkt[0])

	var discard uint16 = 0
	var possibleType uint32 = 0
	maybeStrip := false

	// ref: https://github.com/amnezia-vpn/amneziawg-go/blob/2e3f7d122c/device/device.go#L765
	if size == a.S1+device.MessageInitiationSize {
		discard = a.S1
		possibleType = a.H1
		maybeStrip = true
	} else if size == a.S2+device.MessageResponseSize {
		discard = a.S2
		possibleType = a.H2
		maybeStrip = true
	} // else: default

	if maybeStrip {
		hdr := pkt[discard : discard+h]
		obsType := binary.LittleEndian.Uint32(hdr)
		if obsType == possibleType {
			return pkt[discard:], obsType
		} // else: msg type mismatch, but size matched
	} // else: nothing to discard

	return pkt, uint32(defaultType)
}

func (a *Amnezia) logIfNeeded(dir string, typ uint32, n int) {
	switch typ {
	case device.MessageInitiationType:
		notok := n != device.MessageInitiationSize
		logif(notok)("wg: %s: amnezia: %s: err initiation %d != %d",
			a.id, dir, n, device.MessageInitiationSize)
	case device.MessageResponseType:
		notok := n != device.MessageResponseSize
		logif(notok)("wg: %s: amnezia: %s: err response %d != %d",
			a.id, dir, n, device.MessageResponseSize)
	case device.MessageCookieReplyType:
		notok := n != device.MessageCookieReplySize
		logif(notok)("wg: %s: amnezia: %s: err cookie %d != %d",
			a.id, dir, n, device.MessageCookieReplySize)
	case device.MessageTransportType:
		notok := n < device.MinMessageSize
		logif(notok)("wg: %s: amnezia: %s: err data %d < %d",
			a.id, dir, n, device.MinMessageSize)
	default:
		log.W("wg: %s: amnezia: %s: unexpected type %d; sz(pkt): %d",
			a.id, dir, typ, n)
	}
}

// ref: github.com/amnezia-vpn/amneziawg-go/blob/2e3f7d122c/device/util.go#L1
func blob(sz uint16) ([]byte, error) {
	if sz == 0 {
		return nil, nil
	}

	junk := make([]byte, sz)
	n, err := rand.Read(junk)
	return junk[:n], err
}
