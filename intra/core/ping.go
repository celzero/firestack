// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"time"

	"github.com/celzero/firestack/intra/log"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var errNotICMPEchoReply = errors.New("icmp: expecting echo reply")

const (
	payloadSize      = 16 // bytes
	padlen           = 0  // bytes
	ttl              = 64
	timeout          = 3 * time.Second
	protocolICMP     = 1
	protocolIPv6ICMP = 58
)

// from: github.com/go-ping/ping/blob/caaf2b72ea5/ping.go
func Ping(pc net.PacketConn, ipp netip.AddrPort) (ok bool, rtt time.Duration, err error) {
	v4 := ipp.Addr().Is4()
	seq := 1 // todo: seq?
	var typ icmp.Type = ipv4.ICMPTypeEcho
	if !v4 {
		typ = ipv6.ICMPTypeEchoRequest
	}
	proto := protocolICMP
	if !v4 {
		proto = protocolIPv6ICMP
	}

	var tslen int
	var data []byte
	data, tslen, err = payload()
	if err != nil {
		return
	}
	msgid := mrand.IntN(65535)
	msg := &icmp.Message{
		Type: typ,
		Code: 0,
		Body: &icmp.Echo{
			ID:   msgid,
			Seq:  seq,
			Data: data,
		},
	}
	var pkt []byte
	pkt, err = msg.Marshal(nil)
	if err != nil {
		return
	}

	pkt, _, err = Echo(pc, pkt, net.UDPAddrFromAddrPort(ipp), v4)

	if err != nil {
		return
	}

	var m *icmp.Message
	if m, err = icmp.ParseMessage(proto, pkt); err != nil {
		return
	}

	if m.Type != ipv4.ICMPTypeEchoReply && m.Type != ipv6.ICMPTypeEchoReply {
		err = errNotICMPEchoReply
		return
	}

	end := time.Now()
	switch reply := m.Body.(type) {
	case *icmp.Echo:
		// IDs will never match for userspace icmp
		// github.com/go-ping/ping/blob/caaf2b72e/utils_linux.go#L13
		// github.com/tailscale/tailscale/blob/43138c7a5c/cmd/stunstamp/stunstamp_linux.go#L77
		// if reply.ID != msgid {
		// return fmt.Errorf("icmp: reply from [%v/%v] id %d; want %d",
		// ipp, from, reply.ID, msgid)
		// }

		if len(reply.Data) < len(data) {
			err = fmt.Errorf("icmp: insufficient reply data; %d != %d", len(reply.Data), len(data))
			return
		}

		start := bytesToTime(reply.Data[:tslen])
		// TODO: ref kernel timestamping
		// github.com/tailscale/tailscale/blob/43138c7a5c/cmd/stunstamp/stunstamp_linux.go#L279
		rtt = end.Sub(start)
		ok = true
	default:
		err = fmt.Errorf("icmp: err reply type: '%T' '%v'", pkt, pkt)
	}
	return
}

func Echo(pc net.PacketConn, pkt []byte, dst net.Addr, v4 bool) (reply []byte, from net.Addr, err error) {
	var n int

	if ttlerr := setttl(pc, v4); ttlerr != nil {
		log.D("core: icmp: setttl failed: %v", ttlerr)
	}

	n, err = pc.WriteTo(pkt, dst)
	log.D("core: icmp: egress: write(=> %v) ping; done %d/%d; err? %v",
		dst, n, len(pkt), err)
	if err != nil {
		// TODO: unreachable reply?
		return
	}

	extend(pc)
	n, from, err = pc.ReadFrom(pkt)
	reply = pkt[:n] // trunc

	log.D("core: icmp: ingress: read(<= %v / %v) ping done; done %d; err? %v",
		dst, from, n, err)
	// TODO: on err, unreachable reply?
	return
}

func timeToBytes(t time.Time) []byte {
	nsec := t.UnixNano()
	b := make([]byte, 8)
	for i := uint8(0); i < 8; i++ {
		b[i] = byte((nsec >> ((7 - i) * 8)) & 0xff)
	}
	return b
}

func bytesToTime(b []byte) time.Time {
	var nsec int64
	for i := uint8(0); i < 8; i++ {
		nsec += int64(b[i]) << ((7 - i) * 8)
	}
	return time.Unix(nsec/1000000000, nsec%1000000000)
}

func setttl(c MinConn, v4 bool) (err error) {
	var raw4 *ipv4.PacketConn
	var raw6 *ipv6.PacketConn
	switch x := c.(type) {
	case *icmp.PacketConn:
		if v4 {
			raw4 = x.IPv4PacketConn()
		} else {
			raw6 = x.IPv6PacketConn()
		}
	case *ipv4.PacketConn:
		raw4 = x
	case *ipv6.PacketConn:
		raw6 = x
	case net.PacketConn:
		if v4 {
			raw4 = ipv4.NewPacketConn(x)
		} else {
			raw6 = ipv6.NewPacketConn(x)
		}
	default:
		return
	}
	if raw4 != nil {
		err1 := raw4.SetControlMessage(ipv4.FlagTTL, true)
		err2 := raw4.SetTTL(ttl)
		err = JoinErr(err1, err2)
	} else if raw6 != nil {
		err1 := raw6.SetControlMessage(ipv6.FlagHopLimit, true)
		err2 := raw6.SetHopLimit(ttl)
		err = JoinErr(err1, err2)
	}
	return
}

func extend(c MinConn) {
	if c != nil {
		_ = c.SetDeadline(time.Now().Add(timeout))
	}
}

func cleardeadline(c MinConn) {
	if c != nil {
		_ = c.SetDeadline(time.Time{})
	}
}

func payload() (t []byte, tslen int, err error) {
	randomPayload := make([]byte, payloadSize)
	_, err = rand.Read(randomPayload[:])
	if err != nil {
		return
	}
	ts := timeToBytes(time.Now())
	tslen = len(ts)
	t = append(ts, randomPayload...)
	if padlen > 0 {
		t = append(t, bytes.Repeat([]byte{1}, padlen)...)
	}
	return
}
