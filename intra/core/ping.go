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
	mrand "math/rand"
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
	padlen           = 0
	ttl              = 64
	timeout          = 3 * time.Second
	protocolICMP     = 1
	protocolIPv6ICMP = 58
)

// from: github.com/go-ping/ping/blob/caaf2b72ea5/ping.go
func Ping(c net.PacketConn, ipp netip.AddrPort) (ok bool, rtt time.Duration, err error) {
	v4 := ipp.Addr().Is4()
	err = setttl(c, v4)
	if err != nil {
		log.D("core: icmp: setttl failed: %v", err)
	}
	dst := net.UDPAddrFromAddrPort(ipp)
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
	msgid := mrand.Intn(65535)
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
	var n int
	var from net.Addr
	pkt, err = msg.Marshal(nil)
	if err != nil {
		return
	}

	n, err = c.WriteTo(pkt, dst)
	log.D("core: icmp: egress: write(=> %v) ping; done %d/%d; err? %v",
		ipp, n, len(pkt), err)
	if err != nil {
		return
	}
	extend(c)
	n, from, err = c.ReadFrom(pkt)
	log.D("core: icmp: ingress: read(<= %v / %v) ping done; done %d; err? %v",
		ipp, from, n, err)
	if err != nil {
		return
	}

	var m *icmp.Message
	if m, err = icmp.ParseMessage(proto, pkt[:n]); err != nil {
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
		// if reply.ID != msgid {
		// return fmt.Errorf("icmp: reply from [%v/%v] id %d; want %d",
		// ipp, from, reply.ID, msgid)
		// }

		if len(reply.Data) < len(data) {
			err = fmt.Errorf("icmp: insufficient reply data; %d != %d", len(reply.Data), len(data))
			return
		}

		start := bytesToTime(reply.Data[:tslen])
		rtt = end.Sub(start)
		ok = true
	default:
		err = fmt.Errorf("icmp: err reply type: '%T' '%v'", pkt, pkt)
	}
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
	case *net.UDPConn:
		return
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
	default:
		return
	}
	if raw4 != nil {
		err1 := raw4.SetControlMessage(ipv4.FlagTTL, true)
		err2 := raw4.SetTTL(ttl)
		err = errors.Join(err1, err2)
	} else if raw6 != nil {
		err1 := raw6.SetControlMessage(ipv6.FlagHopLimit, true)
		err2 := raw6.SetHopLimit(ttl)
		err = errors.Join(err1, err2)
	}
	return
}

func extend(c MinConn) {
	if c != nil {
		_ = c.SetDeadline(time.Now().Add(timeout))
	}
}

func payload() (t []byte, tslen int, err error) {
	randomPayload := make([]byte, 16)
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
