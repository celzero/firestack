// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package intra

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/celzero/firestack/intra/ipn"
)

// SocketSummary reports information about each TCP socket
// or a non-DNS UDP association, or ICMP echo when it is closed.
type SocketSummary struct {
	Proto    string    // tcp, udp, icmp, etc.
	ID       string    // Unique ID for this socket.
	PID      string    // Proxy ID that handled this socket.
	UID      string    // UID of the app that owns this socket (sans ICMP).
	Target   string    // Remote IP, if dialed in.
	Rx       int64     // Total bytes downloaded (sans ICMP).
	Tx       int64     // Total bytes uploaded (sans ICMP).
	Duration int32     // Duration in seconds.
	start    time.Time // Tracks start time; unexported.
	Rtt      int32     // Round-trip time (ms); (sans ICMP).
	Msg      string    // Err or other messages, if any.
}

type SocketListener interface {
	// Flow is called on a new connection; return "proxyid,connid" to forward the connection
	// to a pre-registered proxy; "Base" to allow the connection; "Block" to block the connection.
	// "connid" is used to uniquely identify a connection across all proxies, and a summary of the
	// connection is sent back to a pre-registered listener.
	// protocol is 6 for TCP, 17 for UDP, 1 for ICMP.
	// uid is -1 in case owner-uid of the connection couldn't be determined.
	// src and dst are string'd representation of net.TCPAddr and net.UDPAddr.
	// origdsts is a comma-separated list of original source IPs, this may be same as dst.
	// domains is a comma-separated list of domain names associated with origsrcs, if any.
	// probableDomains is a comma-separated list of probable domain names associated with origsrcs, if any.
	// blocklists is a comma-separated list of blocklist names, if any.
	Flow(protocol int32, uid int, src, dst, origdsts, domains, probableDomains, blocklists string) *Mark
	// OnSocketClosed reports summary after a socket closes.
	OnSocketClosed(*SocketSummary)
}

type Mark struct {
	PID string // PID of the proxy to forward the socket over.
	CID string // CID identifies this socket.
	UID string // UID of the app which owns this socket.
}

const (
	ProtoTypeUDP  = "udp"
	ProtoTypeTCP  = "tcp"
	ProtoTypeICMP = "icmp"
)

var (
	optionsBlock = &Mark{PID: ipn.Block}
	optionsBase  = &Mark{PID: ipn.Base}

	errNone = errors.New("no error")
)

func icmpSummary(id, pid string) *SocketSummary {
	return &SocketSummary{
		Proto: ProtoTypeICMP,
		ID:    id,
		PID:   pid,
		start: time.Now(),
		Msg:   errNone.Error(),
	}
}

func tcpSummary(id, pid, uid string, dst netip.Addr) *SocketSummary {
	return &SocketSummary{
		Proto:  ProtoTypeTCP,
		ID:     id,
		PID:    pid,
		UID:    uid,
		Target: dst.String(),
		start:  time.Now(),
		Msg:    errNone.Error(),
	}
}

func udpSummary(id, pid, uid string, dst netip.Addr) *SocketSummary {
	s := tcpSummary(id, pid, uid, dst)
	s.Proto = ProtoTypeUDP
	return s
}

func (s *SocketSummary) str() string {
	return fmt.Sprintf("socket-summary: id=%s pid=%s uid=%s down=%d up=%d dur=%d synack=%d msg=%s",
		s.ID, s.PID, s.UID, s.Rx, s.Tx, s.Duration, s.Rtt, s.Msg)
}

func (s *SocketSummary) elapsed() {
	s.Duration = int32(time.Since(s.start).Seconds())
}

func (s *SocketSummary) done(errs ...error) {
	defer func() {
		if len(s.Msg) <= 0 {
			s.Msg = errNone.Error()
		}
	}()

	s.elapsed()

	if len(errs) <= 0 {
		return
	}

	err := errors.Join(errs...) // errs may be nil
	if err != nil {
		if s.Msg == errNone.Error() {
			s.Msg = err.Error()
		} else {
			s.Msg = s.Msg + "; " + err.Error()
		}
	}
}
