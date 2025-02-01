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

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/ipn"
)

// SocketSummary reports information about each TCP socket
// or a non-DNS UDP association, or ICMP echo when it is closed.
type SocketSummary struct {
	Proto    string    // tcp, udp, icmp, etc.
	ID       string    // Unique ID for this socket.
	PID      string    // Proxy ID that handled this socket.
	RPID     string    // Relay Proxy ID that tunneled PID.
	UID      string    // UID of the app that owns this socket (sans ICMP).
	Target   string    // Remote IP, if dialed in.
	Rx       int64     // Total bytes downloaded.
	Tx       int64     // Total bytes uploaded.
	Duration int32     // Duration in seconds.
	start    time.Time // Tracks start time; unexported.
	Rtt      int32     // Round-trip time (millis).
	Msg      string    // Err or other messages, if any.
}

type SocketListener interface {
	// Preflow is called before a new connection is established; return owner "uid", which is
	// later used by dnsx.Resolver to determine the DNS transport to use for that "uid". That
	// DNS transport will re-resolve "domains" (iff previously resolved to a "fake IP" by
	// dnsx.alg) to determine the real egress IP to connect to.
	Preflow(protocol, uid int32, src, dst, domains string) *PreMark
	// Flow is called on a new connection; return Proxy IDs to forward the connection
	// to a pre-registered proxy; "Base" or "Exit" to allow the connection; "Block" to block it.
	// "connid" is used to uniquely identify a connection across all proxies, and a summary of the
	// connection is sent back to a pre-registered listener.
	// protocol is 6 for TCP, 17 for UDP, 1 for ICMP.
	// uid is -1 in case owner-uid of the connection couldn't be determined.
	// src and dst are string'd representation of net.TCPAddr and net.UDPAddr.
	// origdsts is a comma-separated list of original source IPs, this may be same as dst.
	// domains is a comma-separated list of domain names associated with origdsts, if any.
	// probableDomains is a comma-separated list of probable domain names associated with origdsts, if any.
	// blocklists is a comma-separated list of rdns blocklist names that apply, if any.
	Flow(protocol, uid int32, src, dst, origdsts, domains, probableDomains, blocklists string) *Mark
	Inflow(protocol, uid int32, src, dst string) *Mark
	// OnSocketClosed reports summary after a socket closes.
	OnSocketClosed(*SocketSummary)
}

type PreMark struct {
	// UID of the app which owns the flow.
	UID string
}

type Mark struct {
	// PIDCSV is a list of proxies to forward the flow over.
	PIDCSV string
	// CID uniquely identifies the flow.
	CID string
	// UID of the app which owns the flow.
	UID string
}

const (
	ProtoTypeUDP  = "udp"
	ProtoTypeTCP  = "tcp"
	ProtoTypeICMP = "icmp"
)

var (
	optionsBlock = &Mark{PIDCSV: ipn.Block}
	optionsExit  = &Mark{PIDCSV: ipn.Exit}

	errNone = errors.New("no error")
)

func icmpSummary(id, uid string) *SocketSummary {
	return &SocketSummary{
		Proto: ProtoTypeICMP,
		ID:    id,
		UID:   uid,
		start: time.Now(),
		Msg:   errNone.Error(),
	}
}

func tcpSummary(id, uid string, dst netip.Addr) *SocketSummary {
	return &SocketSummary{
		Proto:  ProtoTypeTCP,
		ID:     id,
		UID:    uid,
		Target: dst.String(),
		start:  time.Now(),
		Msg:    errNone.Error(),
	}
}

func udpSummary(id, uid string, dst netip.Addr) *SocketSummary {
	s := tcpSummary(id, uid, dst)
	s.Proto = ProtoTypeUDP
	return s
}

// String implements fmt.Stringer.
func (s *SocketSummary) String() string {
	if s != nil {
		return fmt.Sprintf("socket-summary: id=%s pid=%s uid=%s down=%d up=%d dur=%d synack=%d msg=%s",
			s.ID, s.PID, s.UID, s.Rx, s.Tx, s.Duration, s.Rtt, s.Msg)
	}
	return "<nil>"
}

func (s *SocketSummary) elapsed() {
	if s != nil {
		s.Duration = int32(time.Since(s.start).Seconds())
	}
}

func (s *SocketSummary) done(errs ...error) *SocketSummary {
	if s == nil {
		return nil
	}

	defer func() {
		if len(s.Msg) <= 0 {
			s.Msg = errNone.Error()
		}
	}()

	s.elapsed()

	if len(errs) <= 0 {
		return s
	}

	err := core.JoinErr(errs...) // errs may be nil
	if err != nil {
		if s.Msg == errNone.Error() {
			s.Msg = err.Error()
		} else {
			s.Msg = s.Msg + "; " + err.Error()
		}
	}
	return s
}
