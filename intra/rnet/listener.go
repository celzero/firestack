// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package rnet

import (
	"errors"
	"fmt"
	"time"
)

var errNop = errors.New("no error")

// Summary is a summary of a DNS transaction, reported when it is complete.
type ServerSummary struct {
	Type     string    // http1, socks5, etc.
	SID      string    // Server id
	PID      string    // Proxy ID (hop) that handled egress, if any.
	CID      string    // Connection id
	Tx       int       // Amount uploaded (bytes).
	Rx       int       // Amount downloaded (bytes).
	Duration int32     // Conn open duration (seconds).
	start    time.Time // Tracks start time; unexported.
	Msg      string    // Error message, if any.
}

func (s *ServerSummary) done(errs ...error) {
	if s == nil {
		return
	}

	s.Duration = int32(time.Since(s.start).Seconds())

	err := errors.Join(errs...) // errs may be nil
	if err != nil {
		if s.Msg == errNop.Error() {
			s.Msg = err.Error()
		} else {
			s.Msg = s.Msg + "; " + err.Error()
		}
	}
	if len(s.Msg) <= 0 {
		s.Msg = errNop.Error()
	}
}

func (s *ServerSummary) String() string {
	return fmt.Sprintf("type: %s, sid: %s, pid: %s, cid: %s, upload: %d, download: %d, duration: %d, msg: %s",
		s.Type, s.SID, s.PID, s.CID, s.Tx, s.Rx, s.Duration, s.Msg)
}

func serverSummary(typ, sid, pid, cid string) *ServerSummary {
	return &ServerSummary{
		Type:  typ,
		SID:   sid,
		PID:   pid,
		CID:   cid,
		start: time.Now(),
		Msg:   errNop.Error(),
	}
}

// ServerListener receives Server events.
type ServerListener interface {
	// Route decides how to forward an incoming connection over service (sid).
	Route(sid, pid, network, sipport, dipport string) *Tab
	// OnComplete reports summary after a connection closes.
	OnComplete(*ServerSummary)
}

type Tab struct {
	CID   string // CID is the ID of this connection.
	Block bool   // Block is true if this connection should be blocked.
}
