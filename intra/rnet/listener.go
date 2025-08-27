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

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
)

var errNop = errors.New("no error")

type ServerSummary struct {
	*x.ServerSummary
	start time.Time // Tracks start time; unexported.
}

func (s *ServerSummary) done(errs ...error) {
	if s == nil {
		return
	}

	s.Duration = time.Since(s.start).Milliseconds()

	err := core.JoinErr(errs...) // errs may be nil
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
	if s == nil {
		return "<nil>"
	}
	return fmt.Sprintf("type: %s, sid: %s, pid: %s, cid: %s, upload: %d, download: %d, duration: %d, msg: %s",
		s.Type, s.SID, s.PID, s.CID, s.Tx, s.Rx, s.Duration, s.Msg)
}

func serverSummary(typ, sid, pid, cid string) *ServerSummary {
	return &ServerSummary{
		ServerSummary: &x.ServerSummary{
			Type: typ,
			SID:  sid,
			PID:  pid,
			CID:  cid,
			Msg:  errNop.Error(),
		},
		start: time.Now(),
	}
}
