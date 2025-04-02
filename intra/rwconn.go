// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package intra

import (
	"net"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/settings"
)

// rwext wraps MinConn and extends deadline to minimum(min, settings.DialerOpts)
// on every read and write.
type rwext struct {
	net.Conn        // underlying conn
	minidle  uint32 // min idle timeout in secs
}

func (rw rwext) IsZeroDeadline() bool {
	r, w := rw.deadlines()
	return r == 0 && w == 0
}

func (rw rwext) SetAsTCPSockOpt() (c *net.TCPConn, ok bool) {
	r, w := rw.deadlines()
	timeout := max(int(r), int(w))
	c, ok = rw.Conn.(*net.TCPConn) // no-op for tcp conns
	if ok && r > 0 {
		// always returns false for udp conns
		ok = core.SetTimeoutSockOpt(c, timeout*1000)
	}
	return c, ok
}

func (rw rwext) Unwrap() net.Conn {
	return rw.Conn
}

func (rw rwext) Read(b []byte) (n int, err error) {
	rw.extend()
	return rw.Conn.Read(b)
}

func (rw rwext) Write(b []byte) (n int, err error) {
	rw.extend()
	return rw.Conn.Write(b)
}

func (rw rwext) deadlines() (r, w uint32) {
	dopt := settings.GetDialerOpts()
	// -ve ints go higher than 2^31 w/ uint: go.dev/play/p/Rrqk_V8a7W0
	return max(rw.minidle, uint32(dopt.ReadTimeoutSec)),
		max(rw.minidle, uint32(dopt.WriteTimeoutSec))
}

func (rw rwext) extend() {
	r, w := rw.deadlines()
	tr := time.Second * time.Duration(r)
	tw := time.Second * time.Duration(w)

	extendc(rw.Conn, tr, tw)
}
