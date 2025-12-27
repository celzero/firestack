// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package intra

import (
	"io"
	"net"
	"syscall"
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

// TODO? var _ core.DuplexCloser = (*rwext)(nil)
var _ core.RetrierConn = (*rwext)(nil)
var _ core.ControlConn = (*rwext)(nil)

func (rw rwext) SetTimeout() (secs int, didSet bool) {
	r, w := rw.deadlines()
	secs = max(int(r), int(w))
	if r > 0 {
		// always returns false for udp conns
		didSet = core.SetTimeoutSockOpt(rw.Unwrap(), secs*1000)
	}
	if !didSet {
		if dx, ok := rw.Unwrap().(*demuxconn); ok {
			// udp demuxconn: set on underlying conn
			extendr(dx, time.Second*time.Duration(r))
			extendw(dx, time.Second*time.Duration(w))
			didSet = true
		}
	}
	return
}

func (rw rwext) Unwrap() net.Conn {
	return rw.Conn
}

func (rw rwext) Read(b []byte) (n int, err error) {
	rw.extendr()
	return rw.Conn.Read(b)
}

func (rw rwext) Write(b []byte) (n int, err error) {
	rw.extendw()
	return rw.Conn.Write(b)
}

// ReadFrom implements core.RetrierConn.
func (rw rwext) ReadFrom(r io.Reader) (n int64, err error) {
	switch c := rw.Unwrap().(type) {
	case io.ReaderFrom:
		// disable read and write deadlines for rw.Conn as
		// io.ReaderFrom does not support io.Reader+io.Writer
		// semantics which rwext relies on to extend deadlines.
		rw.extendForever()
		return c.ReadFrom(r)
	default:
	}
	// nb: stream rw (which extends deadlines) not rw.Conn
	return core.Stream(rw, r)
}

// WriteTo implements core.RetrierConn.
func (rw rwext) WriteTo(w io.Writer) (n int64, err error) {
	switch c := rw.Unwrap().(type) {
	case io.WriterTo:
		// disable read and write deadlines for rw.Conn as
		// io.WriterTo does not support io.Reader+io.Writer
		// semantics which rwext relies on to extend deadlines.
		rw.extendForever()
		return c.WriteTo(w)
	default:
	}
	// nb: stream rw (which extends deadlines) not rw.Conn
	return core.Stream(w, rw)
}

// SyscallConn implements core.ControlConn.
func (rw rwext) SyscallConn() (syscall.RawConn, error) {
	if sc, ok := rw.Unwrap().(syscall.Conn); ok {
		return sc.SyscallConn()
	}
	return nil, syscall.EINVAL
}

func (rw rwext) deadlines() (r, w uint32) {
	dopt := settings.GetDialerOpts()
	// -ve ints go higher than 2^31 w/ uint: go.dev/play/p/Rrqk_V8a7W0
	return max(rw.minidle, uint32(dopt.ReadTimeoutSec)),
		max(rw.minidle, uint32(dopt.WriteTimeoutSec))
}

func (rw rwext) extendForever() {
	extendc(rw, 0, 0)
}

func (rw rwext) extendw() {
	_, w := rw.deadlines()
	tw := time.Second * time.Duration(w)

	extendw(rw.Conn, tw)
}

func (rw rwext) extendr() {
	r, _ := rw.deadlines()
	tr := time.Second * time.Duration(r)

	extendr(rw.Conn, tr)
}
