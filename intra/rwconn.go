// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package intra

import (
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/settings"
)

// A TCP conn's idle-read deadline is governed by
// settings.DialerOpts.ReadTimeoutSec (default 10s, see:
// PersistentState.kt:dialTimeoutSec). That deadline exists to catch conns
// that are PMTUD/censorship blackholed -- silently dropped with no RST/FIN --
// which would otherwise hang forever with no timeout at all (the original
// failure mode dialTimeoutSec's 0->10 change was introduced to fix).
//
// But persistent HTTP/1.1|2 keep-alive conns routinely sit fully idle between
// a completed response and the app's next logical request, and that idle gap
// is not bounded by any protocol invariant -- it's purely a function of how
// long the app takes to decide it wants more data. Eg: Zee5's cold-cache
// DRM/token provisioning after receiving its DASH/HLS manifest response can
// legitimately, and variably, exceed even a generous fixed grace period (45s
// was tried and empirically still insufficient on some runs), causing
// Firestack to RST an already-healthy, still-in-use conn out from under the
// app before it's reused -- manifesting as a silent, permanent player hang
// (no retry, no app-visible error). Root caused via 3-state (vpn-off /
// vpn-on+warm-app-cache / vpn-on+cold-app-cache) logcat capture+diff,
// 2026-09-13; 45s-grace attempt empirically insufficient, re-tested same day.
//
// Since no finite grace period can be guaranteed sufficient, once a conn has
// successfully read >=1 byte from the remote it is proven NOT to be a
// blackhole candidate (a genuinely blackholed conn could never have done
// so) -- at that point the dopt.ReadTimeoutSec-derived deadline is dropped
// entirely, falling back to just the conn-type's own floor (rwext.minidle;
// 0 for tcp => extendr/extend treat that as "no deadline", see common.go).
// A real mid-stream death of a warm conn is still caught: either the peer
// eventually sends a real RST/FIN (no artificial timer needed), or the OS
// TCP stack's own keepalive eventually detects the dead link. Never-yet-
// successful (cold) conns are unaffected and keep the short, aggressive base
// deadline (settings.DialerOpts.ReadTimeoutSec).

// rwext wraps MinConn and extends deadline to minimum(min, settings.DialerOpts)
// on every read and write.
type rwext struct {
	net.Conn              // underlying conn
	minidle  uint32       // min idle timeout in secs
	warm     *atomic.Bool // set once a read succeeds on this conn; never nil
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
	n, err = rw.Conn.Read(b)
	if n > 0 && rw.warm != nil {
		rw.warm.Store(true) // conn proven alive; grant a longer idle grace hereon
	}
	return
}

func (rw rwext) Write(b []byte) (n int, err error) {
	rw.extendw()
	return rw.Conn.Write(b)
}

// ReadFrom implements core.RetrierConn.
func (rw rwext) ReadFrom(r io.Reader) (n int64, err error) {
	switch c := rw.Unwrap().(type) {
	case *net.TCPConn:
		// disable read and write deadlines for rw.Conn as io.ReaderFrom
		// (splice/sendfile) does not support io.Reader+io.Writer semantics
		// which rwext relies on to extend deadlines; safe only for a true
		// os-level conn where the syscall itself is a single operation, not
		// an unbounded higher-level relay loop that can go idle forever.
		rw.extendForever()
		return c.ReadFrom(r)
	default:
	}
	// nb: stream rw (which extends deadlines) not rw.Conn; this also covers
	// wrapper types (eg: *dialers.retrier) that implement io.ReaderFrom but
	// may internally fall back to a plain, idle-able copy loop of their own
	// -- such types must not have their deadlines disabled outright.
	return core.Stream(rw, r)
}

// WriteTo implements core.RetrierConn.
func (rw rwext) WriteTo(w io.Writer) (n int64, err error) {
	switch c := rw.Unwrap().(type) {
	case *net.TCPConn:
		// see ReadFrom for why this is scoped to a genuine os-level conn.
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
	if rw.warm != nil && rw.warm.Load() {
		// already exchanged >=1 byte on this conn: not a blackhole candidate;
		// no finite idle-read grace is guaranteed sufficient (see rationale
		// above), so drop the dopt.ReadTimeoutSec-derived deadline entirely
		// and fall back to just rw.minidle (the conn-type's own floor, if
		// any: 0 for tcp => extendr/extend see <=0 and call
		// SetDeadline(zero-value), ie: no deadline at all, see common.go;
		// 120s for udp => unchanged from before, still bounded so idle udp
		// "conns" -- which have no real end-of-stream signal like tcp's
		// RST/FIN -- don't leak NAT/socket state forever).
		r = rw.minidle
	} else {
		// -ve ints go higher than 2^31 w/ uint: go.dev/play/p/Rrqk_V8a7W0
		r = max(rw.minidle, uint32(dopt.ReadTimeoutSec))
	}
	return r, max(rw.minidle, uint32(dopt.WriteTimeoutSec))
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
