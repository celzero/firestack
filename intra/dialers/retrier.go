// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     Copyright 2019 The Outline Authors
//
//     Licensed under the Apache License, Version 2.0 (the "License");
//     you may not use this file except in compliance with the License.
//     You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
//     Unless required by applicable law or agreed to in writing, software
//     distributed under the License is distributed on an "AS IS" BASIS,
//     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//     See the License for the specific language governing permissions and
//     limitations under the License.

package dialers

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
)

type zeroNetAddr struct{}

func (zeroNetAddr) Network() string { return "no" }
func (zeroNetAddr) String() string  { return "none" }

const (
	maxRetryCount = 3
	maxEmptyReads = 3

	minExpectedTLSRead = 16 // minimum bytes expected in a TLS read
	tlsPort            = 443

	// maximum timeout in seconds for reads to complete before retrying
	cielRetryReadTimeoutSec = 9
	// minimum timeout in milliseconds for reads to complete before retrying
	floorRetryReadTimeoutMillis = 1000
	// max timeout (for ReadFrom, before WriteTo) for desync to complete
	uploadTimeoutForDownload = 3 * time.Second
)

// ippPins maintains a limited-time mapping between ip:port addresses and dialer IDs.
// TODO: invalidate cache on network changes.
// TODO: with context.TODO, expmap's reaper goroutine will leak.
var ippPins = core.NewSieve[netip.AddrPort, string](context.TODO(), desync_cache_ttl)

// retrier implements the DuplexConn interface and must
// be typecastable to *net.TCPConn (see: xdial.DialTCP)
// inheritance: go.dev/play/p/mMiQgXsPM7Y
type retrier struct {
	dialers       []protect.RDialer
	dialerOpts    settings.DialerOpts
	nextDialerIdx int
	currentStrat  int32
	multidial     bool

	rport uint16 //  raddr port
	raddr net.Addr
	laddr net.Addr // laddr may be nil; TCPAddr.IP may be nil.

	// Flags indicating whether the caller has called CloseRead and CloseWrite.
	readDone  atomic.Bool
	writeDone atomic.Bool

	// mu is a lock that guards conn, retryCount, tee, timeout,
	// retryErr, retryDone, readDeadline, and writeDeadline.
	// After retryDoneCh is closed, these values will not be
	// modified again so locking is no longer required for reads.
	mu sync.Mutex

	// the current underlying connection.  It is only modified by the reader
	// thread, so the reader functions may access it without acquiring a lock.
	// nb: if embedding TCPConn; override its WriteTo instead of just ReadFrom
	// as io.Copy prefers WriteTo over ReadFrom; or use core.Pipe
	conn protect.Conn

	// External read and write deadlines.  These need to be stored here so that
	// they can be re-applied in the event of a retry.
	readDeadline  time.Time
	writeDeadline time.Time
	// Time to wait between the 1st write & the 1st read before triggering a retry.
	timeout time.Duration
	// tee is the contents written before the first read.  It is initially empty,
	// and is cleared when the first byte is received.
	tee []byte
	// retryWriteErr is set to the error from the last retry, if any.
	retryWriteErr error
	// tracks the number of retries attempted.
	retryCount uint8
	// must be set to 1 or more, never 0.
	maxRetries uint8
	// Flag indicating when retry is finished or unnecessary.
	retryDone *core.SigCond
}

var _ core.DuplexConn = (*retrier)(nil)
var _ core.RetrierConn = (*retrier)(nil)

var _ core.DuplexConn = (*net.TCPConn)(nil)

// retryCompleted returns true if the retry is complete or unnecessary.
func (r *retrier) retryCompleted() bool { return r.retryDone.Cond() }

func (r *retrier) canRetry() bool {
	return r.dialerOpts.Retry != settings.RetryNever
}

// TODO: make sure "Auto" works as intended for netdev.vger.kernel.narkive.com and norskkalender.no
// Given rtt of a successful socket connection (SYN sent - SYNACK received),
// returns a timeout for replies to the first segment sent on this socket.
func calcTimeout(rtt time.Duration, spread uint16) time.Duration {
	spread = max(1, spread)                                                                   // avoid div by zero
	ciel := time.Duration(max(1, (cielRetryReadTimeoutSec/spread))) * time.Second             // ciel at least 1secs
	floor := time.Duration(min(300, (floorRetryReadTimeoutMillis/spread))) * time.Millisecond // floor is at most 1secs

	// Lower values trigger an unnecessary retry that make connections slower or fail (like nytimes.com)
	// However, overly long timeouts make retry slower.
	return max(rtt*2, ciel) + min(2*rtt, floor)
}

// DialWithSplitRetry returns a TCP connection that transparently retries by
// splitting the initial upstream segment if the socket closes without receiving a
// reply.  Like net.Conn, it is intended for two-threaded use, with one thread calling
// Read and CloseRead, and another calling Write, ReadFrom, and CloseWrite.
// `dialer` will be used to establish the connection.
// `addr` is the destination.
func DialWithSplitRetry(d *protect.RDial, laddr, raddr *net.TCPAddr) (*retrier, error) {
	r := &retrier{
		dialers:    []protect.RDialer{d},
		dialerOpts: settings.GetDialerOpts(),
		laddr:      laddr, // may be nil
		raddr:      raddr, // must not be nil
		maxRetries: maxRetryCount,
		retryDone:  core.NewSigCond(),
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.dialLocked(); err != nil {
		return nil, err
	}
	return r, nil
}

func dialerOptsForMultiDialers() settings.DialerOpts {
	// see: dialStratLocked
	return settings.DialerOpts{
		Strat: settings.SplitNever,
		Retry: settings.RetryWithSplit,
	}
}

func reprioritize(ds []protect.RDialer, ipp netip.AddrPort) []protect.RDialer {
	// reprioritize the dialers based on the IP:port pair
	if !ipp.IsValid() {
		return ds
	}
	if len(ds) <= 1 {
		return ds
	}
	id, ok := ippPins.Get(ipp)
	if !ok || len(id) <= 0 {
		return ds
	}
	for i, d := range ds {
		if d.ID() == id {
			ds[i], ds[0] = ds[0], ds[i]
			break
		}
	}
	return ds
}

func DialAny(ds []protect.RDialer, laddr, raddr net.Addr) (*retrier, error) {
	if len(ds) <= 0 {
		return nil, errNoDialer
	}

	remote := asAddrPort(raddr)
	r := &retrier{
		dialers:    reprioritize(ds, remote),
		dialerOpts: dialerOptsForMultiDialers(),
		multidial:  true,
		maxRetries: uint8(len(ds)),
		laddr:      laddr, // may be nil
		raddr:      raddr, // must not be nil
		rport:      remote.Port(),
		retryDone:  core.NewSigCond(),
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.dialLocked(); err != nil {
		return nil, err
	}
	return r, nil
}

// SycallConn implements core.DuplexConn.
func (r *retrier) SyscallConn() (syscall.RawConn, error) {
	r.mu.Lock()
	c := r.conn
	r.mu.Unlock()
	if sc, ok := c.(syscall.Conn); ok {
		return sc.SyscallConn()
	}
	log.W("retrier: not a syscall.Conn: %T", c)
	return nil, syscall.EINVAL
}

// SetKeepAlive implements core.DuplexConn.
func (r *retrier) SetKeepAlive(y bool) error {
	r.mu.Lock()
	c := r.conn
	r.mu.Unlock()
	if c, ok := c.(core.KeepAliveConn); ok {
		return c.SetKeepAlive(y)
	}
	log.W("retrier: not a net.Conn: %T", c)
	return syscall.EINVAL
}

func (r *retrier) dialStratLocked() (strat int32, err error) {
	if r.multidial { // multidialing retrier does not follow strategies
		// see: dialerOptsForMultiDialers
		return settings.SplitNever, nil
	}

	auto := r.dialerOpts.Strat == settings.SplitAuto
	retryStrat := r.dialerOpts.Retry
	split := r.dialerOpts.Strat != settings.SplitNever

	switch retryStrat {
	case settings.RetryNever:
		if r.retryCount >= 1 {
			err = errNoRetrier // retry not allowed
			return
		}
		split = split && r.retryCount == 0 // split at 1st attempt
	case settings.RetryWithSplit:
		split = split && r.retryCount >= 1 // split after 1st attempt
	case settings.RetryAfterSplit:
		split = split && r.retryCount == 0 // split at 1st attempt
		if auto {
			// split at all attempts except the last
			// (also see "auto" cond block below)
			split = split && r.retryCount < r.maxRetries
		}
	}

	if !split {
		strat = settings.SplitNever
	} else if auto {
		// auto always attempts TCP split first as TLS splits
		// as not all TLS servers play nice with split TLS records.
		attemptCycle := r.retryCount % r.maxRetries
		switch retryStrat {
		case settings.RetryNever:
			// only one attempt allowed; neither retried nor split
			strat = settings.SplitTCP
		case settings.RetryWithSplit: // "auto" retry
			// if retrying (retryCount > 0), always split
			if attemptCycle == 1 {
				strat = settings.SplitTCP
			} else if attemptCycle == 2 {
				strat = settings.SplitTCPOrTLS
			} else { // split is either true or false
				strat = settings.SplitDesync
			}
		case settings.RetryAfterSplit:
			// split for the first two attempts
			if attemptCycle == 0 {
				strat = settings.SplitTCP
			} else if attemptCycle == 1 {
				strat = settings.SplitTCPOrTLS
			} else {
				// split is false when retryCount >= r.maxRetries,
				// and so, the strat here does not matter
				strat = settings.SplitTCP
			}
		}
	} else {
		strat = r.dialerOpts.Strat
	}

	return
}

func (r *retrier) dialerID() string {
	di := 0
	if r.multidial {
		di = min(max(di, r.nextDialerIdx-1), len(r.dialers)-1)
	}
	return r.dialers[di].ID()
}

// dialLocked establishes a new connection to r.raddr and closes existing, if any.
// Sets r.conn on non-errors and timeout as calculated from round-trip time.
func (r *retrier) dialLocked() error {
	clos(r.conn) // close existing connection, if any

	strat, err := r.dialStratLocked()
	if err != nil {
		return err
	}
	r.currentStrat = strat

	spreadTimeoutOver := int(r.maxRetries) - int(r.retryCount)
	if nosplit := strat == settings.SplitNever; nosplit {
		spreadTimeoutOver = 0 // no spread if no split
	}

	begin := time.Now()
	c, err := r.doDialLocked(strat)
	rtt := time.Since(begin)

	if c != nil && core.IsNotNil(c) { // c may be deep nil
		r.conn = c
	} else {
		r.conn = nil
	}

	if r.canRetry() {
		// final retry gets maximum possible timeout
		r.timeout = calcTimeout(rtt, uint16(spreadTimeoutOver))
	} else {
		// if retries are disabled, then do not aggressively timeout
		// as there's nothing else for the retrier to do.
		r.timeout = 0
	}

	logeif(err)("retrier: dial(%s) %s=>%s; strat: %d+%d (mult? %d %T), rtt: %s / to: %s; err? %v",
		r.dialerID(), laddr(c), r.raddr, strat, r.dialerOpts.Retry, len(r.dialers), c, core.FmtPeriod(rtt), core.FmtPeriod(r.timeout), err)

	return err
}

func (r *retrier) isSplitStrat() bool {
	if r.multidial { // multidial do not follow strats
		return false
	}
	return r.currentStrat == settings.SplitTCP || r.currentStrat == settings.SplitTCPOrTLS
}

// dialStrat returns a core.DuplexConn to r.raddr using a specified strategy, strat,
// which is one of the settings.Split* constants.
func (r *retrier) doDialLocked(dialStrat int32) (protect.Conn, error) {
	if r.multidial {
		var errs error
		if r.nextDialerIdx >= len(r.dialers) && r.retryCount < r.maxRetries {
			r.nextDialerIdx = 0
			log.D("retrier: mult: %s: reset dialer index; retry # %d / %d",
				r.dialerID(), r.retryCount, r.maxRetries)
		}
		for r.nextDialerIdx < len(r.dialers) {
			d := r.dialers[r.nextDialerIdx]
			c, err := protect.Dial(d, r.laddr, r.raddr)
			logeif(err)("retrier: mult: #%d/%d dial(%s: %s) %s=>%s; err? %v",
				r.nextDialerIdx, len(r.dialers), d.ID(), r.dialerOpts, laddr(c), r.raddr, err)

			r.nextDialerIdx++ // incr regardless of err

			if err == nil {
				return c, nil
			}
			clos(c)
			errs = core.JoinErr(errs, err)
		}
		return nil, core.OneErr(errs, errNoDialer)
	}

	di := r.dialers[0] // always use the first dialer when not multidialing

	network := r.raddr.Network()
	if isTCP := strings.HasPrefix(network, "tcp"); !isTCP {
		return protect.Dial(di, r.laddr, r.raddr)
	}

	// r.laddr may be nil or laddr.IP may be nil.
	switch dialStrat {
	case settings.SplitNever:
		return protect.Dial(di, r.laddr, r.raddr)
	case settings.SplitDesync:
		return dialWithSplitAndDesync(di, r.laddr, r.raddr)
	case settings.SplitTCP, settings.SplitTCPOrTLS:
		fallthrough
	default:
	}
	tc, terr := protect.DialTCP(di, network, r.laddr, r.raddr)
	if terr != nil || tc == nil {
		return nil, core.JoinErr(terr, errNilConn)
	}
	// todo: assert strat must be tcp or tls?
	return &splitter{conn: tc, strat: dialStrat, used: core.NewSigCond()}, nil
}

// retryWriteReadLocked closes the current connection, dials a new one, and writes
// the first segment after splitting according to specified dial strategy.
// Returns an error if the dial fails or if the splits could not be written.
func (r *retrier) retryWriteReadLocked(buf []byte) (int, error) {
	// r.dialLocked also closes provisional socket
	err := r.dialLocked() // errs on dial strat = no retries, too
	newConn := r.conn
	if err != nil || newConn == nil {
		return 0, core.OneErr(err, errNoConn)
	}

	var nw int
	nw, r.retryWriteErr = newConn.Write(r.tee)
	logeif(r.retryWriteErr)("retrier: retryLocked: strat(%s, mult? %d %T) %s=>%s; write? %d/%d; err? %v",
		r.dialerID(), len(r.dialers), newConn, laddr(newConn), r.raddr, nw, len(r.tee), r.retryWriteErr)
	if r.retryWriteErr != nil {
		return 0, r.retryWriteErr
	}

	// while we were creating the new socket, the caller might have called CloseRead
	// or CloseWrite on the old socket. Copy that state to the new socket.
	// CloseRead and CloseWrite are idempotent, so this is safe even if the user's
	// action actually affected the new socket.
	readdone := r.readDone.Load()
	writedone := r.writeDone.Load()
	if readdone {
		core.CloseOp(newConn, core.CopR)
	}
	if writedone {
		core.CloseOp(newConn, core.CopW)
	}

	logedcond(readdone || writedone)("retrier: retryLocked: done! strat(%s; mult? %d %T) %s=>%s; write? %d/%d; closed r/w? %t/%t; rtt: %s, deadline r/w: %v/%v",
		r.dialerID(), len(r.dialers), newConn, laddr(newConn), r.raddr, nw, len(r.tee), readdone, writedone, core.FmtPeriod(r.timeout), core.FmtTimeAsPeriod(r.readDeadline), core.FmtTimeAsPeriod(r.writeDeadline))

	// all of buf was written to c
	// require a response within a short timeout on r.conn (same as newConn)
	newConn.SetReadDeadline(time.Now().Add(r.readTimeoutLocked()))
	return newConn.Read(buf)
}

// CloseRead closes r.conn for reads, and the read flag.
func (r *retrier) CloseRead() error {
	r.readDone.Store(true)
	r.mu.Lock()
	defer r.mu.Unlock()
	core.CloseOp(r.conn, core.CopR)
	return nil
}

// Read data from r.conn into buf ("download" from remote to local).
func (r *retrier) Read(buf []byte) (n int, err error) {
	note := log.VV
	redoForTls := false

	r.mu.Lock()
	c := r.conn // r.conn may be provisional or final connection
	r.mu.Unlock()

	if c != nil {
		for reads := range maxEmptyReads {
			n, err = c.Read(buf)
			if n == 0 && err == nil { // no data and no error
				note("retrier: read: %s: no data #%d; retrying [%s<=%s], b: 0/%d",
					r.dialerID(), reads, laddr(c), r.raddr, len(buf))
				continue // nothing yet to retry; on to next read
			} // else: check if retry is needed (c == nil or err != nil)
			break
		}
		if n == 0 && err == nil {
			err = io.ErrNoProgress
		}
		redoForTls = r.isSplitStrat() && r.rport == tlsPort && n < minExpectedTLSRead
		if err == nil && redoForTls {
			err = errTLSHandshake
		}
		logeor(err, note)("retrier: read: %s: [%s<=%s]; (rtt: %s / read: %s / redo? %t); b: %d/%d (tee: %d); err: %v",
			r.dialerID(), laddr(c), r.raddr, core.FmtPeriod(r.timeout), core.FmtTimeAsPeriod(r.readDeadline), redoForTls, n, len(buf), len(r.tee), err)
	} // else: needs retry as c == nil

	note = log.D

	// must enter this block at least once (even if c != nil)
	// as it resets read timeout and teed write buffer
	if !r.retryCompleted() {
		r.mu.Lock()
		defer r.mu.Unlock()

		if !r.retryCompleted() {
			note = log.I
			defer r.retryDone.Signal() // signal completion (success or not)

			retryReadErr := err
			// retry on errs like timeouts or connection resets
			for (c == nil || redoForTls || retryReadErr != nil) && (r.canRetry() && r.retryCount < r.maxRetries) {
				r.retryCount++

				n, retryReadErr = r.retryWriteReadLocked(buf)

				redoForTls = r.isSplitStrat() && r.rport == tlsPort && n < minExpectedTLSRead
				if retryReadErr == nil && redoForTls {
					err = errTLSHandshake
				}

				c = r.conn // re-assign c to newConn, if any; may be nil
				if c == nil || retryReadErr != nil {
					retryReadErr = core.OneErr(retryReadErr, errNoConn)
					err = core.JoinErr(err, retryReadErr)
				} else {
					retryReadErr = nil // break
					err = nil          // return no error
					redoForTls = false
				}
				logeor(retryReadErr, note)("retrier: read: %s: #%d + (mult? %d %T / c: %d): [%s<=%s]; t: %s; redo? %t; b:%d/%d; err? %v",
					r.dialerID(), r.retryCount, len(r.dialers), c, r.nextDialerIdx, laddr(c), r.raddr, core.FmtPeriod(r.timeout), redoForTls, n, len(buf), retryReadErr)
			}
			if c != nil {
				// caller might have set read or write deadlines before the retry;
				// if not, clear any deadlines set by the retrier
				_ = c.SetReadDeadline(r.readDeadline)
				_ = c.SetWriteDeadline(r.writeDeadline)
			}
			logeor(err, note)("retrier: read: %s: #%d + (mult? %d / %d) [%s<=%s]; rshortt: %s / rfullt: %s; b: %d/%d; err? %v",
				r.dialerID(), r.retryCount, len(r.dialers), r.nextDialerIdx, laddr(c), r.raddr, core.FmtPeriod(r.timeout), core.FmtTimeAsPeriod(r.readDeadline), n, len(buf), err)
			r.tee = nil // discard teed data
			return
		}
		logeor(err, note)("retrier: read: %s already retried! (conn? %t) [%s<=%s]; t: %s; b: %d/%d; err? %v",
			r.dialerID(), c != nil, laddr(c), r.raddr, core.FmtPeriod(r.timeout), n, len(buf), err)
	} // else: just one read is enough; no retry needed
	if c == nil { // retry completed but no conn
		cerr := log.EE("retrier: read: %s: no conn! [<=%s]; t: %s; b: %d/%d",
			r.dialerID(), r.raddr, core.FmtPeriod(r.timeout), n, len(buf))
		err = core.JoinErr(err, cerr, errNilConn)
	}
	return
}

func (r *retrier) teedFirstWrite(b []byte) (n int, firstWrite, didAttemptWrite bool, readWait time.Duration, src net.Addr, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	firstWrite = len(r.tee) <= 0

	c := r.conn
	if c == nil {
		err = errNilConn
		log.E("retrier: send: %s: tee [] => %s, no conn; sz(%d)",
			r.dialerID(), r.raddr, len(b))
		return
	}

	src = laddr(c)
	if !r.retryCompleted() { // may be first write
		_ = c.SetWriteDeadline(r.writeDeadline)

		n, err = c.Write(b)

		// capture first write, aka "hello"
		r.tee = append(r.tee, b...)
		didAttemptWrite = true
		readWait = r.readTimeoutLocked()
		// all of b was written to r.tee if not to c
		// require a response or another write within a short timeout.
		c.SetReadDeadline(time.Now().Add(readWait))
	}

	return
}

func (r *retrier) readTimeoutLocked() time.Duration {
	if r.timeout > 0 {
		return r.timeout
	}
	if r.readDeadline.IsZero() {
		// 2501h 59m 59s 25ms: a comfortably high duration in nanos
		return math.MaxInt64 >> 10
	}
	return time.Until(r.readDeadline)
}

// Write data in b to retrier's underlying conn, r.conn ("upload" from local to remote).
func (r *retrier) Write(b []byte) (int, error) {
	start := time.Now()
	// Double-checked locking pattern.  This avoids lock acquisition on
	// every packet after retry completes, while also ensuring that r.tee is
	// empty at steady-state.
	if !r.retryCompleted() {
		// todo: what if sentAndCopied is false and err != nil?
		n, first, sentAndCopied, waitForRead, src, err := r.teedFirstWrite(b)

		note := log.D
		if sentAndCopied {
			note = log.I
		}

		logeor(err, note)("retrier: write: %s: (first? %t, sent? %t) [%v=>%s]; t: %s; b: %d/%d (tee: %d); after: %s; write-err? %v",
			r.dialerID(), first, sentAndCopied, src, r.raddr, core.FmtPeriod(r.timeout), n, len(b), len(r.tee), core.FmtTimeAsPeriod(start), err)

		if sentAndCopied {
			// if Write() does not wait for <-retryDoneCh in absence of errors,
			// it is possible that ReadFrom() => copyOnce() is called before retryDoneCh
			// is closed, resulting in two Write() calls, and r.tee containing buffers
			// the size of two Writes()
			if err == nil {
				return n, nil
			} // write failed, wait for retry to complete

			start := time.Now()
			// write error on the provisional socket should be handled
			// by the retry procedure. Block until we have a final socket (which will
			// already have replayed r.tee), and retry.
			// ie, wait until first write is done on the final socket.
			maxUntil := max(waitForRead, waitForRead*time.Duration(r.maxRetries))
			if r.multidial {
				maxUntil = max(maxUntil, maxUntil*time.Duration(len(r.dialers)))
			}
			if !r.retryDone.TryWait(maxUntil) { // timed out waiting for retry completion
				rerr := log.EE("retrier: write: %s: 1st write timed-out waiting for %s [calc-rtt: %s] 1st read b/w [%s=>%s], mult: %d, b: %d/%d, err: %v",
					r.dialerID(), core.FmtPeriod(maxUntil), core.FmtPeriod(r.timeout), src, r.raddr, len(r.dialers), n, len(b), err)
				return n, core.JoinErr(err, rerr, errRetryTimeout)
			}

			r.mu.Lock()
			defer r.mu.Unlock()

			// r.conn may be nil or closed by the time we get here
			finalConn := r.conn
			noconn := finalConn == nil || core.IsNil(finalConn)
			if r.retryWriteErr != nil || noconn { // check if retried writes also failed
				if noconn {
					err = core.JoinErr(err, errNilConn)
				}
				werr := log.EE("retrier: write: %s: retry failed (conn? %t) [%s=>%s] b: %d/%d (tee: %d) in %s; old => new: %v => %v",
					r.dialerID(), !noconn, laddr(r.conn), r.raddr, n, len(b), len(r.tee), core.FmtTimeAsPeriod(start), err, r.retryWriteErr)
				return n, core.JoinErr(err, r.retryWriteErr, werr) // pass on the og error, too
			}

			// if len(leftover) > 0 {
			//	m, err = newConn.Write(leftover)
			//  return n + m, err
			// }

			// retry write succeeded, nil error
			// ie, all of b was written to r.tee which was replayed
			return len(b), nil
		} // not sent by teedFirstWrite; do a normal write
	}

	r.mu.Lock()
	c := r.conn // retry has completed, so r.conn is final and may not need locking?
	r.mu.Unlock()
	if c == nil {
		cerr := log.EE("retrier: write: %s: [] => %s (b: %d, tee: %d), not retrying, but no conn; after: %s",
			r.dialerID(), r.raddr, len(b), len(r.tee), core.FmtTimeAsPeriod(start))
		return 0, core.JoinErr(cerr, errNilConn)
	}

	n, err := c.Write(b)
	if err != nil {
		err = log.EE("retrier: write: %s: [%s=>%s]; b: %d/%d (retried? %t); after: %s; err? %v",
			r.dialerID(), laddr(c), r.raddr, n, len(b), r.retryCompleted(), core.FmtTimeAsPeriod(start), err)
	}
	return n, err
}

// WriteTo writes data to writer via r.conn.WriteTo, after (as needed)
// retries are done; before which reads are delegated to copyOnce.
// Usually, WriteTo is executing the "download" phase of egressing conn (w).
func (r *retrier) WriteTo(w io.Writer) (bytes int64, err error) {
	start := time.Now()
	copies := 0
	// TODO: skip copyOnce if r.multidial set or if strat is SplitNever?
	for !r.retryCompleted() { // should iter only once
		b, e := copyOnce(w, r)
		copies++
		bytes += b
		err = e
		done := r.retryCompleted()
		logeif(e)("retrier: writerto: %s: copyOnce #%d (done? %t) %s<=%s; sz: %d/%d; err: %v",
			r.dialerID(), copies, done, laddr(r.conn), r.raddr, b, bytes, e)
		if e != nil {
			return bytes, e
		} // TODO: return after first copyOnce if strat is RetryNever?
	}

	wait := r.timeout
	// _ = r.retryDone.TryWait(wait) // 0 when no need to wait for retry

	r.mu.Lock() // may block if retry in progress
	c := r.conn
	tee := len(r.tee)
	r.mu.Unlock()

	logedcond(c == nil)("retrier: writerto: %s: (conn? %t) [%s <= %s], tee(%d), waited %s/%s",
		r.dialerID(), c != nil, laddr(c), r.raddr, tee, core.FmtTimeAsPeriod(start), core.FmtPeriod(wait))

	if c == nil {
		return bytes, io.ErrUnexpectedEOF
	}

	// check if writer is a Unix Domain Socket (splice) or tcp.WriteTo
	// won't be optimized (as of go1.25).
	_, canOptimizeWriteTo := w.(*net.UnixConn)

	optimizedWriteTo := canOptimizeWriteTo
	var b int64
	if canOptimizeWriteTo {
		switch x := c.(type) {
		case *net.TCPConn:
			r.SetDeadline(time.Time{})
			b, err = x.WriteTo(w)
			bytes += b
		case *splitter:
			r.SetDeadline(time.Time{})
			b, err = x.WriteTo(w)
			bytes += b
		case io.WriterTo:
			r.SetDeadline(time.Time{})
			b, err = x.WriteTo(w)
			bytes += b
		default: // net.UDPConn, net.PacketConn etc?
			optimizedWriteTo = false
		}
	}

	if !optimizedWriteTo {
		// write to w from c until EOF
		b, err = core.Stream(w, c)
		bytes += b
	}

	msg := fmt.Sprintf("retrier: writerto: %s: (can? %t / optimized? %t for %T) %s<=%s done; sz: %d; after: %s; err: %v",
		r.dialerID(), canOptimizeWriteTo, optimizedWriteTo, c, laddr(c), r.raddr, bytes, core.FmtTimeAsPeriod(start), err)

	if err != nil {
		err = log.EE(msg)
	} else {
		log.V(msg)
	}

	return bytes, err
}

// ReadFrom reads data from reader via r.conn.ReadFrom, after (as needed)
// retries are done; before which reads are delegated to copyOnce.
// Usually, ReadFrom is executing the "upload" phase of egressing conn (r).
func (r *retrier) ReadFrom(reader io.Reader) (bytes int64, err error) {
	start := time.Now()
	copies := 0
	// TODO: skip copyOnce if r.multidial set or if strat is SplitNever?
	for !r.retryCompleted() { // should iter only once
		b, e := copyOnce(r, reader)
		copies++
		bytes += b
		err = e
		done := r.retryCompleted()
		logeif(e)("retrier: readfrom: %s: copyOnce #%d (done? %t) %s<=%s; sz: %d/%d; err: %v",
			r.dialerID(), copies, done, laddr(r.conn), r.raddr, b, bytes, e)
		if e != nil {
			return bytes, e
		}
		// TODO: return after first copyOnce if strat is RetryNever?
	}

	r.mu.Lock()
	c := r.conn // reader thread does not need the mutex?
	tee := len(r.tee)
	r.mu.Unlock()

	if c == nil {
		log.E("retrier: readfrom: %s: [] <= %s, no conn; after# %d: sz(%d) tee(%d); after %s",
			r.dialerID(), r.raddr, copies, bytes, tee, core.FmtTimeAsPeriod(start))
		return bytes, io.ErrUnexpectedEOF
	}

	pinned := false
	pinnedID := ""
	if r.multidial {
		if ipp := asAddrPort(r.raddr); ipp.IsValid() {
			// cache the dialer ID for the IP:port pair
			pinnedID = r.dialerID()
			ippPins.Put(ipp, pinnedID)
			pinned = true
		}
	}

	// check if reader is SyscallConn (sendfile) or *net.TCPConn (splice)
	// as tcp.ReadFrom otherwise won't be optimized but rather use built-in
	// io.Copy which doesn't use a buffer pool unlike core.Stream (go1.25).
	_, canOptimizeReadFrom := reader.(*net.TCPConn)
	if !canOptimizeReadFrom {
		if sc, ok := reader.(syscall.Conn); ok {
			_, err := sc.SyscallConn()
			canOptimizeReadFrom = err == nil
		}
	}

	// disable read and write deadlines as io.ReaderFrom does not
	// rely on io.Read and io.Write semantics for "r.conn" from which
	// deadlines are extended to avoid timeouts (see also: rwconn.go)
	optimizedReadFrom := canOptimizeReadFrom
	var b int64
	if canOptimizeReadFrom {
		switch x := c.(type) {
		case *net.TCPConn:
			r.SetDeadline(time.Time{})
			b, err = x.ReadFrom(reader)
			bytes += b
		case *splitter:
			r.SetDeadline(time.Time{})
			b, err = x.ReadFrom(reader)
			bytes += b
		case io.ReaderFrom:
			r.SetDeadline(time.Time{})
			b, err = x.ReadFrom(reader)
			bytes += b
		default: // net.UDPConn, net.PacketConn etc?
			optimizedReadFrom = false
		}
	}

	if !optimizedReadFrom {
		// read from reader into c until EOF
		b, err = core.Stream(c, reader)
		bytes += b
	}

	msg := fmt.Sprintf("retrier: readfrom: %s: (can? %t / optimized? %t for %T) done (id:%s/pinned?%t) %s<=%s; sz: %d; after: %s; err: %v",
		r.dialerID(), canOptimizeReadFrom, optimizedReadFrom, c, pinnedID, pinned, laddr(c), r.raddr, bytes, core.FmtTimeAsPeriod(start), err)

	if err != nil {
		err = log.EE(msg)
	} else {
		log.V(msg)
	}
	return
}

// CloseWrite closes r.conn for writes, the write flag.
func (r *retrier) CloseWrite() error {
	r.writeDone.Store(true)
	r.mu.Lock()
	defer r.mu.Unlock()
	core.CloseOp(r.conn, core.CopW)
	return nil
}

// Close closes the connection and the read and write flags.
func (r *retrier) Close() error {
	// also close the read and write flags
	return core.JoinErr(r.CloseRead(), r.CloseWrite())
}

// LocalAddr behaves slightly strangely: its value may change as a
// result of a retry.  However, LocalAddr is largely useless for
// TCP client sockets anyway, so nothing should be relying on this.
func (r *retrier) LocalAddr() net.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c := r.conn; c != nil {
		return c.LocalAddr()
	}
	return zeroNetAddr{}
}

// RemoteAddr returns the remote address of the connection.
func (r *retrier) RemoteAddr() net.Addr {
	return r.raddr
}

// SetReadDeadline sets the read deadline for the connection
// if the retry is complete, otherwise it does so after the retry.
func (r *retrier) SetReadDeadline(t time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.readDeadline = t
	// Don't enforce read deadlines until after the retry
	// is complete. Retry relies on setting its own read
	// deadline, and we don't want this to interfere.
	if r.retryCompleted() {
		if c := r.conn; c != nil {
			return c.SetReadDeadline(t)
		}
		return errNoConn
	}
	return nil
}

// SetWriteDeadline sets the write deadline for the connection.
func (r *retrier) SetWriteDeadline(t time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.writeDeadline = t
	if c := r.conn; c != nil {
		return c.SetWriteDeadline(t)
	}
	return errNoConn
}

// SetDeadline sets the read and write deadlines for the connection.
// Read deadlines are set eventually depending on the status of retries.
func (r *retrier) SetDeadline(t time.Time) error {
	e1 := r.SetReadDeadline(t)
	e2 := r.SetWriteDeadline(t)
	return core.JoinErr(e1, e2)
}
