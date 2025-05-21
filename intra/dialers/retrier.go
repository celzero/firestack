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
	"io"
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
	multidial     bool

	raddr net.Addr
	laddr net.Addr // laddr may be nil; TCPAddr.IP may be nil.

	// Flags indicating whether the caller has called CloseRead and CloseWrite.
	readDone  atomic.Bool
	writeDone atomic.Bool

	// mu is a lock that guards conn, retryCount, tee, timeout,
	// retryErr, retryDoneCh, readDeadline, and writeDeadline.
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
	retryCount    uint8
	// Flag indicating when retry is finished or unnecessary.
	retryDoneCh chan struct{} // always unbuffered
}

var _ core.DuplexConn = (*retrier)(nil)

var _ core.DuplexConn = (*net.TCPConn)(nil)

// Helper functions for reading flags.
// In this package, a "flag" is a thread-safe single-use status indicator that
// starts in the "open" state and transitions to "closed" when close() is called.
// It is implemented as a channel over which no data is ever sent.
// Some advantages of this implementation:
//   - The language enforces the one-way transition.
//   - Nonblocking and blocking access are both straightforward.
//   - Checking the status of a closed flag should be extremely fast (although currently
//     it's not optimized: https://github.com/golang/go/issues/32529)
func closed(c <-chan struct{}) bool {
	select {
	case <-c: // The channel has been closed.
		return true
	default:
		return false
	}
}

// retryCompleted returns true if the retry is complete or unnecessary.
func (r *retrier) retryCompleted() bool {
	return closed(r.retryDoneCh)
}

func (r *retrier) canRetryLocked() bool {
	return r.retryCount < maxRetryCount
}

// Given rtt of a successful socket connection (SYN sent - SYNACK received),
// returns a timeout for replies to the first segment sent on this socket.
func calcTimeout(rtt time.Duration) time.Duration {
	// These values were chosen to have a <1% false positive rate based on test data.
	// False positives trigger an unnecessary retry, which can make connections slower, so they are
	// worth avoiding.  However, overly long timeouts make retry slower and less useful.
	return 400*time.Millisecond + max(2*rtt, 100*time.Millisecond)
}

// DialWithSplitRetry returns a TCP connection that transparently retries by
// splitting the initial upstream segment if the socket closes without receiving a
// reply.  Like net.Conn, it is intended for two-threaded use, with one thread calling
// Read and CloseRead, and another calling Write, ReadFrom, and CloseWrite.
// `dialer` will be used to establish the connection.
// `addr` is the destination.
func DialWithSplitRetry(d *protect.RDial, laddr, raddr *net.TCPAddr) (*retrier, error) {
	r := &retrier{
		dialers:     []protect.RDialer{d},
		dialerOpts:  settings.GetDialerOpts(),
		laddr:       laddr, // may be nil
		raddr:       raddr, // must not be nil
		retryDoneCh: make(chan struct{}),
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, err := r.dialLocked(); err != nil {
		return nil, err
	}
	return r, nil
}

func dialerOptsForRace() settings.DialerOpts {
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
	r := &retrier{
		dialers:     reprioritize(ds, asAddrPort(raddr)),
		dialerOpts:  dialerOptsForRace(),
		multidial:   true,
		laddr:       laddr, // may be nil
		raddr:       raddr, // must not be nil
		retryDoneCh: make(chan struct{}),
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, err := r.dialLocked(); err != nil {
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
			split = split && r.retryCount < maxRetryCount
		}
	}

	if !split {
		strat = settings.SplitNever
	} else if auto {
		cycle := r.retryCount % maxRetryCount
		switch retryStrat {
		case settings.RetryNever:
			// only one attempt allowed; neither retried nor split
			strat = settings.SplitTCPOrTLS
		case settings.RetryWithSplit:
			// if retrying (retryCount > 0), always split
			if cycle == 1 {
				strat = settings.SplitTCPOrTLS
			} else if cycle == 2 {
				strat = settings.SplitDesync
			} else { // split is either true or false
				strat = settings.SplitTCP
			}
		case settings.RetryAfterSplit:
			// split for the first two attempts
			if cycle == 0 {
				strat = settings.SplitTCPOrTLS
			} else if cycle == 1 {
				strat = settings.SplitDesync
			} else { // split is false, so strat does not matter
				strat = settings.SplitTCP
			}
		}
	} else {
		strat = r.dialerOpts.Strat
	}

	return
}

// dialLocked establishes a new connection to r.raddr and closes existing, if any.
// Sets r.conn on non-errors and timeout as calculated from round-trip time.
func (r *retrier) dialLocked() (c protect.Conn, err error) {
	clos(r.conn) // close existing connection, if any

	strat, err := r.dialStratLocked()
	if err != nil {
		return
	}

	begin := time.Now()
	c, err = r.doDialLocked(strat)
	rtt := time.Since(begin)

	r.conn = c // c may be nil
	r.timeout = calcTimeout(rtt)

	logeif(err)("retrier: dial(%s) %s=>%s; strat: %d (mult? %d), rtt: %dms; err? %v",
		r.dialerOpts, laddr(c), r.raddr, strat, len(r.dialers), rtt.Milliseconds(), err)

	return
}

// dialStrat returns a core.DuplexConn to r.raddr using a specified strategy, strat,
// which is one of the settings.Split* constants.
func (r *retrier) doDialLocked(dialStrat int32) (protect.Conn, error) {
	if r.multidial {
		var errs error
		if r.nextDialerIdx >= len(r.dialers) && r.retryCount < maxRetryCount {
			r.nextDialerIdx = 0
			log.D("retrier: mult: %s: reset dialer index; retry # %d / %d",
				r.dialerID(), r.retryCount, maxRetryCount)
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
	return &splitter{conn: tc, strat: dialStrat}, nil
}

// retryWriteReadLocked closes the current connection, dials a new one, and writes
// the first segment after splitting according to specified dial strategy.
// Returns an error if the dial fails or if the splits could not be written.
func (r *retrier) retryWriteReadLocked(buf []byte) (int, error) {
	// r.dialLocked also closes provisional socket
	newConn, err := r.dialLocked() // errs on dial strat = no retries, too
	if err != nil || newConn == nil || core.IsNil(newConn) {
		return 0, core.OneErr(err, errNoConn)
	}

	var nw int
	nw, r.retryWriteErr = newConn.Write(r.tee)
	logeif(r.retryWriteErr)("retrier: retryLocked: strat(%s, mult? %t) %s=>%s; write? %d/%d; err? %v",
		r.dialerOpts, r.multidial, laddr(newConn), r.raddr, nw, len(r.tee), r.retryWriteErr)
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
	} else {
		_ = newConn.SetReadDeadline(r.readDeadline)
	}
	// caller might have set read or write deadlines before the retry.
	if writedone {
		core.CloseOp(newConn, core.CopW)
	} else {
		_ = newConn.SetWriteDeadline(r.writeDeadline)
	}

	logedcond(readdone || writedone)("retrier: retryLocked: done! strat(%s; mult? %t) %s=>%s; write? %d/%d; closed r/w? %t/%t; deadline r/w: %v/%v",
		r.dialerOpts, r.multidial, laddr(newConn), r.raddr, nw, len(r.tee), readdone, writedone, time.Since(r.readDeadline).Seconds(), time.Since(r.writeDeadline).Seconds())

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

// Read data from r.conn into buf
func (r *retrier) Read(buf []byte) (n int, err error) {
	note := log.V

	c := r.conn // r.conn may be provisional or final connection
	if c != nil && core.IsNotNil(c) {
		for reads := range maxEmptyReads {
			n, err = c.Read(buf)
			if n == 0 && err == nil { // no data and no error
				note("retrier: read: no data #%d; retrying [%s<=%s]", reads, laddr(c), r.raddr)
				continue // nothing yet to retry; on to next read
			} // else: check if retry is needed (c == nil or err != nil)
			break
		}
		if n == 0 && err == nil {
			err = io.ErrNoProgress
		}
		logeor(err, note)("retrier: read: [%s<=%s] %d; err: %v", laddr(c), r.raddr, n, err)
	} // else: needs retry as c == nil

	note = log.D

	if !r.retryCompleted() {
		r.mu.Lock()
		defer r.mu.Unlock()

		if !r.retryCompleted() {
			note = log.I
			defer close(r.retryDoneCh) // signal that retry is complete or unnecessary

			retryReadErr := err
			// retry on errs like timeouts or connection resets
			for (c == nil || core.IsNil(c) || retryReadErr != nil) && r.canRetryLocked() {
				r.retryCount++
				n, retryReadErr = r.retryWriteReadLocked(buf)
				c = r.conn // re-assign c to newConn, if any; may be nil
				if c == nil || core.IsNil(c) || retryReadErr != nil {
					retryReadErr = core.OneErr(retryReadErr, errNoConn)
					err = core.JoinErr(err, retryReadErr)
				} else {
					retryReadErr = nil // break
					err = nil          // return no error
				}
				logeor(retryReadErr, note)("retrier: read: #%d + (mult? %t / c: %d): [%s<=%s] %d; err? %v",
					r.retryCount, r.multidial, r.nextDialerIdx, laddr(c), r.raddr, n, retryReadErr)
			}
			if c != nil && core.IsNotNil(c) {
				_ = c.SetReadDeadline(r.readDeadline)
				_ = c.SetWriteDeadline(r.writeDeadline)
			}
			logeor(err, note)("retrier: read: #%d + (mult? %d / %d) [%s<=%s] %d; err? %v",
				r.retryCount, len(r.dialers), r.nextDialerIdx, laddr(c), r.raddr, n, err)
			r.tee = nil // discard teed data
			return
		}
		logeor(err, note)("retrier: read: already retried! [%s<=%s] %s; err? %v",
			laddr(c), r.raddr, n, err)
	} // else: just one read is enough; no retry needed
	return
}

func (r *retrier) teedFirstWrite(b []byte) (n int, didWrite bool, src net.Addr, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	c := r.conn
	if c == nil || core.IsNil(c) {
		err = errNilConn
		log.E("retrier: send(tee): [] => %s, no conn; sz(%d)", r.raddr, len(b))
		return
	}
	src = laddr(c)
	if !r.retryCompleted() { // first write
		n, err = c.Write(b)
		// capture first write, aka "hello"
		r.tee = append(r.tee, b...)
		// all of b was written to r.tee if not to c
		// require a response or another write within a short timeout.
		_ = c.SetReadDeadline(time.Now().Add(r.timeout))
		didWrite = true
	}
	return
}

// Write data in b to retrier's underlying conn, r.conn
func (r *retrier) Write(b []byte) (int, error) {
	// Double-checked locking pattern.  This avoids lock acquisition on
	// every packet after retry completes, while also ensuring that r.tee is
	// empty at steady-state.
	if !r.retryCompleted() {
		// todo: what if sentAndCopied is false and err != nil?
		n, sentAndCopied, src, err := r.teedFirstWrite(b)

		note := log.D
		if sentAndCopied {
			note = log.I
		}

		logeor(err, note)("retrier: write: first?(%t) [%v=>%s] %d; 1st write-err? %v",
			sentAndCopied, src, r.raddr, n, err)

		if sentAndCopied {
			start := time.Now()
			// write error on the provisional socket should be handled
			// by the retry procedure. Block until we have a final socket (which will
			// already have replayed r.tee), and retry.
			// ie, wait until first write is done on the final socket.
			maxExpectedReadTimeout := r.timeout * maxRetryCount
			if r.multidial {
				maxExpectedReadTimeout = r.timeout * time.Duration(len(r.dialers))
			}
			select {
			case <-r.retryDoneCh:
			case <-time.After(3 * maxExpectedReadTimeout): // arb high timeout; it should rarely if ever needed
				log.W("retrier: write: 1st write timed-out waiting for %d [calc-rtt: %d] 1st read b/w [%s=>%s], mult: %d, n: %d, err: %v",
					3*maxExpectedReadTimeout, r.timeout, src, r.raddr, len(r.dialers), n, err)
				return n, core.JoinErr(err, errRetryTimeout)
			}

			// if Write() does not wait for <-retryDoneCh in absence of errors,
			// it is possible that ReadFrom() => copyOnce() is called before retryDoneCh
			// is closed, resulting in two Write() calls, and r.tee containing buffers
			// the size of two Writes()
			if err == nil {
				return n, nil // 1st write + read succeeded
			} // 1st write failed, but retry is complete

			r.mu.Lock()
			defer r.mu.Unlock()

			elapsed := time.Since(start).Milliseconds()
			// r.conn may be nil or closed by the time we get here
			finalConn := r.conn
			noconn := finalConn == nil || core.IsNil(finalConn)
			if r.retryWriteErr != nil || noconn { // check if retried writes also failed
				if noconn {
					err = core.JoinErr(err, errNilConn)
				}
				log.E("retrier: write: retry failed [%s=>%s] in %dms; old => new: %v => %v; noconn? %t",
					laddr(r.conn), r.raddr, elapsed, err, r.retryWriteErr, noconn)
				return n, core.JoinErr(err, r.retryWriteErr) // pass on the og error, too
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

	// retryCompleted() is true, so r.conn is final and doesn't need locking
	if c := r.conn; c == nil || core.IsNil(c) {
		log.E("retrier: write: [] => %s, not retrying, but no conn", r.raddr)
		return 0, errNilConn
	} else {
		return c.Write(b)
	}
}

// ReadFrom reads data from reader via r.conn.ReadFrom, after (as needed)
// retries are done; before which reads are delegated to copyOnce.
func (r *retrier) ReadFrom(reader io.Reader) (bytes int64, err error) {
	copies := 0
	// TODO: skip copyOnce if r.multidial set or if strat is SplitNever?
	for !r.retryCompleted() { // should iter only once
		b, e := copyOnce(r, reader)
		copies++
		bytes += b
		logeif(err)("retrier: readfrom: copyOnce #%d; sz: %d/%d; err: %v", copies, b, bytes, err)
		if e != nil {
			return bytes, e
		}
		// TODO: return after first copyOnce if strat is RetryNever?
	}

	c := r.conn // reader thread does not need the mutex
	if c == nil || core.IsNil(c) {
		log.E("retrier: readfrom: [] <= %s, no conn; after# %d: sz(%d)", r.raddr, copies, bytes)
		return bytes, io.ErrUnexpectedEOF
	}

	pinned := false
	pinnedID := ""
	if r.multidial {
		if ipp := asAddrPort(r.raddr); ipp.IsValid() {
			// cache the dialer ID for the IP:port pair
			di := max(0, r.nextDialerIdx-1) % len(r.dialers)
			pinnedID = r.dialers[di].ID()
			ippPins.Put(ipp, pinnedID)
			pinned = true
		}
	}

	optimizedReadFrom := true
	var b int64
	switch x := c.(type) {
	case *net.TCPConn:
		b, err = x.ReadFrom(reader)
		bytes += b
	case *splitter:
		b, err = x.ReadFrom(reader)
		bytes += b
	case io.ReaderFrom:
		b, err = x.ReadFrom(reader)
		bytes += b
	default: // net.UDPConn, net.PacketConn etc?
		optimizedReadFrom = false
		// read from reader until EOF
		b, err = core.Stream(c, reader)
		bytes += b
	}

	if optimizedReadFrom {
		// disable read and write deadlines as io.ReaderFrom does not
		// rely on io.Read and io.Write semantics from which deadlines
		// are usually extended to avoid timeouts (see also: rwconn.go)
		r.SetDeadline(time.Time{})
	}

	logeif(err)("retrier: readfrom: (optimized? %t) done (id: %s, pinned? %t); sz: %d; err: %v",
		optimizedReadFrom, pinnedID, pinned, bytes, err)
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
	if c := r.conn; c != nil && core.IsNotNil(c) {
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
		if c := r.conn; c != nil && core.IsNotNil(c) {
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
	if c := r.conn; c != nil && core.IsNotNil(c) {
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
