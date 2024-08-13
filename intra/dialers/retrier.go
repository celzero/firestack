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
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
)

type zeroNetAddr struct{}

func (zeroNetAddr) Network() string { return "no" }
func (zeroNetAddr) String() string  { return "none" }

// retrier implements the DuplexConn interface and must
// be typecastable to *net.TCPConn (see: xdial.DialTCP)
// inheritance: go.dev/play/p/mMiQgXsPM7Y
type retrier struct {
	dial      *protect.RDial
	dialStrat int32
	raddr     *net.TCPAddr

	// Flags indicating whether the caller has called CloseRead and CloseWrite.
	readDone  atomic.Bool
	writeDone atomic.Bool

	// mutex is a lock that guards `conn`, `hello`, and `retryCompleteFlag`,
	// readDeadline, and writeDeadline.
	// These fields must not be modified except under this lock.
	// After retryCompletedFlag is closed, these values will not be modified
	// again so locking is no longer required for reads.
	mutex sync.Mutex

	// the current underlying connection.  It is only modified by the reader
	// thread, so the reader functions may access it without acquiring a lock.
	// nb: if embedding TCPConn; override its WriteTo instead of just ReadFrom
	// as io.Copy prefers WriteTo over ReadFrom; or use core.Pipe
	conn core.DuplexConn

	// External read and write deadlines.  These need to be stored here so that
	// they can be re-applied in the event of a retry.
	readDeadline  time.Time
	writeDeadline time.Time
	// Time to wait between the first write and the first read before triggering a
	// retry.
	timeout time.Duration
	// hello is the contents written before the first read.  It is initially empty,
	// and is cleared when the first byte is received.
	hello []byte
	// Flag indicating when retry is finished or unnecessary.
	retryDoneCh chan struct{} // always unbuffered
}

var _ core.TCPConn = (*retrier)(nil)

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

// Given timestamps immediately before and after a successful socket connection
// (i.e. the time the SYN was sent and the time the SYNACK was received), this
// function returns a reasonable timeout for replies to a hello sent on this socket.
func calcTimeout(before, after time.Time) time.Duration {
	// These values were chosen to have a <1% false positive rate based on test data.
	// False positives trigger an unnecessary retry, which can make connections slower, so they are
	// worth avoiding.  However, overly long timeouts make retry slower and less useful.
	rtt := after.Sub(before)
	return 1200*time.Millisecond + max(2*rtt, 100*time.Millisecond)
}

// DialWithSplitRetry returns a TCP connection that transparently retries by
// splitting the initial upstream segment if the socket closes without receiving a
// reply.  Like net.Conn, it is intended for two-threaded use, with one thread calling
// Read and CloseRead, and another calling Write, ReadFrom, and CloseWrite.
// `dialer` will be used to establish the connection.
// `addr` is the destination.
func DialWithSplitRetry(d *protect.RDial, addr *net.TCPAddr) (*retrier, error) {
	before := time.Now()
	conn, err := d.DialTCP(addr.Network(), nil, addr)
	if err != nil {
		log.E("rdial: tcp addr %s: err %v", addr, err)
		return nil, err
	}
	after := time.Now()

	r := &retrier{
		conn:        conn,
		dial:        d,
		dialStrat:   settings.DialStrategy.Load(),
		raddr:       addr,
		timeout:     calcTimeout(before, after),
		retryDoneCh: make(chan struct{}),
	}

	log.V("rdial: dial: %s->%s; timeout %v", laddr(conn), addr, r.timeout)
	return r, nil
}

// retryWriteReadLocked closes the current connection, dials a new one, and writes the TLS client hello
// message after splitting it in to two. It returns an error if the dial fails or if the
// split TLS client hello messages could not be written.
func (r *retrier) retryWriteReadLocked(buf []byte) (n int, err error) {
	clos(r.conn) // close provisional socket
	var newConn core.DuplexConn

	switch r.dialStrat {
	case settings.DesyncStrategy:
		if newConn, err = dialWithSplitAndDesync(r.dial, r.raddr.AddrPort()); err != nil {
			log.E("rdial: retryLocked: dialDesync %s: err %v", r.raddr, err)
			return
		}
	case settings.SplitTCPStrategy, settings.SplitTCPOrTLSStrategy:
		fallthrough
	default:
		if newConn, err = r.dial.DialTCP(r.raddr.Network(), nil, r.raddr); err != nil {
			log.E("rdial: retryLocked: dialTCP %s: err %v", r.raddr, err)
			return
		}
	}

	r.conn = newConn
	n, split, err := r.writeSplitLocked()
	logeif(err)("rdial: retryLocked: strat(%d) %s->%s; split? %d; write? %d/%d; err? %v", r.dialStrat, laddr(r.conn), r.raddr, split, n, len(r.hello), err)
	if err != nil {
		return
	}

	// While we were creating the new socket, the caller might have called CloseRead
	// or CloseWrite on the old socket. Copy that state to the new socket.
	// CloseRead and CloseWrite are idempotent, so this is safe even if the user's
	// action actually affected the new socket.
	readdone := r.readDone.Load()
	writedone := r.writeDone.Load()
	if readdone {
		core.CloseTCPRead(r.conn)
	} else {
		_ = r.conn.SetReadDeadline(r.readDeadline)
	}
	// caller might have set read or write deadlines before the retry.
	if writedone {
		core.CloseTCPWrite(r.conn)
	} else {
		_ = r.conn.SetWriteDeadline(r.writeDeadline)
	}

	return r.conn.Read(buf)
}

// CloseRead closes r.conn for reads, and the read flag.
func (r *retrier) CloseRead() error {
	r.readDone.Store(true)
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.conn.CloseRead()
}

// Read data from r.conn into buf
func (r *retrier) Read(buf []byte) (n int, err error) {
	note := log.V

	n, err = r.conn.Read(buf)
	if n == 0 && err == nil { // no data and no error
		note("rdial: read: no data; retrying [%s<-%s]", laddr(r.conn), r.raddr)
		return // nothing yet to retry; on to next read
	}
	mustretry := err != nil
	logeor(err, note)("rdial: read: [%s<-%s] %d; mustretry? %t; err: %v", laddr(r.conn), r.raddr, n, mustretry, err)

	note = log.D
	if !r.retryCompleted() {
		r.mutex.Lock()
		defer r.mutex.Unlock()
		done := r.retryCompleted()
		if !done {
			defer close(r.retryDoneCh) // signal that retry is complete or unnecessary

			if mustretry { // retry; err may be timeout or conn reset
				n, err = r.retryWriteReadLocked(buf)
				note = log.I
			}
			logeor(err, note)("rdial: read: [%s<-%s] %d; retried? %t; err? %v", laddr(r.conn), r.raddr, n, mustretry, err)
			// todo: reset deadlines only if no err?
			_ = r.conn.SetReadDeadline(r.readDeadline)
			_ = r.conn.SetWriteDeadline(r.writeDeadline)
			// reset hello
			r.hello = nil
			return
		}
		logeor(err, note)("rdial: read: already retried! [%s<-%s] %d; err? %v", laddr(r.conn), r.raddr, n, err)
	} // else: just one read is enough; no retry needed
	return
}

func (r *retrier) sendCopyHello(b []byte) (n int, didWrite bool, src net.Addr, err error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	src = laddr(r.conn)
	if !r.retryCompleted() { // first write
		n, err = r.conn.Write(b)
		r.hello = append(r.hello, b[:n]...) // capture first write, "hello"
		// require a response or another write within a short timeout.
		_ = r.conn.SetReadDeadline(time.Now().Add(r.timeout))
		didWrite = true
	}
	return
}

// Write data in b to r.conn
func (r *retrier) Write(b []byte) (int, error) {
	// Double-checked locking pattern.  This avoids lock acquisition on
	// every packet after retry completes, while also ensuring that r.hello is
	// empty at steady-state.
	if !r.retryCompleted() {
		n, sent, srcaddr, err := r.sendCopyHello(b)

		note := log.D
		if sent {
			note = log.I
		}

		logeor(err, note)("rdial: write: first?(%t) [%s->%s] %d; 1st write-err? %v", sent, srcaddr, r.raddr, n, err)

		if sent {
			// since Write() does not wait for <-retryDoneCh if there are no errors,
			// it is possible that ReadFrom() -> copyOnce() is called before retryDoneCh
			// is closed, resulting in two Write() calls, and r.hello containing buffers
			// the size of two Writes()
			if err == nil {
				return n, nil
			}
			err = nil

			leftover := b[n:]

			start := time.Now()
			// write error on the provisional socket should be handled
			// by the retry procedure. Block until we have a final socket (which will
			// already have replayed b[:n]), and retry.
			<-r.retryDoneCh

			r.mutex.Lock()
			c := r.conn
			r.mutex.Unlock()

			elapsed := time.Since(start).Milliseconds()

			m := 0
			if len(leftover) > 0 {
				m, err = c.Write(leftover)
			}
			logeor(err, note)("rdial: write retried [%s->%s] %d in %dms; 2nd write-err? %v", laddr(c), r.raddr, m, elapsed, err)
			return n + m, err
		}
	}

	// retryCompleted() is true, so r.conn is final and doesn't need locking
	return r.conn.Write(b)
}

// ReadFrom reads data from reader into r.conn.ReadFrom, after
// retries are done; before which reads are delegated to copyOnce.
func (r *retrier) ReadFrom(reader io.Reader) (bytes int64, err error) {
	copies := 0
	for !r.retryCompleted() {
		b, e := copyOnce(r, reader)

		copies++
		bytes += b

		logeif(err)("rdial: readfrom: copyOnce #%d; sz: %d/%d; err: %v", copies, b, bytes, err)
		if e != nil {
			return bytes, e
		}
	}

	// retryCompleted() is true, so r.conn is final and doesn't need locking
	var b int64
	b, err = r.conn.ReadFrom(reader)
	bytes += b

	logeif(err)("rdial: readfrom: done; sz: %d; err: %v", bytes, err)
	return
}

// CloseWrite closes r.conn for writes, the write flag.
func (r *retrier) CloseWrite() error {
	r.writeDone.Store(true)
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.conn.CloseWrite()
}

// Close closes the connection and the read and write flags.
func (r *retrier) Close() error {
	// also close the read and write flags
	return errors.Join(r.CloseRead(), r.CloseWrite())
}

// LocalAddr behaves slightly strangely: its value may change as a
// result of a retry.  However, LocalAddr is largely useless for
// TCP client sockets anyway, so nothing should be relying on this.
func (r *retrier) LocalAddr() net.Addr {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.conn.LocalAddr()
}

// RemoteAddr returns the remote address of the connection.
func (r *retrier) RemoteAddr() net.Addr {
	return r.raddr
}

// SetReadDeadline sets the read deadline for the connection
// if the retry is complete, otherwise it does so after the retry.
func (r *retrier) SetReadDeadline(t time.Time) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.readDeadline = t
	// Don't enforce read deadlines until after the retry
	// is complete. Retry relies on setting its own read
	// deadline, and we don't want this to interfere.
	if r.retryCompleted() {
		return r.conn.SetReadDeadline(t)
	}
	return nil
}

// SetWriteDeadline sets the write deadline for the connection.
func (r *retrier) SetWriteDeadline(t time.Time) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.writeDeadline = t
	return r.conn.SetWriteDeadline(t)
}

// SetDeadline sets the read and write deadlines for the connection.
// Read deadlines are set eventually depending on the status of retries.
func (r *retrier) SetDeadline(t time.Time) error {
	e1 := r.SetReadDeadline(t)
	e2 := r.SetWriteDeadline(t)
	return errors.Join(e1, e2)
}

// Copy one buffer from src to dst, using dst.Write.
func copyOnce(dst io.Writer, src io.Reader) (int64, error) {
	// A buffer large enough to hold any ordinary first write
	// without introducing extra splitting.
	bptr := core.Alloc()
	buf := *bptr
	buf = buf[:cap(buf)]
	defer func() {
		*bptr = buf
		core.Recycle(bptr)
	}()

	var dstaddr, srcaddr net.Addr
	switch r := dst.(type) {
	case *retrier:
		srcaddr = laddr(r.conn)
		dstaddr = r.raddr
	case *splitter:
		srcaddr = laddr(r)
		dstaddr = raddr(r)
	case *overwriteSplitter:
		srcaddr = laddr(r)
		dstaddr = raddr(r)
	case net.Conn:
		srcaddr = laddr(r)
		dstaddr = raddr(r)
	default:
		log.W("rdial: copyOnce: unknown dst type %T", dst)
	}

	n, err := src.Read(buf) // src: netstack; downstream conn
	if err != nil {
		log.W("rdial: copyOnce: read [%s->%s] %d/%d; err %v", srcaddr, dstaddr, n, len(buf), err)
		return 0, err
	}
	wn, err := dst.Write(buf[:n]) // dst: retrier; upstream conn

	logeif(err)("rdial: copyOnce: rw [%s->%s] %d/%d; err %v", srcaddr, dstaddr, n, wn, err)

	return int64(n), err
}

func getTLSClientHelloRecordLen(h []byte) (uint16, bool) {
	if len(h) < 5 {
		return 0, false
	}

	const (
		TYPE_HANDSHAKE byte   = 22
		VERSION_TLS10  uint16 = 0x0301
		VERSION_TLS11  uint16 = 0x0302
		VERSION_TLS12  uint16 = 0x0303
		VERSION_TLS13  uint16 = 0x0304
	)

	if h[0] != TYPE_HANDSHAKE {
		return 0, false
	}

	ver := binary.BigEndian.Uint16(h[1:3])
	if ver != VERSION_TLS10 && ver != VERSION_TLS11 &&
		ver != VERSION_TLS12 && ver != VERSION_TLS13 {
		return 0, false
	}

	return binary.BigEndian.Uint16(h[3:5]), true
}

func (r *retrier) writeSplitLocked() (n, splitLen int, err error) {
	return writeSplit(r.dialStrat, r.conn, r.hello)
}

func writeSplit(strat int32, w net.Conn, b []byte) (n, splitLen int, err error) {
	switch strat {
	case settings.SplitTCPStrategy:
		n, splitLen, err = writeTCPSplit(w, b)
	case settings.SplitTCPOrTLSStrategy:
		n, splitLen, err = writeTCPOrTLSSplit(w, b)
	case settings.DesyncStrategy:
		n, err = writeDesync(w, b)
		// desync does not always split
		splitLen = len(desync_http1_1str)
	default:
		n, err = w.Write(b)
	}
	return
}

func writeDesync(w io.Writer, b []byte) (n int, err error) {
	return w.Write(b)
}

func writeTCPSplit(w net.Conn, hello []byte) (n, splitLen int, err error) {
	var p, q int
	to := raddr(w)
	from := laddr(w)

	first, second := splitHello(hello)

	splitLen = len(first)

	if p, err = w.Write(first); err != nil {
		log.E("rdial: retryLocked: TCP split1 %s (%d): err %v", to, len(first), err)
		return p, splitLen, err
	} else if q, err = w.Write(second); err != nil {
		log.E("rdial: retryLocked: TCP split2 %s (%d): err %v", to, len(second), err)
		return p + q, splitLen, err
	}
	log.D("rdial: retryLocked: %s->%s; TCP splits: %d,%d", from, to, len(first), len(second))

	return p + q, splitLen, nil
}

// from: github.com/Jigsaw-Code/Intra/blob/27637e0ed497/Android/app/src/go/intra/split/retrier.go#L245
func writeTCPOrTLSSplit(w net.Conn, hello []byte) (n, splitLen int, err error) {
	to := raddr(w)
	from := laddr(w)

	if len(hello) <= 1 {
		n, err = w.Write(hello)
		log.D("rdial: Splits: %s->%s; len(hello) <= 1; n: %d; err: %v", from, to, n, err)
		return
	}

	const (
		MIN_SPLIT int = 6
		MAX_SPLIT int = 64
	)

	// random number in the range [MIN_SPLIT, MAX_SPLIT]
	// splitLen includes 5 bytes of TLS header
	splitLen = MIN_SPLIT + rand.Intn(MAX_SPLIT+1-MIN_SPLIT)
	limit := len(hello) / 2
	if splitLen > limit {
		splitLen = limit
	}

	recordLen, ok := getTLSClientHelloRecordLen(hello)
	recordSplitLen := splitLen - 5
	if !ok || recordSplitLen <= 0 || recordSplitLen >= int(recordLen) {
		// TCP split if hello is not a valid TLS Client Hello, or cannot be fragmented
		n, err = w.Write(hello[:splitLen])
		if err == nil {
			var m int
			m, err = w.Write(hello[splitLen:])
			n += m
		}
		log.D("rdial: Splits: %s->%s; TCP %d/%d; n: %d; err: %v", from, to, splitLen, len(hello), n, err)
		return
	}

	parcel := hello[:splitLen]
	binary.BigEndian.PutUint16(parcel[3:5], uint16(recordSplitLen))
	if n, err = w.Write(parcel); err != nil {
		log.E("rdial: Splits: %s->%s; TLS1 %d/%d; n: %d; err: %v", from, to, splitLen, len(hello), n, err)
		return
	}

	parcel = hello[splitLen-5:]
	copy(parcel, hello[:5])
	binary.BigEndian.PutUint16(parcel[3:5], recordLen-uint16(recordSplitLen))

	m, err := w.Write(parcel)
	n += m

	logeif(err)("rdial: Splits: %s->%s; TLS2 %d/%d; n: %d; err: %v", from, to, splitLen, len(hello), n, err)
	return
}

// splitHello splits the TLS client hello message into two.
func splitHello(hello []byte) ([]byte, []byte) {
	if len(hello) == 0 {
		return hello, hello
	}
	const (
		min int = 32
		max int = 64
	)

	// Random number in the range [MIN_SPLIT, MAX_SPLIT]
	s := min + rand.Intn(max+1-min)
	limit := len(hello) / 2
	if s > limit {
		s = limit
	}
	return hello[:s], hello[s:]
}

// laddr returns the local address of the connection.
func laddr(c net.Conn) net.Addr {
	if c != nil && core.IsNotNil(c) {
		return c.LocalAddr()
	}
	return zeroNetAddr{}
}

func raddr(c net.Conn) net.Addr {
	if c != nil && core.IsNotNil(c) {
		return c.RemoteAddr()
	}
	return zeroNetAddr{}
}

func logeif(e error) log.LogFn {
	if e != nil {
		return log.E
	} else {
		return log.D
	}
}

func logeor(e error, d log.LogFn) log.LogFn {
	if e != nil {
		return log.E
	}
	return d
}
