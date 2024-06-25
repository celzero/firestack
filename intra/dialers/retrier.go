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
)

type zeroNetAddr struct{}

func (zeroNetAddr) Network() string { return "no" }
func (zeroNetAddr) String() string  { return "none" }

// retrier implements the DuplexConn interface and must
// be typecastable to *net.TCPConn (see: xdial.DialTCP)
// inheritance: go.dev/play/p/mMiQgXsPM7Y
type retrier struct {
	dial  *protect.RDial
	raddr *net.TCPAddr

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
	// as io.Copy prefers WriteTo over ReadFrom
	conn *net.TCPConn

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
	return 1200*time.Millisecond + max(2*rtt, 400*time.Millisecond)
}

// DialWithSplitRetry returns a TCP connection that transparently retries by
// splitting the initial upstream segment if the socket closes without receiving a
// reply.  Like net.Conn, it is intended for two-threaded use, with one thread calling
// Read and CloseRead, and another calling Write, ReadFrom, and CloseWrite.
// `dialer` will be used to establish the connection.
// `addr` is the destination.
func DialWithSplitRetry(dial *protect.RDial, addr *net.TCPAddr) (*retrier, error) {
	before := time.Now()
	conn, err := dial.DialTCP(addr.Network(), nil, addr)
	if err != nil {
		log.E("rdial: tcp addr %s: err %v", addr, err)
		return nil, err
	}
	after := time.Now()

	r := &retrier{
		conn:        conn,
		dial:        dial,
		raddr:       addr,
		timeout:     calcTimeout(before, after),
		retryDoneCh: make(chan struct{}),
	}

	log.V("rdial: dial: %s->%s; timeout %v", laddr(conn), addr, r.timeout)
	return r, nil
}

// retryLocked closes the current connection, dials a new one, and writes the TLS client hello
// message after splitting it in to two. It returns an error if the dial fails or if the
// split TLS client hello messages could not be written.
func (r *retrier) retryLocked(buf []byte) (n int, err error) {
	clos(r.conn) // close provisional socket
	var newConn *net.TCPConn
	if newConn, err = r.dial.DialTCP(r.raddr.Network(), nil, r.raddr); err != nil {
		log.E("rdial: retryLocked: dial %s: err %v", r.raddr, err)
		return
	}
	r.conn = newConn
	first, second := splitHello(r.hello)
	if _, err = r.conn.Write(first); err != nil {
		log.E("rdial: retryLocked: splitWrite1 %s (%d): err %v", r.raddr, len(first), err)
		return
	}
	if _, err = r.conn.Write(second); err != nil {
		log.E("rdial: retryLocked: splitWrite2 %s (%d): err %v", r.raddr, len(second), err)
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
	if readdone || writedone {
		log.I("rdial: retryLocked: %s->%s; end read? %t, end write? %t", laddr(r.conn), r.raddr, readdone, writedone)
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
	note = log.D
	if !r.retryCompleted() {
		r.mutex.Lock()
		defer r.mutex.Unlock()
		if !r.retryCompleted() {
			defer close(r.retryDoneCh) // signal that retry is complete or unnecessary

			if mustretry { // retry; err may be timeout or conn reset
				n, err = r.retryLocked(buf)
				note = log.I
			}
			logeor(err, note)("rdial: read: [%s<-%s] %d; retried? %t; err? %v", laddr(r.conn), r.raddr, n, mustretry, err)
			// reset deadlines
			_ = r.conn.SetReadDeadline(r.readDeadline)
			_ = r.conn.SetWriteDeadline(r.writeDeadline)
			// reset hello
			r.hello = nil
			return
		} else {
			log.I("rdial: read: already retried! [%s<-%s] %d; err? %v", laddr(r.conn), r.raddr, n, err)
		}
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
			if err == nil {
				return n, nil
			}

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

				logeif(err)("rdial: write retried [%s->%s] %d in %dms; 2nd write-err? %v", laddr(c), r.raddr, m, elapsed, err)
			}
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
		var b int64
		if b, err = copyOnce(r, reader); err != nil {
			log.W("rdial: readfrom: copyOnce #%d; sz: %d; err: %v", copies, bytes, err)
			return
		}
		if b == 0 {
			log.W("rdial: readfrom: copyOnce #%d; sz: %d; err: zero byte!", copies, bytes)
		}
		copies++
		bytes += b
	}
	log.D("rdial: readfrom: copyOnce done #%d; sz: %d", copies, bytes)

	// retryCompleted() is true, so r.conn is final and doesn't need locking
	var b int64
	b, err = r.conn.ReadFrom(reader)
	bytes += b

	if err != nil {
		log.W("rdial: readfrom: sz: %d; err: %v", bytes, err)
	}
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

	n, err := src.Read(buf) // downstream conn
	if err != nil {
		log.W("rdial: copyOnce: read %d/%d; err %v", n, len(buf), err)
		return 0, err
	}
	n, err = dst.Write(buf[:n]) // retrier
	logeif(err)("rdial: copyOnce: write %d/%d; err %v", n, len(buf), err)
	return int64(n), err
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
