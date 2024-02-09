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
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
)

// retrier implements the DuplexConn interface and must
// be typecastable to *net.TCPConn (see: xdial.DialTCP)
// inheritance: go.dev/play/p/mMiQgXsPM7Y
type retrier struct {
	// the current underlying connection.  It is only modified by the reader
	// thread, so the reader functions may access it without acquiring a lock.
	// nb: if embedding TCPConn; override its WriteTo instead of just ReadFrom
	// as io.Copy prefers WriteTo over ReadFrom
	conn *net.TCPConn
	// mutex is a lock that guards `conn`, `hello`, and `retryCompleteFlag`.
	// These fields must not be modified except under this lock.
	// After retryCompletedFlag is closed, these values will not be modified
	// again so locking is no longer required for reads.
	mutex sync.Mutex
	dial  *protect.RDial
	addr  *net.TCPAddr
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
	retryCompleteFlag chan struct{}
	// Flags indicating whether the caller has called CloseRead and CloseWrite.
	readCloseFlag  chan struct{}
	writeCloseFlag chan struct{}
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
func closed(c chan struct{}) bool {
	select {
	case <-c:
		// The channel has been closed.
		return true
	default:
		return false
	}
}

func (r *retrier) readClosed() bool {
	return closed(r.readCloseFlag)
}

func (r *retrier) writeClosed() bool {
	return closed(r.writeCloseFlag)
}

func (r *retrier) retryCompleted() bool {
	return closed(r.retryCompleteFlag)
}

// Given timestamps immediately before and after a successful socket connection
// (i.e. the time the SYN was sent and the time the SYNACK was received), this
// function returns a reasonable timeout for replies to a hello sent on this socket.
func calcTimeout(before, after time.Time) time.Duration {
	// These values were chosen to have a <1% false positive rate based on test data.
	// False positives trigger an unnecessary retry, which can make connections slower, so they are
	// worth avoiding.  However, overly long timeouts make retry slower and less useful.
	rtt := after.Sub(before)
	return 1200*time.Millisecond + min(2*rtt, 400*time.Millisecond)
}

// DefaultTimeout is the value that will cause DialWithSplitRetry to use the system's
// default TCP timeout (typically 2-3 minutes).
const DefaultTimeout time.Duration = 0

// DialWithSplitRetry returns a TCP connection that transparently retries by
// splitting the initial upstream segment if the socket closes without receiving a
// reply.  Like net.Conn, it is intended for two-threaded use, with one thread calling
// Read and CloseRead, and another calling Write, ReadFrom, and CloseWrite.
// `dialer` will be used to establish the connection.
// `addr` is the destination.
func DialWithSplitRetry(dial *protect.RDial, addr *net.TCPAddr) (DuplexConn, error) {
	before := time.Now()
	conn, err := dial.DialTCP(addr.Network(), nil, addr)
	if err != nil {
		return nil, err
	}
	after := time.Now()

	r := &retrier{
		conn:              conn,
		dial:              dial,
		addr:              addr,
		timeout:           calcTimeout(before, after),
		retryCompleteFlag: make(chan struct{}),
		readCloseFlag:     make(chan struct{}),
		writeCloseFlag:    make(chan struct{}),
	}

	return r, nil
}

func (r *retrier) retryLocked(buf []byte) (err error) {
	_ = r.conn.Close() // close provisional socket
	var newConn *net.TCPConn
	if newConn, err = r.dial.DialTCP(r.addr.Network(), nil, r.addr); err != nil {
		return
	}
	r.conn = newConn
	first, second := splitHello(r.hello)
	if _, err = r.conn.Write(first); err != nil {
		return
	}
	if _, err = r.conn.Write(second); err != nil {
		return
	}
	// While we were creating the new socket, the caller might have called CloseRead
	// or CloseWrite on the old socket. Copy that state to the new socket.
	// CloseRead and CloseWrite are idempotent, so this is safe even if the user's
	// action actually affected the new socket.
	if r.readClosed() {
		_ = r.conn.CloseRead()
	} else {
		_ = r.conn.SetReadDeadline(r.readDeadline)
	}
	// caller might have set read or write deadlines before the retry.
	if r.writeClosed() {
		_ = r.conn.CloseWrite()
	} else {
		_ = r.conn.SetWriteDeadline(r.writeDeadline)
	}
	return
}

func (r *retrier) CloseRead() error {
	if !r.readClosed() {
		close(r.readCloseFlag)
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.conn.CloseRead()
}

// Read data from r.TCPConn into buf
func (r *retrier) Read(buf []byte) (n int, err error) {
	n, err = r.conn.Read(buf)
	if n == 0 && err == nil { // no data and no error
		return // nothing yet to retry; on to next read
	}
	var retryerr error
	retryNeeded := err != nil
	if !r.retryCompleted() {
		r.mutex.Lock()
		if retryNeeded {
			// retry only on errors; may be due to timeout or conn reset
			if retryerr = r.retryLocked(buf); retryerr == nil {
				n, err = r.conn.Read(buf)
			}
		}
		log.D("rdial: read: reset; retried?(%t) [%s<-%s] %d; read-err? %v, retry-err? %v", retryNeeded, r.conn.LocalAddr(), r.addr, n, err, retryerr)
		close(r.retryCompleteFlag)
		// reset deadlines
		_ = r.conn.SetReadDeadline(r.readDeadline)
		_ = r.conn.SetWriteDeadline(r.writeDeadline)
		// _ = r.conn.SetReadDeadline(time.Time{})
		// reset hello and signal that retry is complete
		r.hello = nil
		r.mutex.Unlock()
	}
	return
}

// Write data in b to r.TCPConn
func (r *retrier) Write(b []byte) (int, error) {
	// Double-checked locking pattern.  This avoids lock acquisition on
	// every packet after retry completes, while also ensuring that r.hello is
	// empty at steady-state.
	if !r.retryCompleted() {
		n := 0
		var err error
		attempted := false
		r.mutex.Lock()
		if !r.retryCompleted() { // nothing to retry
			n, err = r.conn.Write(b)
			attempted = true
			r.hello = append(r.hello, b[:n]...)
			// require a response or another write within a short timeout.
			_ = r.conn.SetReadDeadline(time.Now().Add(r.timeout))
		}

		log.D("rdial: write retry?(%t) [%s->%s] %d; write-err? %v", attempted, r.conn.LocalAddr(), r.addr, n, err)
		r.mutex.Unlock()
		if attempted {
			if err == nil {
				return n, nil
			}
			// write error on the provisional socket should be handled
			// by the retry procedure. Block until we have a final socket (which will
			// already have replayed b[:n]), and retry.
			<-r.retryCompleteFlag
			m, err := r.conn.Write(b[n:])
			log.D("rdial: write retried(%t) [%s->%s] %d; write-err? %v", attempted, r.conn.LocalAddr(), r.addr, n+m, err)
			return n + m, err
		}
	}

	// retryCompleted() is true, so r.conn is final and doesn't need locking.
	return r.conn.Write(b)
}

func (r *retrier) ReadFrom(reader io.Reader) (bytes int64, err error) {
	for !r.retryCompleted() {
		if bytes, err = copyOnce(r, reader); err != nil {
			return
		}
	}

	var b int64
	b, err = r.conn.ReadFrom(reader)
	bytes += b
	return
}

func (r *retrier) CloseWrite() error {
	if !r.writeClosed() {
		close(r.writeCloseFlag)
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.conn.CloseWrite()
}

func (r *retrier) Close() error {
	if err := r.CloseWrite(); err != nil {
		return err
	}
	return r.CloseRead()
}

// LocalAddr behaves slightly strangely: its value may change as a
// result of a retry.  However, LocalAddr is largely useless for
// TCP client sockets anyway, so nothing should be relying on this.
func (r *retrier) LocalAddr() net.Addr {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.conn.LocalAddr()
}

func (r *retrier) RemoteAddr() net.Addr {
	return r.addr
}

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

func (r *retrier) SetWriteDeadline(t time.Time) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.writeDeadline = t
	return r.conn.SetWriteDeadline(t)
}

func (r *retrier) SetDeadline(t time.Time) error {
	e1 := r.SetReadDeadline(t)
	e2 := r.SetWriteDeadline(t)
	return errors.Join(e1, e2)
}

// Copy one buffer from src to dst, using dst.Write.
func copyOnce(dst io.Writer, src io.Reader) (int64, error) {
	// A buffer large enough to hold any ordinary first write
	// without introducing extra splitting.
	buf := *core.Alloc()
	buf = buf[:cap(buf)]
	defer func() {
		core.Recycle(&buf)
	}()

	n, err := src.Read(buf)
	if err != nil {
		return 0, err
	}
	n, err = dst.Write(buf[:n])
	return int64(n), err
}

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
