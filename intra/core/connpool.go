// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/celzero/firestack/intra/log"
	"golang.org/x/sys/unix"
)

const useread = false                 // always false; here for doc purposes
const poolcapacity = 8                // default capacity
const maxattempts = poolcapacity / 2  // max attempts to retrieve a conn from pool
const Nobody = uintptr(0)             // nobody
const scrubinterval = 5 * time.Minute // interval between subsequent scrubs
const maxttl = 8 * time.Minute        // close unused pooled conns after this period

// go.dev/play/p/ig2Zpk-LTSv
var (
	kaidle     = int(maxttl / 5 / time.Second)  // 8m / 5 => 96s
	kainterval = int(maxttl / 10 / time.Second) // 8m / 10 => 48s
)
var errUnexpectedRead error = errors.New("pool: unexpected read")

type superpool[T comparable] struct {
	quit context.CancelFunc
	pool *ConnPool[T]
}

type MultConnPool[T comparable] struct {
	ctx       context.Context
	mu        sync.RWMutex
	m         map[T]*superpool[T]
	scrubtime time.Time
}

func NewMultConnPool[T comparable](ctx context.Context) *MultConnPool[T] {
	return &MultConnPool[T]{
		ctx: ctx,
		m:   make(map[T]*superpool[T]),
	}
}

func (m *MultConnPool[T]) scrub() {
	now := time.Now()
	if now.Sub(m.scrubtime) <= scrubinterval { // too soon
		return
	}
	m.scrubtime = now

	select {
	case <-m.ctx.Done():
		return
	default:
	}

	Go("superpool.scrub", func() {
		m.mu.Lock()
		defer m.mu.Unlock()

		var n, nclosed, nquit, nscrubbed int
		n = len(m.m)
		for id, super := range m.m {
			if super.pool.closed.Load() {
				nclosed++
				delete(m.m, id)
			} else if super.pool.empty() {
				nquit++
				super.quit()
				delete(m.m, id)
			} else {
				nscrubbed++
				Go("poo.scrub", super.pool.scrub)
			}
		}

		log.D("pool: scrubbed: %d, closed: %d, quit: %d, total: %d",
			nscrubbed, nclosed, nquit, n)
	})
}

func (m *MultConnPool[T]) Get(id T) net.Conn {
	if IsZero(id) {
		return nil
	}

	m.mu.RLock()
	super := m.m[id]
	m.mu.RUnlock()

	if super != nil {
		return super.pool.Get()
	}
	return nil
}

func (m *MultConnPool[T]) Put(id T, conn net.Conn) bool {
	if IsZero(id) || IsNil(conn) {
		return false
	}

	m.mu.RLock() // read lock
	super := m.m[id]
	m.mu.RUnlock()

	if super == nil {
		m.mu.Lock() // double check with write lock
		if super = m.m[id]; super == nil {
			child, sigstop := context.WithCancel(m.ctx)
			super = &superpool[T]{sigstop, NewConnPool(child, id)}
			m.m[id] = super
		}
		m.mu.Unlock()
	}

	m.scrub()
	return super.pool.Put(conn)
}

type timedconn struct {
	c   net.Conn
	dob time.Time
}

// github.com/redis/go-redis/blob/d9eeed13/internal/pool/pool.go
type ConnPool[T comparable] struct {
	ctx    context.Context
	id     T
	p      chan timedconn // never closed
	closed atomic.Bool
}

func NewConnPool[T comparable](ctx context.Context, id T) *ConnPool[T] {
	c := &ConnPool[T]{
		ctx: ctx,
		id:  id,
		p:   make(chan timedconn, poolcapacity),
	}

	context.AfterFunc(ctx, c.clean)
	return c
}

func (c *ConnPool[T]) Get() (zz net.Conn) {
	if c.closed.Load() {
		return
	}

	if len(c.p) == 0 {
		return
	}

	pooled, complete := Grx("pool.get", func(ctx context.Context) (zz net.Conn) {
		i := 0
		for i < maxattempts {
			i++
			select {
			case tconn := <-c.p:
				// if readable, return conn regardless of its freshness
				if readable(tconn.c) {
					nokeepalive(tconn.c)
					return tconn.c
				}
				CloseConn(tconn.c)
			case <-ctx.Done():
				return // signal stop
			default:
				return // empty
			}
		}
		return // maxattempts exceeded
	}, timeout)

	empty := IsNil(pooled) // or maxattempts exceeded
	timedout := !complete
	logevif(timedout || empty)("pool: %v get: empty? %t, timedout? %t",
		c.id, empty, timedout)

	return pooled
}

func (c *ConnPool[T]) Put(conn net.Conn) (ok bool) {
	if c.closed.Load() {
		return
	}
	if c.full() {
		return
	}

	tconn := timedconn{conn, time.Now()}
	select {
	case c.p <- tconn:
		cleardeadline(conn) // reset any previous timeout
		keepalive(conn)
		return true
	case <-c.ctx.Done(): // stop
		return false
	default: // pool full
		return false
	}
}

func (c *ConnPool[T]) empty() bool {
	return len(c.p) == 0
}

func (c *ConnPool[T]) full() bool {
	return len(c.p) >= poolcapacity
}

func (c *ConnPool[T]) clean() {
	// defer close(c.p)

	ok := c.closed.CompareAndSwap(false, true)
	log.I("pool: %v closed? %t", c.id, ok)
	for {
		select {
		case tconn := <-c.p:
			CloseConn(tconn.c)
		default:
			return
		}
	}
}

func (c *ConnPool[T]) scrub() {
	for {
		if c.closed.Load() {
			return
		}

		select {
		case tconn := <-c.p:
			if fresh(tconn.dob) && readable(tconn.c) {
				select {
				case c.p <- tconn: // update dob only on Put()
				case <-c.ctx.Done(): // stop
					CloseConn(tconn.c)
					return
				default: // full
					CloseConn(tconn.c)
				}
			} else {
				CloseConn(tconn.c)
			}
		case <-c.ctx.Done():
			return
		default:
			return
		}
	}
}

func fresh(t time.Time) bool {
	return time.Since(t) < maxttl
}

// github.com/golang/go/issues/15735
func readable(c net.Conn) bool {
	var err error
	id := conn2str(c)
	// must use syscall.Conn: github.com/golang/go/issues/65143
	switch x := c.(type) {
	case syscall.Conn:
		err = canread(x)
	default:
	}
	logev(err)("pool: %s readable? %t; err? %v", id, err == nil, err)
	return err == nil
}

// github.com/go-sql-driver/mysql/blob/f20b28636/conncheck.go
// github.com/redis/go-redis/blob/cc9bcb0c0/internal/pool/conn_check.go
func canread(sc syscall.Conn) error {
	var checkErr error
	var ctlErr error

	raw, err := sc.SyscallConn()
	if err != nil {
		return fmt.Errorf("pool: sysconn: %w", err)
	}

	if useread { // stackoverflow.com/q/12741386
		ctlErr = raw.Read(func(fd uintptr) bool {
			// 0 byte reads do not work to detect readability:
			// see: go-review.googlesource.com/c/go/+/23227
			// pitfalls: github.com/redis/go-redis/issues/3137
			var buf [1]byte
			n, err := syscall.Read(int(fd), buf[:])
			switch {
			case n == 0 && err == nil:
				checkErr = io.EOF
			case n > 0:
				// conn is supposed to be idle
				checkErr = errUnexpectedRead
			case err == syscall.EAGAIN || err == syscall.EWOULDBLOCK:
				checkErr = nil
			default:
				checkErr = err
			}
			return true
		})
	} else {
		ctlErr = raw.Control(func(fd uintptr) {
			fds := []unix.PollFd{
				{Fd: int32(fd), Events: unix.POLLIN | unix.POLLERR},
			}
			n, err := unix.Poll(fds, 0)
			if err != nil {
				checkErr = fmt.Errorf("pool: poll: err: %v", err)
			}
			if n > 0 {
				checkErr = fmt.Errorf("pool: poll: sz: %d (must be 0), errno: %v",
					n, fds[0].Revents)
			}
		})
	}
	return errors.Join(ctlErr, checkErr) // may return nil
}

func keepalive(c net.Conn) bool {
	return SetKeepAliveConfigSockOpt(c, kaidle, kainterval)
}

func nokeepalive(c net.Conn) bool {
	if tc, ok := c.(*net.TCPConn); ok {
		return tc.SetKeepAlive(false) == nil
	}
	return false
}

func logev(err error) log.LogFn {
	return logevif(err != nil)
}

func logevif(e bool) log.LogFn {
	if e {
		return log.E
	}
	return log.D
}
