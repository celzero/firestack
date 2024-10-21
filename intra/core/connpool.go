// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/celzero/firestack/intra/log"
	"github.com/miekg/dns"
	"golang.org/x/sys/unix"
)

const pooluseread = false                 // never used; for documentation only
const poolcapacity = 8                    // default capacity
const poolmaxattempts = poolcapacity / 2  // max attempts to retrieve a conn from pool
const Nobody = uintptr(0)                 // nobody
const poolscrubinterval = 5 * time.Minute // interval between subsequent scrubs
const poolmaxttl = 8 * time.Minute        // close unused pooled conns after this period

// go.dev/play/p/ig2Zpk-LTSv
var (
	kaidle     = int(poolmaxttl / 5 / time.Second)  // 8m / 5 => 96s
	kainterval = int(poolmaxttl / 10 / time.Second) // 8m / 10 => 48s
)

var (
	errUnexpectedRead   = errors.New("pool: unexpected read")
	errNotSyscallConn   = errors.New("pool: not a syscall.Conn")
	errAttemptsExceeded = errors.New("pool: max attempts exceeded")
)

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
		ctx:       ctx,
		m:         make(map[T]*superpool[T]),
		scrubtime: time.Now(),
	}
}

func (m *MultConnPool[T]) scrub() {
	now := time.Now()
	if now.Sub(m.scrubtime) <= poolscrubinterval { // too soon
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
				Go("pool.scrub", super.pool.scrub)
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

func (m *MultConnPool[T]) Put(id T, conn net.Conn) (ok bool) {
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

type agingconn struct {
	c   net.Conn     // pooled conn
	sc  PoolableConn // raw conn; may be nil
	dob time.Time    // induction time
	str string       // local and remote addrs
}

func newAgingConn(c net.Conn) agingconn {
	var sc PoolableConn

	s := conn2str(c)
	if sc, _ = c.(PoolableConn); sc != nil {
		// ok
	} else if dc, _ := c.(*dns.Conn); dc != nil {
		if tc, _ := dc.Conn.(*tls.Conn); tc != nil {
			if sc, _ = tc.NetConn().(PoolableConn); sc == nil {
				log.W("pool: dnsconn != sysconn: %T", tc.NetConn())
			} // else: ok
		} else if sc, _ = dc.Conn.(PoolableConn); sc == nil {
			log.W("pool: dnsconn != sysconn: %T", dc.Conn)
		} // else: ok
	} else if tc, _ := c.(*tls.Conn); tc != nil {
		if sc, _ = tc.NetConn().(PoolableConn); sc == nil {
			log.W("pool: tlsconn != sysconn: %T", tc.NetConn())
		} // else: ok
	} // sc is nil
	return agingconn{c, sc, time.Time{}, s}
}

// github.com/redis/go-redis/blob/d9eeed13/internal/pool/pool.go
type ConnPool[T comparable] struct {
	ctx    context.Context
	id     T
	p      chan agingconn // never closed
	closed atomic.Bool
}

func NewConnPool[T comparable](ctx context.Context, id T) *ConnPool[T] {
	c := &ConnPool[T]{
		ctx: ctx,
		id:  id,
		p:   make(chan agingconn, poolcapacity),
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

	pooled, complete := Grx("pool.get", func(ctx context.Context) (zz net.Conn, err error) {
		i := 0
		for i < poolmaxattempts {
			i++
			select {
			case aconn := <-c.p:
				// if readable, return conn regardless of its freshness
				if aconn.readable() {
					aconn.keepalive(false)
					return aconn.c, nil
				}
				(&aconn).close()
			case <-ctx.Done():
				return // signal stop
			default:
				return // empty
			}
		}
		return nil, errAttemptsExceeded // maxattempts exceeded
	}, timeout)

	empty := IsNil(pooled) // or maxattempts exceeded
	timedout := !complete
	logevif(timedout || empty)("pool: %v get: empty? %t, timedout? %t",
		c.id, empty, timedout)

	return pooled
}

// Put puts conn back in the pool.
// Put takes ownership of the conn regardless of the return value.
func (c *ConnPool[T]) Put(conn net.Conn) (ok bool) {
	defer func() {
		if !ok {
			CloseConn(conn)
		}
	}()

	if c.closed.Load() {
		return
	}
	if c.full() {
		return
	}

	aconn := newAgingConn(conn)
	if !aconn.readable() {
		return false
	}

	select {
	case c.p <- aconn:
		aconn.keepalive(true)
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
	return len(c.p) > poolcapacity
}

func (c *ConnPool[T]) clean() {
	// todo: defer close(c.p)

	ok := c.closed.CompareAndSwap(false, true)
	log.I("pool: %v closed? %t", c.id, ok)
	for {
		select {
		case aconn := <-c.p:
			(&aconn).close()
		default:
			return
		}
	}
}

func (c *ConnPool[T]) scrub() {
	if c.closed.Load() {
		return
	}

	staged := make([]agingconn, 0)
	defer func() {
		for _, aconn := range staged {
			kept := false
			select {
			case <-c.ctx.Done(): // closed
			default:
				select {
				case c.p <- aconn: // put it back in
					kept = true
				case <-c.ctx.Done(): // closed
				default: // pool full
				}
			}
			if !kept {
				(&aconn).close()
			}
		}
	}()

	for {
		select {
		case aconn := <-c.p:
			if aconn.ok() {
				staged = append(staged, aconn)
			} else {
				(&aconn).close()
			} // next
		case <-c.ctx.Done(): // closed
			return
		default: // empty
			return
		}
	}
}

func (a agingconn) ok() bool {
	return a.fresh() &&
		a.readable()
}

func (a agingconn) fresh() bool {
	return a.dob != (time.Time{}) &&
		time.Since(a.dob) < poolmaxttl
}

func (a *agingconn) close() {
	a.dob = time.Time{}
	CloseConn(a.c)
}

// github.com/golang/go/issues/15735
func (a agingconn) readable() bool {
	err := a.canread()

	logev(err)("pool: %s sysconn? %T readable? %t; err? %v",
		a.str, a.c, err == nil, err)
	return err == nil
}

func (a agingconn) keepalive(y bool) bool {
	if y {
		cleardeadline(a.c) // reset any previous timeout
		return SetKeepAliveConfigSockOpt(a.c, kaidle, kainterval)
	} else {
		if tc, ok := a.c.(*net.TCPConn); ok {
			return tc.SetKeepAlive(false) == nil
		}
		return false
	}
}

// github.com/go-sql-driver/mysql/blob/f20b28636/conncheck.go
// github.com/redis/go-redis/blob/cc9bcb0c0/internal/pool/conn_check.go
func (a agingconn) canread() error {
	sc := a.sc
	if sc == nil {
		return errNotSyscallConn
	}

	var checkErr error
	var ctlErr error

	raw, err := sc.SyscallConn()
	if err != nil {
		return fmt.Errorf("pool: sysconn: %w", err)
	}

	if pooluseread { // stackoverflow.com/q/12741386
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

func logev(err error) log.LogFn {
	return logevif(err != nil)
}

func logevif(e bool) log.LogFn {
	if e {
		return log.E
	}
	return log.V
}
