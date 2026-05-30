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
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"weak"

	"github.com/celzero/firestack/intra/log"
	"github.com/miekg/dns"
	"golang.org/x/sys/unix"
)

const pooluseread = false                 // never used; for documentation only
const poolcapacity = 8                    // default capacity
const poolmaxattempts = poolcapacity / 2  // max attempts to retrieve a conn from pool
const Nobody = uint64(0)                  // nobody
const poolmaxidle = 8 * time.Minute       // close unused pooled conns after this period
const poolfreshttl = 1 * time.Minute      // considered fresh if less than this period
const poolscrubinterval = poolmaxidle / 3 // interval between subsequent scrubs

// go.dev/play/p/ig2Zpk-LTSv
var (
	kaidle     = int(poolmaxidle / 5 / time.Second)  // 8m / 5 => 96s
	kainterval = int(poolmaxidle / 10 / time.Second) // 8m / 10 => 48s
)

var (
	errUnexpectedRead   = errors.New("pool: unexpected read")
	errNotSyscallConn   = errors.New("core: not a syscall.Conn")
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

// NewMultConnPool creates a new multi connection-pool.
func NewMultConnPool[T comparable](ctx context.Context) *MultConnPool[T] {
	p := &MultConnPool[T]{
		ctx:       ctx,
		m:         make(map[T]*superpool[T]),
		scrubtime: time.Now(),
	}
	return p
}

// scrub closes and removes old conns from all conn pools.
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

// Get returns a conn from the pool[id], if available.
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

// Put puts conn back in the pool[id].
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
	c   net.Conn        // pooled conn
	sc  syscall.RawConn // raw conn; may be nil
	dob time.Time       // induction time
	str string          // local and remote addrs
}

// newAgingConn creates a new agingconn.
// if c is a PoolableConn, it is used to check for readability.
// if not, c is checked for freshness.
func newAgingConn(c net.Conn) agingconn {
	if IsNil(c) {
		return agingconn{}
	}

	var sc PoolableConn

	s := conn2str(c)
	if sc, _ = c.(PoolableConn); sc != nil {
		// ok
	} else if dc, _ := c.(*dns.Conn); dc != nil {
		if tc, _ := dc.Conn.(*tls.Conn); tc != nil {
			if sc, _ = tc.NetConn().(PoolableConn); sc == nil {
				log.VV("pool: dnsconn != sysconn: %T for %s", tc.NetConn(), s)
			} // else: ok
		} else if sc, _ = dc.Conn.(PoolableConn); sc == nil {
			log.VV("pool: dnsconn != sysconn: %T for %s", dc.Conn, s)
		} // else: ok
	} else if tc, _ := c.(*tls.Conn); tc != nil {
		if sc, _ = tc.NetConn().(PoolableConn); sc == nil {
			log.VV("pool: tlsconn != sysconn: %T for %s", tc.NetConn(), s)
		} // else: ok
	} // sc is nil

	var raw syscall.RawConn
	var err error
	if sc != nil { // confirm syscall.Conn works
		raw, err = sc.SyscallConn()
		if err != nil {
			log.VV("pool: sysconn %T for %s; err %v", c, s, err)
			raw = nil
		}
	}
	return agingconn{c, raw /* may be nil */, time.Now(), s}
}

// github.com/redis/go-redis/blob/d9eeed13/internal/pool/pool.go
type ConnPool[T comparable] struct {
	ctx    context.Context
	id     T
	sid    string         // string id; used in metrics
	p      chan agingconn // never closed
	closed atomic.Bool
	nputs  atomic.Uint64 // count of successful Put() calls
	ngets  atomic.Uint64 // count of successful Get() calls
	ndels  atomic.Uint64 // count of conns evicted/closed within the pool
}

// NewConnPool creates a new conn pool with preset capacity and ttl.
func NewConnPool[T comparable](ctx context.Context, id T) *ConnPool[T] {
	c := &ConnPool[T]{
		ctx: ctx,
		id:  id,
		p:   make(chan agingconn, poolcapacity),
	}
	c.sid = fmt.Sprintf("connpool.%v", id) + "." + LocStr(c)
	sid := c.sid
	wc := weak.Make(c)
	deregister := trackmap(c.sid, func() MapState {
		if p := wc.Value(); p != nil {
			return p.Stat()
		}
		return MapState{Typ: "connpool", ID: "gc." + sid}
	})
	runtime.AddCleanup(c, func(f func()) { f() }, deregister)
	context.AfterFunc(ctx, func() {
		c.clean()
		deregister()
	})
	return c
}

// Stat returns a snapshot of the pool's current state.
func (c *ConnPool[T]) Stat() MapState {
	return MapState{
		Typ:  "connpool",
		ID:   c.sid,
		Len:  uint64(len(c.p)),
		Puts: c.nputs.Load(),
		Gets: c.ngets.Load(),
		Dels: c.ndels.Load(),
	}
}

// Get returns a conn from the pool, if available, within 3 seconds.
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
				// if readable/fresh, return conn regardless of its freshness
				if aconn.ok() {
					aconn.keepalive(false)
					return aconn.c, nil
				}
				(&aconn).close()
				c.ndels.Add(1)
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

	if !empty {
		c.ngets.Add(1)
	}
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
	if !aconn.ok() {
		return
	}

	aconn.resetDeadline()

	select {
	case c.p <- aconn:
		c.nputs.Add(1)
		aconn.keepalive(true)
		return true
	case <-c.ctx.Done(): // stop
		return
	default: // pool full
		return
	}
}

// empty returns true if pool is empty.
func (c *ConnPool[T]) empty() bool {
	return len(c.p) == 0
}

// full returns true if pool is full.
func (c *ConnPool[T]) full() bool {
	return len(c.p) > poolcapacity
}

// clean closes all conns in the pool.
func (c *ConnPool[T]) clean() {
	// todo: defer close(c.p)

	ok := c.closed.CompareAndSwap(false, true)
	log.I("pool: %v closed? %t", c.id, ok)
	for {
		select {
		case aconn := <-c.p:
			(&aconn).close()
			c.ndels.Add(1)
		default:
			return
		}
	}
}

// scrub closes and removes old conns from the pool.
func (c *ConnPool[T]) scrub() {
	if c.closed.Load() {
		return
	}

	staged := make([]agingconn, 0)
	defer func() {
		for _, aconn := range staged {
			kept := false
			select {
			case <-c.ctx.Done(): // close conn; fallthrough
			default:
				select {
				case c.p <- aconn: // put it back in
					kept = true
				case <-c.ctx.Done(): // close conn; fallthrough
				default: // pool full
				}
			}
			if !kept {
				(&aconn).close()
				c.ndels.Add(1)
			}
		}
	}()

	for {
		select {
		case aconn := <-c.p:
			if aconn.old() || !aconn.ok() {
				(&aconn).close()
				c.ndels.Add(1)
			} else {
				staged = append(staged, aconn)
			} // next
		case <-c.ctx.Done(): // closed
			return
		default: // empty
			return
		}
	}
}

// old returns true if conn must be closed,
// or it might end up far longer than desired
// (ex: with long keepalives draining power).
func (a agingconn) old() bool {
	return time.Since(a.dob) > poolmaxidle
}

// ok returns true if a is readable or fresh.
func (a agingconn) ok() bool {
	if a.sc != nil { // if sysconn, check readability
		return a.readable()
	}
	return a.fresh() // else: check freshness
}

// fresh returns true if conn is recent enough.
func (a agingconn) fresh() bool {
	return time.Since(a.dob) < poolfreshttl
}

// close closes the conn.
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

// keepalive sets tcp keepalive, if y is true.
// If y is false, it disables keepalive.
func (a agingconn) keepalive(y bool) bool {
	if y {
		cleardeadline(a.c) // reset any previous timeout
		return SetKeepAliveConfigSockOpt(a.c, kaidle, kainterval)
	} else {
		if c, ok := a.c.(KeepAliveConn); ok {
			return c.SetKeepAlive(false) == nil
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

	if pooluseread { // stackoverflow.com/q/12741386
		ctlErr = sc.Read(func(fd uintptr) bool {
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
		ctlErr = sc.Control(func(fd uintptr) {
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
	return JoinErr(ctlErr, checkErr) // may return nil
}

func (a agingconn) resetDeadline() {
	a.c.SetDeadline(time.Time{})
}

func logev(err error) log.LogFn {
	return logevif(err != nil)
}

func logevif(e bool) log.LogFn {
	if e {
		return log.E
	}
	return log.VV
}
