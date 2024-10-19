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

const useread = false                // always false; here for doc purposes
const poolcapacity = 8               // default capacity
const maxattempts = poolcapacity / 2 // max attempts to retrieve a conn from pool
const Nobody = uintptr(0)            // nobody

var errUnexpectedRead error = errors.New("pool: unexpected read")

type superpool[T comparable] struct {
	quit context.CancelFunc
	pool *ConnPool[T]
}

type MultConnPool[T comparable] struct {
	ctx context.Context
	mu  sync.RWMutex
	m   map[T]*superpool[T]
}

func NewMultConnPool[T comparable](ctx context.Context) *MultConnPool[T] {
	mc := &MultConnPool[T]{
		ctx: ctx,
		m:   make(map[T]*superpool[T]),
	}
	every10m := time.NewTicker(10 * time.Minute)
	go mc.scrub(ctx, every10m)
	return mc
}

func (m *MultConnPool[T]) scrub(ctx context.Context, tick *time.Ticker) {
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			m.mu.Lock()
			for id, super := range m.m {
				if !super.pool.closed.Load() {
					delete(m.m, id)
				} else if super.pool.empty() {
					super.quit()
					delete(m.m, id)
				} else {
					go super.pool.scrub()
				}
			}
			m.mu.Unlock()
		}
	}
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

	return super.pool.Put(conn)
}

// github.com/redis/go-redis/blob/d9eeed13/internal/pool/pool.go
type ConnPool[T comparable] struct {
	ctx    context.Context
	id     T
	p      chan net.Conn // never closed
	closed atomic.Bool
}

func NewConnPool[T comparable](ctx context.Context, id T) *ConnPool[T] {
	c := &ConnPool[T]{
		ctx: ctx,
		id:  id,
		p:   make(chan net.Conn, poolcapacity),
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
			case conn := <-c.p:
				if readable(conn) {
					// reset previous timeout
					_ = conn.SetDeadline(time.Time{})
					return conn
				}
				clos(conn)
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

	select {
	case c.p <- conn:
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
		case conn := <-c.p:
			clos(conn)
		default:
			return
		}
	}
}

func (c *ConnPool[T]) scrub() {
	if c.closed.Load() {
		return
	}
	for {
		select {
		case conn := <-c.p:
			if readable(conn) {
				select {
				case c.p <- conn:
				case <-c.ctx.Done(): // stop
					clos(conn)
					return
				default: // full
					clos(conn)
				}
			} else {
				clos(conn)
			}
		case <-c.ctx.Done():
		default:
			return
		}
	}
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

func clos(c net.Conn) {
	CloseConn(c)
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

	if useread {
		ctlErr = raw.Read(func(fd uintptr) bool {
			// pitfall: github.com/redis/go-redis/issues/3137
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
	return log.D
}
