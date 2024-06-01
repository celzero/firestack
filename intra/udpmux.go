// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package intra

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
)

// from: github.com/pion/transport/blob/03c807b/udp/conn.go

const (
	maxtimeouterrors = 3
)

var (
	errMuxerDone = errors.New("udp: muxer closed")
)

type sender interface {
	sendto([]byte, net.Addr) (int, error)
	extend(time.Time)
}

type stats struct {
	dxcount int
	dur     time.Duration
	start   time.Time
	tx      int
	rx      int
}

func (s *stats) String() string {
	return fmt.Sprintf("mux: tx: %d, rx: %d, conns: %d, dur: %s", s.tx, s.rx, s.dxcount, s.dur)
}

// muxer muxes multiple connections grouped by remote addr over net.PacketConn
type muxer struct {
	mxconn core.UDPConn
	stats  *stats

	until time.Time // deadline extension

	dxconns chan *demuxconn
	doneCh  chan struct{} // stop vending, reading, and routing
	once    sync.Once

	rmu    sync.Mutex            // protects routes
	routes map[string]*demuxconn // remote addr -> demuxed conn

	dxconnWG *sync.WaitGroup // wait group for demuxed conns
}

// demuxconn writes to addr and reads from the muxer
type demuxconn struct {
	remux sender   // promiscuous sender
	raddr net.Addr // remote address connected to
	laddr net.Addr // local address connected from

	incomingCh chan *slice // incoming data
	overflowCh chan *slice // overflow data

	closed chan struct{} // close signal
	once   sync.Once     // close once

	wt  *time.Ticker  // write deadline
	rt  *time.Ticker  // read deadline
	wto time.Duration // write timeout
	rto time.Duration // read timeout
}

// slice is a byte slice v and its recycler free.
type slice struct {
	v    []byte
	free func()
}

var _ sender = (*muxer)(nil)
var _ net.Conn = (*demuxconn)(nil)

// mux creates a muxer/demuxer for a connectionless conn.
func newMuxer(conn core.UDPConn) *muxer {
	x := &muxer{
		mxconn:   conn,
		stats:    &stats{start: time.Now()},
		routes:   make(map[string]*demuxconn),
		rmu:      sync.Mutex{},
		dxconns:  make(chan *demuxconn),
		doneCh:   make(chan struct{}),
		dxconnWG: &sync.WaitGroup{},
	}
	go x.read()
	return x
}

// vend waits for and returns a demuxed conn to process.
func (x *muxer) vend() (net.Conn, error) {
	select {
	case c := <-x.dxconns:
		x.dxconnWG.Add(1) // accept
		go func() {
			<-c.closed
			x.unroute(c)
			x.dxconnWG.Done() // unaccept
		}()
		return c, nil

	case <-x.doneCh:
		return nil, errMuxerDone
	}
}

// stop closes conns in the backlog, stops accepting new conns,
// closes muxconn, and waits for demuxed conns to close.
func (x *muxer) stop() error {
	var err error
	x.once.Do(func() {
		close(x.doneCh)
		x.drain()
		err = x.mxconn.Close() // close the muxed conn

		x.dxconnWG.Wait() // all conns close / error out
		x.stats.dur = time.Since(x.stats.start)
	})

	return err
}

func (x *muxer) drain() {
	x.rmu.Lock()
	defer x.rmu.Unlock()

	for { // close unaccepted connections
		select {
		case c := <-x.dxconns:
			// unroute must be called from a different
			// goroutine as it blocks on rmu
			go x.unroute(c)
			clos(c)
		default:
			return
		}
	}
}

// read has to tasks:
//  1. Dispatching incoming packets to the correct Conn.
//     It can therefore not be ended until all Conns are closed.
//  2. Creating a new Conn when receiving from a new remote.
func (x *muxer) read() {
	defer func() {
		_ = x.stop() // stop muxer
	}()

	timeouterrors := 0
	for {
		bptr := core.AllocRegion(core.BMAX)
		b := *bptr
		b = b[:cap(b)]
		free := func() {
			*bptr = b
			core.Recycle(bptr)
		}

		n, who, err := x.mxconn.ReadFrom(b)

		x.stats.tx += n // upload
		if timedout(err) {
			timeouterrors++
			if timeouterrors < maxtimeouterrors {
				log.I("udp: mux: read timeout(%d): %v", timeouterrors, err)
				continue
			} // else: err out
		}
		if err != nil {
			log.I("udp: mux: read done: %v", err)
			return
		}

		if dst, err := x.route(who); err != nil {
			// route fails if muxer.dxconns is closed (which is never closed)
			log.W("udp: mux: new route failed: %v", err)
			return
		} else { // may be existing route or a new route
			select {
			case dst.incomingCh <- &slice{v: b[:n], free: free}:
			default: // dst probably closed, but not yet unrouted
				log.W("udp: mux: read: drop(sz: %d); route to %s closed but yet found?", n, dst.raddr)
			}
		}
	}
}

func (x *muxer) route(raddr net.Addr) (*demuxconn, error) {
	x.rmu.Lock()
	defer x.rmu.Unlock()
	conn, ok := x.routes[raddr.String()]
	if !ok {
		conn = x.demux(raddr)
		select {
		case <-x.doneCh:
			clos(conn)
			return nil, errMuxerDone
		case x.dxconns <- conn:
			x.stats.dxcount++
			x.routes[raddr.String()] = conn
		}
	}
	return conn, nil
}

func (x *muxer) unroute(c *demuxconn) {
	x.rmu.Lock()
	delete(x.routes, c.raddr.String())
	x.rmu.Unlock()
}

func (x *muxer) sendto(p []byte, addr net.Addr) (int, error) {
	// on closed(x.doneCh), x.mxconn is closed and writes will fail
	n, err := x.mxconn.WriteTo(p, addr)
	x.stats.rx += n // download
	return n, err
}

func (x *muxer) extend(t time.Time) {
	if t.IsZero() || x.until.IsZero() {
		x.until = t
		extend(x.mxconn, time.Until(t))
		return
	}
	// extend if t is after existing deadline at x.until
	if x.until.Before(t) {
		x.until = t
		extend(x.mxconn, time.Until(t))
	}
}

// demux creates a demuxed conn to r.
func (x *muxer) demux(r net.Addr) *demuxconn {
	return &demuxconn{
		remux:      x,
		laddr:      x.mxconn.LocalAddr(),
		raddr:      r,
		incomingCh: make(chan *slice),
		overflowCh: make(chan *slice),
		closed:     make(chan struct{}), // must always be unbuffered
		wt:         time.NewTicker(udptimeout),
		rt:         time.NewTicker(udptimeout),
		wto:        udptimeout,
		rto:        udptimeout,
	}
}

// Read implements net.Conn.Read
func (c *demuxconn) Read(p []byte) (int, error) {
	defer c.rt.Reset(c.rto)
	select {
	case <-c.rt.C:
		return 0, os.ErrDeadlineExceeded
	case <-c.closed:
		return 0, net.ErrClosed
	case sx := <-c.overflowCh:
		return c.io(&p, sx)
	case sx := <-c.incomingCh:
		return c.io(&p, sx)
	}
}

func (c *demuxconn) io(out *[]byte, in *slice) (int, error) {
	// todo: handle the case where len(b) > len(p)
	n := copy(*out, in.v)
	q := len(in.v) - n
	if q > 0 {
		ov := &slice{v: in.v[n:], free: in.free}
		select {
		case <-c.closed:
			log.W("udp: demux: read: drop(sz: %d)", q)
			in.free()
		case c.overflowCh <- ov:
		}
		log.D("udp: demux: read: overflow(sz: %d)", q)
	} else {
		in.free()
	}
	return n, nil
}

// Write implements net.Conn.Write
func (c *demuxconn) Write(p []byte) (n int, err error) {
	defer c.wt.Reset(c.wto)
	select {
	case <-c.wt.C:
		return 0, os.ErrDeadlineExceeded
	case <-c.closed:
		return 0, net.ErrClosed
	default:
		return c.remux.sendto(p, c.raddr)
	}
}

// Close implements net.Conn.Close
func (c *demuxconn) Close() error {
	c.once.Do(func() {
		close(c.closed) // sig close
		for {
			select {
			case sx := <-c.incomingCh:
				sx.free()
			case sx := <-c.overflowCh:
				sx.free()
			default:
				c.wt.Stop()
				c.rt.Stop()
				return
			}
		}
	})

	return nil
}

// LocalAddr implements net.Conn.LocalAddr
func (c *demuxconn) LocalAddr() net.Addr {
	return c.laddr
}

// RemoteAddr implements net.Conn.RemoteAddr
func (c *demuxconn) RemoteAddr() net.Addr {
	return c.raddr
}

// SetDeadline implements net.Conn.SetDeadline
func (c *demuxconn) SetDeadline(t time.Time) error {
	werr := c.SetReadDeadline(t)
	rerr := c.SetReadDeadline(t)
	return errors.Join(werr, rerr)
}

// SetReadDeadline implements net.Conn.SetReadDeadline
func (c *demuxconn) SetReadDeadline(t time.Time) error {
	if d := time.Until(t); d > 0 {
		c.rto = d
		c.rt.Reset(d)
		c.remux.extend(t)
	} else {
		c.remux.extend(time.Time{}) // no deadline
		c.rt.Stop()
	}
	return nil
}

// SetWriteDeadline implements net.Conn.SetWriteDeadline
func (c *demuxconn) SetWriteDeadline(t time.Time) error {
	if d := time.Until(t); d > 0 {
		c.wto = d
		c.rt.Reset(d)
		c.remux.extend(t)
	} else {
		c.remux.extend(time.Time{}) // no deadline
		c.rt.Stop()
	}
	// Write deadline of underlying connection should not be changed
	// since the connection can be shared.
	return nil
}

func timedout(err error) bool {
	x, ok := err.(net.Error)
	return ok && x.Timeout()
}
