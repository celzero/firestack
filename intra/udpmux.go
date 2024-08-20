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
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
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
	dur   time.Duration // set only once; on stop()
	start time.Time     // set only once; on ctor

	dxcount atomic.Uint32
	tx      atomic.Uint32
	rx      atomic.Uint32
}

func (s *stats) String() string {
	return fmt.Sprintf("mux: tx: %d, rx: %d, conns: %d, dur: %s", s.tx.Load(), s.rx.Load(), s.dxcount.Load(), s.dur)
}

// muxer muxes multiple connections grouped by remote addr over net.PacketConn
type muxer struct {
	// mxconn and stats are immutable (never reassigned)
	mxconn net.PacketConn
	stats  *stats

	until time.Time // deadline extension

	dxconns chan *demuxconn // never closed
	doneCh  chan struct{}   // stop vending, reading, and routing
	once    sync.Once
	cb      func() // muxer.stop() callback (new goroutine)

	rmu    sync.Mutex            // protects routes
	routes map[string]*demuxconn // remote addr -> demuxed conn

	dxconnWG *sync.WaitGroup // wait group for demuxed conns
}

// demuxconn writes to addr and reads from the muxer
type demuxconn struct {
	remux sender   // promiscuous sender
	raddr net.Addr // remote address connected to
	laddr net.Addr // local address connected from

	incomingCh chan *slice // incoming data, never closed
	overflowCh chan *slice // overflow data, never closed

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
var _ core.UDPConn = (*demuxconn)(nil)

// newMuxer creates a muxer/demuxer for a connectionless conn.
func newMuxer(conn net.PacketConn, f func()) *muxer {
	x := &muxer{
		mxconn:   conn,
		stats:    &stats{start: time.Now()},
		routes:   make(map[string]*demuxconn),
		rmu:      sync.Mutex{},
		dxconns:  make(chan *demuxconn),
		doneCh:   make(chan struct{}),
		dxconnWG: &sync.WaitGroup{},
		cb:       f,
	}
	go x.readers()
	go x.closers()
	return x
}

// closers waits for a demuxed conns to close, then cleans the state up.
func (x *muxer) closers() {
	for {
		select {
		case c := <-x.dxconns:
			x.dxconnWG.Add(1) // accept
			core.Gx("udpmux.vend.close", func() {
				<-c.closed
				x.unroute(c)
				x.dxconnWG.Done() // unaccept
			})
		case <-x.doneCh:
			return
		}
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
		go x.cb()         // dissociate
		x.stats.dur = time.Since(x.stats.start)
	})

	return err
}

func (x *muxer) drain() {
	dc := make([]*demuxconn, 0, len(x.dxconns))
	draintimeout := 2 * time.Second
	tick := time.NewTicker(draintimeout)

	defer func() {
		go x.unroute(dc...)
		for _, c := range dc {
			clos(c)
		}
	}()

	for { // close unaccepted connections
		select {
		case c := <-x.dxconns:
			tick.Reset(draintimeout)
			// unroute must be called from a different
			// goroutine as it blocks on rmu
			dc = append(dc, c)
		case <-tick.C:
			return
		}
	}
}

// readers has to tasks:
//  1. Dispatching incoming packets to the correct Conn.
//     It can therefore not be ended until all Conns are closed.
//  2. Creating a new Conn when receiving from a new remote.
func (x *muxer) readers() {
	// todo: recover must call "free()" if it wasn't.
	defer core.Recover(core.Exit11, "udpmux.read")
	defer func() {
		_ = x.stop() // stop muxer
	}()

	timeouterrors := 0
	for {
		bptr := core.AllocRegion(core.BMAX)
		b := *bptr
		b = b[:cap(b)]
		// todo: if panics are recovered above, free() may never be called
		free := func() {
			*bptr = b
			core.Recycle(bptr)
		}

		n, who, err := x.mxconn.ReadFrom(b)

		x.stats.tx.Add(uint32(n)) // upload
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
			log.W("udp: mux: new route err: %v", err)
			return
		} else { // may be existing route or a new route
			select {
			case dst.incomingCh <- &slice{v: b[:n], free: free}: // incomingCh is never closed
			default: // dst probably closed, but not yet unrouted
				log.W("udp: mux: read: drop(sz: %d); route to %s", n, dst.raddr)
			}
		}
	}
}

func (x *muxer) route(raddr net.Addr) (*demuxconn, error) {
	x.rmu.Lock()
	defer x.rmu.Unlock()
	conn, ok := x.routes[raddr.String()]
	if !ok {
		// new routes created here won't really exist in netstack if
		// settings.EndpointIndependentMapping or settings.EndpointIndependentFiltering
		// is set to false.
		conn = x.new(raddr)
		select {
		case <-x.doneCh:
			clos(conn)
			return nil, errMuxerDone
		case x.dxconns <- conn:
			x.stats.dxcount.Add(1)
			x.routes[raddr.String()] = conn
		}
	}
	return conn, nil
}

func (x *muxer) unroute(cc ...*demuxconn) {
	// don't really expect to handle panic w/ core.Recover
	x.rmu.Lock()
	defer x.rmu.Unlock()
	for _, c := range cc {
		delete(x.routes, c.raddr.String())
	}
}

func (x *muxer) sendto(p []byte, addr net.Addr) (int, error) {
	// on closed(x.doneCh), x.mxconn is closed and writes will fail
	n, err := x.mxconn.WriteTo(p, addr)
	x.stats.rx.Add(uint32(n)) // download
	return n, err
}

func (x *muxer) extend(t time.Time) {
	if t.IsZero() || x.until.IsZero() {
		x.until = t
		extendp(x.mxconn, time.Until(t))
		return
	}
	// extend if t is after existing deadline at x.until
	if x.until.Before(t) {
		x.until = t
		extendp(x.mxconn, time.Until(t))
	}
}

// new creates a demuxed conn to r.
func (x *muxer) new(r net.Addr) *demuxconn {
	return &demuxconn{
		remux:      x,                     // muxer
		laddr:      x.mxconn.LocalAddr(),  // listen addr
		raddr:      r,                     // sendto addr
		incomingCh: make(chan *slice, 32), // read from muxer
		overflowCh: make(chan *slice, 16), // overflow from read
		closed:     make(chan struct{}),   // always unbuffered
		wt:         time.NewTicker(udptimeout),
		rt:         time.NewTicker(udptimeout),
		wto:        udptimeout,
		rto:        udptimeout,
	}
}

// TODO: make sure a conn can only be vend once
func (x *muxer) vend(dst net.Addr) (net.Conn, error) {
	c, err := x.route(dst)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Read implements core.UDPConn.Read
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

// Write implements core.UDPConn.Write
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

// ReadFrom implements core.UDPConn.ReadFrom
func (c *demuxconn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	return n, c.raddr, err
}

// WriteTo implements core.UDPConn.WriteTo
func (c *demuxconn) WriteTo(p []byte, to net.Addr) (int, error) {
	if to.String() != c.raddr.String() {
		return 0, net.ErrWriteToConnected
	}
	return c.Write(p)
}

// Close implements core.UDPConn.Close
func (c *demuxconn) Close() error {
	c.once.Do(func() {
		close(c.closed) // sig close
		defer c.wt.Stop()
		defer c.rt.Stop()
		for {
			select {
			case sx := <-c.incomingCh:
				sx.free()
			case sx := <-c.overflowCh:
				sx.free()
			default:
				return
			}
		}
	})

	return nil
}

// LocalAddr implements core.UDPConn.LocalAddr
func (c *demuxconn) LocalAddr() net.Addr {
	return c.laddr
}

// RemoteAddr implements core.UDPConn.RemoteAddr
func (c *demuxconn) RemoteAddr() net.Addr {
	return c.raddr
}

// SetDeadline implements core.UDPConn.SetDeadline
func (c *demuxconn) SetDeadline(t time.Time) error {
	werr := c.SetReadDeadline(t)
	rerr := c.SetReadDeadline(t)
	return errors.Join(werr, rerr)
}

// SetReadDeadline implements core.UDPConn.SetReadDeadline
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

// SetWriteDeadline implements core.UDPConn.SetWriteDeadline
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
		case c.overflowCh <- ov: // overflowCh is never closed
		}
		log.D("udp: demux: read: overflow(sz: %d)", q)
	} else {
		in.free()
	}
	return n, nil
}

func timedout(err error) bool {
	x, ok := err.(net.Error)
	return ok && x.Timeout()
}

type muxTable struct {
	sync.Mutex
	t map[netip.AddrPort]*muxer // src -> dst endpoint independent nat
}

type assocFn func(net, dst string) (net.PacketConn, error)

func newMuxTable() *muxTable {
	return &muxTable{t: make(map[netip.AddrPort]*muxer)}
}

func (e *muxTable) associate(src netip.AddrPort, fn assocFn) (*muxer, error) {
	e.Lock()
	defer e.Unlock()
	if mxr, ok := e.t[src]; ok {
		return mxr, nil
	} else if pc, err := fn("udp", src.String()); err == nil {
		mxr = newMuxer(pc, func() {
			e.dissociate(src)
		})
		e.t[src] = mxr
		return mxr, nil
	} else {
		core.Close(pc)
		return nil, err
	}
}

func (e *muxTable) dissociate(src netip.AddrPort) {
	e.Lock()
	defer e.Unlock()
	delete(e.t, src)
}
