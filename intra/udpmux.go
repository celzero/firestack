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
	"github.com/celzero/firestack/intra/netstack"
)

// from: github.com/pion/transport/blob/03c807b/udp/conn.go

const (
	maxtimeouterrors = 3
)

var (
	errMuxerDone = errors.New("udp: muxer closed")
)

type sender interface {
	id() string
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
	return fmt.Sprintf("tx: %d, rx: %d, conns: %d, dur: %ds", s.tx.Load(), s.rx.Load(), s.dxcount.Load(), int64(s.dur.Seconds()))
}

// muxer muxes multiple connections grouped by remote addr over net.PacketConn
type muxer struct {
	// id, mxconn, stats are immutable (never reassigned)
	cid    string
	mxconn net.PacketConn
	stats  *stats

	until time.Time // deadline extension

	dxconns chan *demuxconn // never closed
	doneCh  chan struct{}   // stop vending, reading, and routing
	once    sync.Once
	cb      func()             // muxer.stop() callback (in a new goroutine)
	vnd     netstack.DemuxerFn // for new routes in netstack

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
func newMuxerLocked(id string, conn net.PacketConn, vnd netstack.DemuxerFn, f func()) *muxer {
	x := &muxer{
		cid:      id,
		mxconn:   conn,
		stats:    &stats{start: time.Now()},
		routes:   make(map[string]*demuxconn),
		rmu:      sync.Mutex{},
		dxconns:  make(chan *demuxconn),
		doneCh:   make(chan struct{}),
		dxconnWG: &sync.WaitGroup{},
		cb:       f,
		vnd:      vnd,
	}
	go x.readers()
	go x.awaiters()
	return x
}

// awaiters waits for a demuxed conns to close, then cleans the state up.
func (x *muxer) awaiters() {
	for {
		select {
		case c := <-x.dxconns:
			log.D("udp: mux: %s awaiter: watching %s => %s", x.cid, c.laddr, c.raddr)
			x.dxconnWG.Add(1) // accept
			core.Gx("udpmux.vend.close", func() {
				<-c.closed
				x.unroute(c)
				x.dxconnWG.Done() // unaccept
			})
		case <-x.doneCh:
			log.I("udp: mux: %s awaiter: done", x.cid)
			return
		}
	}
}

// stop closes conns in the backlog, stops accepting new conns,
// closes muxconn, and waits for demuxed conns to close.
func (x *muxer) stop() error {
	log.D("udp: mux: %s stop", x.cid)

	var err error
	x.once.Do(func() {
		close(x.doneCh)
		x.drain()
		err = x.mxconn.Close() // close the muxed conn

		x.dxconnWG.Wait() // all conns close / error out
		go x.cb()         // dissociate
		x.stats.dur = time.Since(x.stats.start)
		log.I("udp: mux: %s stopped; stats: %s", x.cid, x.stats)
	})

	return err
}

func (x *muxer) drain() {
	dc := make([]*demuxconn, 0, len(x.dxconns))
	draintimeout := 2 * time.Second
	tick := time.NewTicker(draintimeout)

	defer func() {
		log.I("udp: mux: %s draining... %d", x.cid, len(dc))
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
				log.I("udp: mux: %s read timeout(%d): %v", x.cid, timeouterrors, err)
				continue
			} // else: err out
		}
		if err != nil {
			log.I("udp: mux: %s read done n(%d): %v", x.cid, n, err)
			return
		}
		if who == nil {
			log.W("udp: mux: %s read done n(%d): nil remote addr; skip", x.cid, n)
			continue
		}

		if dst, err := x.route(who); err != nil {
			// route fails if muxer.dxconns is closed (which is never closed)
			log.W("udp: mux: %s new route err: %v", x.cid, err)
			return
		} else { // may be existing route or a new route
			select {
			case dst.incomingCh <- &slice{v: b[:n], free: free}: // incomingCh is never closed
			default: // dst probably closed, but not yet unrouted
				log.W("udp: mux: %s read: drop(sz: %d); route to %s", x.cid, n, dst.raddr)
			}
		}
	}
}

func (x *muxer) route(raddr net.Addr) (*demuxconn, error) {
	x.rmu.Lock()
	defer x.rmu.Unlock()

	addr := raddr.String() // raddr must never be nil
	conn, ok := x.routes[addr]
	if !ok || conn == nil {
		// new routes created here won't really exist in netstack if
		// settings.EndpointIndependentMapping or settings.EndpointIndependentFiltering
		// is set to false.
		conn = x.newLocked(raddr)
		select {
		case <-x.doneCh:
			clos(conn)
			return nil, errMuxerDone
		case x.dxconns <- conn:
			x.stats.dxcount.Add(1)
			x.routes[addr] = conn
			if dst, err := addr2netip(raddr); err == nil && dst.IsValid() {
				go x.vnd(dst)
			} else { // should never happen
				log.E("udp: mux: %s route: invalid addr %s; err: %v", x.cid, raddr, err)
			}
			log.I("udp: mux: %s route: new for %s; stats: %d",
				x.cid, raddr, x.stats)
		}
	}
	return conn, nil
}

func (x *muxer) unroute(cc ...*demuxconn) {
	// don't really expect to handle panic w/ core.Recover
	x.rmu.Lock()
	defer x.rmu.Unlock()

	for _, c := range cc {
		log.I("udp: mux: %s unrouting... %s => %s", x.cid, c.laddr, c.raddr)
		delete(x.routes, c.raddr.String())
	}
}

func (x *muxer) id() string { return x.cid }

func (x *muxer) sendto(p []byte, addr net.Addr) (int, error) {
	// on closed(x.doneCh), x.mxconn is closed and writes will fail
	n, err := x.mxconn.WriteTo(p, addr)
	x.stats.rx.Add(uint32(n)) // download
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

// new creates a demuxed conn to r.
func (x *muxer) newLocked(r net.Addr) *demuxconn {
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
	log.D("udp: mux: %s demux %s => %s close, in: %d, over: %d",
		c.remux.id(), c.laddr, c.raddr, len(c.incomingCh), len(c.overflowCh))
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
				log.I("udp: mux: %s demux from %s => %s closed", c.remux.id(), c.laddr, c.raddr)
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
	id := c.remux.id()
	// todo: handle the case where len(b) > len(p)
	n := copy(*out, in.v)
	q := len(in.v) - n
	if q > 0 {
		ov := &slice{v: in.v[n:], free: in.free}
		select {
		case <-c.closed:
			log.W("udp: mux: %s demux: read: drop(sz: %d)", id, q)
			in.free()
		case c.overflowCh <- ov: // overflowCh is never closed
			log.W("udp: mux: %s demux: read: overflow(sz: %d)", id, q)
		}
	} else {
		log.D("udp: mux: %s demux: read: done(sz: %d)", id, n)
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

func (e *muxTable) associate(id string, src netip.AddrPort, mk assocFn, v netstack.DemuxerFn) (*muxer, error) {
	e.Lock()
	defer e.Unlock()

	proto, anyaddr := anyaddrFor(src)
	if mxr, ok := e.t[src]; ok {
		return mxr, nil
	} else if pc, err := mk(proto, anyaddr); err == nil {
		log.I("udp: mux: %s new assoc for %s", id, src)
		mxr = newMuxerLocked(id, pc, v, func() {
			e.dissociate(id, src)
		})
		e.t[src] = mxr
		return mxr, nil
	} else {
		core.Close(pc)
		return nil, err
	}
}

func (e *muxTable) dissociate(id string, src netip.AddrPort) {
	log.I("udp: mux: %s dissoc for %s", id, src)

	e.Lock()
	defer e.Unlock()
	delete(e.t, src)
}

func addr2netip(addr net.Addr) (netip.AddrPort, error) {
	return netip.ParseAddrPort(addr.String())
}
