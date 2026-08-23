// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     SPDX-License-Identifier: MIT
//
//     Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.

package wg

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/ipn/multihost"
	"github.com/celzero/firestack/intra/settings"

	"github.com/celzero/firestack/intra/log"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

// from: github.com/WireGuard/wireguard-go/blob/ebbd4a433/conn/bind_std.go

const maxbindtries = 30

// wireguard udp socket buffer sizes to 7mib by tailscale
// github.com/tailscale/tailscale/blob/632293de7d/wgengine/magicsock/magicsock.go#L89
const (
	wgreadsz  = 7 * 1024 * 1024 // 7MiB
	wgwritesz = 7 * 1024 * 1024 // 7MiB
)

// github.com/WireGuard/wireguard-go/blob/19ac233cc6/wireguard/device/send.go#L96
var (
	// quic?
	// github.com/hiddify/hiddify-sing-box/blob/17127b0535d/outbound/wireguard.go#L217
	mlist = []byte{0xDC, 0xDE, 0xD3, 0xD9, 0xD0, 0xEC, 0xEE, 0xE3}
	// github.com/WireGuard/wireguard-go/blob/12269c27617/device/send.go#L456
	wgheader = []byte{ // size 18
		/*00-03*/ 0x05, 0x00, 0x00, 0x00, // fieldType
		/*04-07*/ 0x01, 0x08, 0x00, 0x00, // fieldReceiver
		/*08-11*/ 0x00, 0x00, 0x00, 0x00, // fieldNonce
		/*11-15*/ 0x00, 0x00, 0x00, 0x00, // fieldNonce
		/*16-17*/ 0x44, 0xD0, // ???
	}

	anyaddr6 = netip.IPv6Unspecified()
	anyaddr4 = netip.IPv4Unspecified()
)

const (
	minFloodPkts     = 3
	maxFloodPkts     = minFloodPkts * 10
	maxFloodDuration = 3 * time.Second
	minFloodInterval = 1 * time.Minute // flood once every min

	minFloodPktLen = 28  // bytes; must be > len(wgheader)
	maxFloodPktLen = 138 // must be >> minFloodPktLen; < device.MessageInitiationSize?
)

var (
	errInvalidEndpoint = errors.New("wg: bind: no endpoint")
	errNoLocalAddr     = errors.New("wg: bind: no local address")
	errNoRawConn       = errors.New("wg: bind: no raw conn")
	errNotUDP          = errors.New("wg: bind: not a UDP conn")
	errNoListen        = errors.New("wg: bind: listen failed")
	errEnded           = errors.New("wg: bind: proxy ended")

	ErrPeerUnreachable = errors.New("wg: bind: peer unreachable")
)

type floodkind int

const (
	fkHandshake floodkind = iota
	fkKeepalive
)

func (k floodkind) String() string {
	switch k {
	case fkHandshake:
		return "handshake"
	case fkKeepalive:
		return "keepalive"
	default:
		return "unknown"
	}
}

type rwobserver func(op PktDir, err error) (ended bool)
type connector func(network, to string) (net.PacketConn, error)

type PktDir string

const (
	Rcv PktDir = "recv" // data received
	Snd PktDir = "send" // data sent
	Crc PktDir = "notr" // not transport data (recv)
	Csn PktDir = "nots" // not transport data (send)
	Con PktDir = "conn" // e.g. dial, announce, accept
	Opn PktDir = "open" // open conn to the wg endpoint
	Clo PktDir = "clos" // close conn to the wg endpoint
	Drp PktDir = "drop" // ignored packet
)

// Rcv or Crc
func (op PktDir) Read() bool {
	return op == Rcv || op == Crc
}

// Snd or Csn
func (op PktDir) Write() bool {
	return op == Snd || op == Csn
}

type StdNetBind struct {
	ctx     context.Context
	id      string
	connect connector
	pm      *atomic.Pointer[multihost.MHMap] // peer ip:port or host => preferred-addrs

	amnezia *atomic.Pointer[Amnezia] // may return nil *Amnezia
	floodBa *core.Barrier[int, netip.AddrPort]

	mu   sync.RWMutex   // protects following fields
	ipv4 net.PacketConn // (*net.UDPConn or *gonet.UDPConn)
	ipv6 net.PacketConn // (*net.UDPConn or *gonet.UDPConn)
	fd4  int
	fd6  int

	// keeps wireguard's recv routine running by not returning errors yet dropping packets
	blackhole4 bool
	blackhole6 bool

	epmu sync.RWMutex
	eps  map[netip.AddrPort]*StdNetEndpoint // peer-addr => std-net-endpoint

	observer rwobserver
	obsCh    chan obsMsg // async observer delivery

	sendAddr atomic.Pointer[netip.AddrPort] // may be invalid

	closed atomic.Bool // wgconn has been closed (can be reopened)
	ended  atomic.Bool // observer / connector are done (wgconn must remain closed)
	use6   atomic.Bool // default IP family for new endpoints; false = v4, true = v6
}

// obsMsg is a (op, err) pair sent to the observer goroutine.
type obsMsg struct {
	op  PktDir
	err error
}

// TODO: get d, ep, f, rb through an Opts bag?
func NewEndpoint(ctx context.Context, id string, d connector, pm *atomic.Pointer[multihost.MHMap], f rwobserver, a *atomic.Pointer[Amnezia]) *StdNetBind {
	s := &StdNetBind{
		ctx:      ctx,
		id:       id,
		connect:  d,
		pm:       pm,
		observer: f,
		obsCh:    make(chan obsMsg, 8), // buffered for async delivery
		amnezia:  a,
		floodBa:  core.NewKeyedBarrier[int, netip.AddrPort](ctx, "wg.flood."+id, minFloodInterval),
		eps:      make(map[netip.AddrPort]*StdNetEndpoint),
	}
	core.Go("wg.obs."+s.id, s.processObsMsg)
	context.AfterFunc(ctx, s.quit)
	return s
}

type StdNetEndpoint struct {
	v4   netip.AddrPort // ipv4 peer address
	v6   netip.AddrPort // ipv6 peer address
	use6 *atomic.Bool   // tracks active IP family; nil for recv-only endpoints
}

var invalidStdNetEndpoint = &StdNetEndpoint{}

var (
	_ conn.Bind     = (*StdNetBind)(nil)
	_ conn.Endpoint = (*StdNetEndpoint)(nil)
)

func (e *StdNetBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	/*
		host, portstr, err := net.SplitHostPort(s)
		if err != nil {
			log.E("wg: bind: %s invalid endpoint in(%s); err: %v", e.id, s, err)
			return nil, err
		}
		port, err := strconv.Atoi(portstr)
		if err != nil {
			log.E("wg: bind: %s invalid port in(%s); err: %v", e.id, s, err)
			return nil, err
		}
	*/
	// d.Add([]string{host}) // resolves host if needed
	d, err := e.pm.Load().Get(s)
	if err != nil || d == nil /*nilaway; can't happen*/ {
		log.E("wg: bind: parse: %s invalid endpoint in(%s); err: %v", e.id, s, err)
		return nil, err
	}

	ogep, _ := netip.ParseAddrPort(s)

	all := d.Addrs()
	// do what tailscale does, and share a preferred endpoint regardless of "s"?
	// github.com/tailscale/tailscale/blob/3a6d3f1a5b7/wgengine/magicsock/magicsock.go#L2568
	ipp4, ipp6 := d.PreferredAddr2()

	// in cases where dialers.Use4() and dialers.Use6 return true, but only v6 route
	// may in fact exist (v4 is over only DNS64 / NAT64), prefer v6 instead

	if !ipok(ipp4) && !ipok(ipp6) {
		log.E("wg: bind: parse: %s invalid endpoint; (chosen: %v / alt: %v) => in(%s) => out(%s, %s)", e.id, ipp4, ipp6, s, d.Names(), all)
		// erroring out from here prevents PostConfig (handshake for this peer endpoint will always be zero)
		// github.com/WireGuard/wireguard-go/blob/12269c276173/device/uapi.go#L183
		return nil, errInvalidEndpoint
	}

	ep := &StdNetEndpoint{v4: ipp4, v6: ipp6, use6: &e.use6}
	active := ep.get()
	e.sendAddr.Store(&active)

	log.I("wg: bind: %s new shared endpoint for %s %v [alt: %v / among: %s]", e.id, s, ipp4, ipp6, all)

	e.epmu.Lock()
	e.eps[ogep] = ep
	e.epmu.Unlock()
	return ep, nil
}

// get returns the currently active address (v4 or v6) based on use6.
// Falls back to whichever is valid if the preferred family is not set.
func (e *StdNetEndpoint) get() netip.AddrPort {
	if e.use6 != nil && e.use6.Load() && e.v6.IsValid() {
		return e.v6
	}
	if e.v4.IsValid() {
		return e.v4
	}
	return e.v6 // fallback; may be invalid
}

func (e *StdNetEndpoint) get2() *net.UDPAddr {
	return udpaddr(e.get())
}

func (*StdNetEndpoint) ClearSrc() {} // not supported

func (e *StdNetEndpoint) DstIP() netip.Addr {
	return e.get().Addr()
}

func (e *StdNetEndpoint) SrcIP() netip.Addr {
	return netip.Addr{} // not supported
}

func (e *StdNetEndpoint) DstToBytes() (b []byte) {
	b, _ = e.get().MarshalBinary()
	return
}

func (e *StdNetEndpoint) DstToString() string {
	return e.get().String()
}

func (e *StdNetEndpoint) SrcToString() string {
	return ""
}

func udpaddr(ipp netip.AddrPort) *net.UDPAddr {
	if ipp.IsValid() {
		return net.UDPAddrFromAddrPort(ipp)
	}
	return nil
}

func (s *StdNetBind) RemoteAddr() netip.AddrPort {
	if addr := s.sendAddr.Load(); addr != nil {
		return *addr
	}
	return netip.AddrPort{}
}

func (s *StdNetBind) listenNet(network string, port int) (net.PacketConn, int, error) {
	if s.ended.Load() {
		return nil, 0, errEnded
	}

	anyaddr := anyaddr6
	if network == "udp4" {
		anyaddr = anyaddr4
	}
	saddr := net.JoinHostPort(anyaddr.String(), fmt.Sprintf("%d", port))

	conn, err := s.connect(network, saddr)
	if err != nil || conn == nil {
		log.E("wg: bind: listen: %s %s: on(%v); err: %v", s.id, network, saddr, err)
		return nil, 0, core.OneErr(err, errNoListen)
	}

	laddr := conn.LocalAddr()
	if laddr == nil {
		log.E("wg: bind: listen: %s %s: on(%v); local-addr nil", s.id, network, saddr)
		clos(conn)
		return nil, 0, errNoLocalAddr
	}
	uaddr, err := net.ResolveUDPAddr(
		laddr.Network(),
		laddr.String(),
	)
	if err != nil || uaddr == nil {
		clos(conn)
		return nil, 0, core.OneErr(err, errNoLocalAddr)
	}

	log.I("wg: bind: listen: %s %s: on(%v)", s.id, network, laddr)

	// typecast is safe, because "network" is always udp[4|6]; see: Open
	return conn, uaddr.Port, nil
}

func (s *StdNetBind) Open(uport uint16) ([]conn.ReceiveFunc, uint16, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ended.Load() {
		return nil, 0, errEnded
	}

	s.closed.Store(false)

	var err error
	var tries int

	if s.ipv4 != nil || s.ipv6 != nil {
		log.W("wg: bind: open: %s already open at :%d", s.id, uport)
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	// Attempt to open ipv4 and ipv6 listeners on the same port.
	// If uport is 0, we can retry on failure.
again:
	port := int(uport)
	var ipv4, ipv6 net.PacketConn

	ipv4, port, err = s.listenNet("udp4", port)
	no4 := errors.Is(err, syscall.EAFNOSUPPORT)
	if err != nil || log.Debug {
		loge(err)("wg: bind: open: 1 %s #%d listen4(%d); no4? %t err? %v", s.id, tries, port, no4, err)
	}
	if err != nil && !no4 {
		return nil, 0, err
	}

	// Listen on the same port as we're using for ipv4.
	ipv6, port, err = s.listenNet("udp6", port)
	busy := errors.Is(err, syscall.EADDRINUSE)
	// TODO: does loopback mode affect this? Should dialers.Use6 be used as a hint here?
	no6 := errors.Is(err, syscall.EAFNOSUPPORT)
	if err != nil || log.Debug {
		loge(err)("wg: bind: open: 2 %s #%d listen6(%d); busy? %t no6? %t err? %v", s.id, tries, port, busy, no6, err)
	}
	if uport == 0 && busy && tries < maxbindtries {
		clos(ipv4)
		tries++
		goto again
	}
	if err != nil && !no6 { // err and supports v6
		clos(ipv4)
		return nil, 0, err
	}

	var fns []conn.ReceiveFunc
	if ipv4 != nil {
		s.ipv4 = ipv4
		s.fd4, _, _ = core.ChangeBufferSizesSockOpt(s.id, ipv4, wgreadsz, wgwritesz)
		fns = append(fns, s.makeReceiveFn(s.fd4, ipv4))
	}
	if ipv6 != nil {
		s.ipv6 = ipv6
		s.fd6, _, _ = core.ChangeBufferSizesSockOpt(s.id, ipv6, wgreadsz, wgwritesz)
		fns = append(fns, s.makeReceiveFn(s.fd6, ipv6))
	}

	s.probe()

	log.I("wg: bind: open: %s opened port(requested %d => using %d) for v4? %t (%d) v6? %t (%d) use6? %t",
		s.id, uport, port, ipv4 != nil, s.fd4, ipv6 != nil, s.fd6, s.use6.Load())
	if len(fns) == 0 {
		return nil, 0, syscall.EAFNOSUPPORT
	}

	var eerr error = nil
	if s.ended.Load() {
		eerr = errEnded
	}
	return fns, uint16(port), eerr
}

// probe tests peer reachability over v4 and v6 using the
// just-opened sockets, and sets the default IP family preference.
// Prefers v4; falls back to v6 if v4 is unreachable.
func (s *StdNetBind) probe() (use6 bool) {
	s.epmu.RLock()
	eps := maps.Clone(s.eps)
	sz := len(eps)
	s.epmu.RUnlock()

	i, j := 0, 0
	for _, ep := range eps {
		v4 := ep.v4
		v6 := ep.v6

		if s.ipv4 != nil && v4.IsValid() {
			i++
			_, err := s.ipv4.WriteTo([]byte{}, udpaddr(v4))
			if err == nil || !isUnreachable(err) {
				s.use6.Store(false)
				log.I("wg: bind: %s probe: %d v4 reachable %v; err? %v", s.id, i, v4, err)
				return false
			}
		}

		if s.ipv6 != nil && v6.IsValid() {
			j++
			_, err := s.ipv6.WriteTo([]byte{}, udpaddr(v6))
			if err == nil || !isUnreachable(err) {
				s.use6.Store(true)
				log.I("wg: bind: %s probe: %d v6 reachable %v; err? %v", s.id, j, v6, err)
				return true
			}
		}
	}

	// Both fail or neither available; default to v4
	prefer6 := settings.PtMode.Load() == settings.PtModeForce46
	s.use6.Store(prefer6)
	log.I("wg: bind: %s probe: default v6? %t; v4:%d / v6:%d / tot: %d", s.id, prefer6, i, j, sz)
	return prefer6
}

// getconn returns the UDP socket, fd, and blackhole state for the given address family.
func (s *StdNetBind) getconn(ipp netip.AddrPort) (net.PacketConn, int, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	blackhole := s.blackhole4
	uc := s.ipv4
	fd := s.fd4
	if ipp.Addr().Is6() {
		blackhole = s.blackhole6
		uc = s.ipv6
		fd = s.fd6
	}
	return uc, fd, blackhole
}

// Pause implements wgconn
func (s *StdNetBind) Pause() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.blackhole4 = true
	s.blackhole6 = true

	// by the time resume comes about, the internal wireguard send/recv routines may have been stopped
	// or the keepalives blackholed for long enough that a new connection needs to be established.
	log.I("wg: bind: pr: %s pausing... v4? %t v6? %t", s.id, s.ipv4 != nil, s.ipv6 != nil)

	return true
}

// Resume implements wgconn
func (s *StdNetBind) Resume() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.blackhole4 = false
	s.blackhole6 = false

	log.I("wg: bind: pr: %s resuming... v4? %t v6? %t", s.id, s.ipv4 != nil, s.ipv6 != nil)

	return true
}

// Closed implements wgconn
func (s *StdNetBind) Closed() bool {
	return s.closed.Load()
}

// processObsMsg launches a goroutine that drains observerCh and calls the
// observer synchronously for each message.  The goroutine exits when s.ctx
// is cancelled (which happens in Close via obsCancel) or the channel is closed.
func (s *StdNetBind) processObsMsg() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case msg, ok := <-s.obsCh:
			if !ok {
				return
			}
			if s.observer(msg.op, msg.err) {
				s.ended.Store(true)
			}
		}
	}
}

func (s *StdNetBind) drainObsCh() (n int) {
	maxdrain := 12
	for {
		if n >= maxdrain {
			return
		}
		select {
		case <-s.obsCh:
			n++
		default:
			return
		}
	}
}

// sendObsMsg delivers (op, err) to the observer goroutine via a channel.
// It never blocks: the caller returns immediately after the send.
func (s *StdNetBind) sendObsMsg(op PktDir, err error) {
	drained := 0
	retry := true
again:
	select {
	case <-s.ctx.Done():
	case s.obsCh <- obsMsg{op, err}:
	default:
		if retry {
			drained = s.drainObsCh() // sync drain old msgs
			retry = false
			goto again
		}
		if log.Debug { // warn if in debug mode ;)
			log.W("wg: bind: %s obs channel full (drained %d); dropping %s", s.id, drained, op)
		}
	}
}

func (s *StdNetBind) Close() error {
	s.epmu.Lock()
	clear(s.eps)
	s.epmu.Unlock()

	// Do NOT do a pre-lock s.closed.Load() check here.
	// Open() writes s.closed under s.mu; a read outside the lock races with it.
	// The CAS below (also under s.mu) is the only correct guard.
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed.CompareAndSwap(false, true) {
		var err1, err2 error
		var addr1, addr2 net.Addr
		v4, v6 := s.ipv4, s.ipv6
		fd4, fd6 := s.fd4, s.fd6
		if v4 != nil {
			addr1 = v4.LocalAddr()
			err1 = v4.Close()
			s.ipv4 = nil
		}
		if v6 != nil {
			addr2 = v6.LocalAddr()
			err2 = v6.Close()
			s.ipv6 = nil
		}
		s.fd4 = -1
		s.fd6 = -1
		// resume if paused, so wireguard routines calling into send/recv error out
		s.blackhole4 = false
		s.blackhole6 = false

		s.sendObsMsg(Clo, nil)

		log.I("wg: bind: close: %s addrs %v (%d) + %v (%d); err4? %v err6? %v", s.id, addr1, fd4, addr2, fd6, err1, err2)
		return core.JoinErr(err1, err2)
	}
	log.W("wg: bind: close: %s racing... ignored", s.id)
	return nil
}

func (s *StdNetBind) quit() {
	_ = s.Close()
}

func (s *StdNetBind) makeReceiveFn(fd int, uc net.PacketConn) conn.ReceiveFunc {
	who := strconv.Itoa(fd)
	// github.com/WireGuard/wireguard-go/blob/469159ecf/device/device.go#L531
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		defer core.Recover(core.Exit11, "wgconn.recv."+who+"."+s.id)

		anyProcessed := false // true when numMsgs > 0 (ex: no error)
		anyTransportTyp := false
		defer func() {
			op := Rcv
			if !anyTransportTyp && anyProcessed {
				op = Crc // processed packets not transport data
			}
			s.sendObsMsg(op, err)
		}()

		amnezia := s.amnezia.Load()
		usingamz := amnezia.Set()
		overwritten := false

		numMsgs := 0
		b := bufs[0] // usually sized device.MaxMessageSize

		n, addr, err := uc.ReadFrom(b)
		if err == nil {
			b, overwritten = amnezia.recv(b, n)
			numMsgs++
		}

		var epsz int
		for i := range numMsgs {
			anyProcessed = true
			if overwritten {
				copy(bufs[i], b)
				sizes[i] = len(b)
			} else { // bufs remained unchanged
				sizes[i] = n
			}
			anyTransportTyp = anyTransportTyp || transportType(bufs[i])
			epsz, eps[i] = s.asEndpoint(addr)
		}

		if err != nil || log.Debug { // log errors if in debug mode
			loge(err)("wg: bind: recv: %s (%s) recvfrom(%v / %d): %d / ov? %t<=%t / transport? %t / err? %v",
				s.id, who, addr, epsz, n, usingamz, overwritten, anyTransportTyp, err)
		}
		return numMsgs, err
	}
}

func (s *StdNetBind) Send(buf [][]byte, peer conn.Endpoint) (err error) {
	defer core.Recover(core.Exit11, "wgconn.send."+s.id)

	anyTimedout := false
	anyProcessed := false
	anyTransportTyp := false
	defer func() {
		op := Snd
		if !anyTransportTyp && anyProcessed {
			op = Csn // processed packet not transport data
		}
		if anyTimedout {
			// implements Timeout interface that the observer expects
			err = os.ErrDeadlineExceeded
		}
		s.sendObsMsg(op, err)
	}()

	// the peer endpoint
	ep, ok := peer.(*StdNetEndpoint)
	if !ok {
		log.E("wg: bind: send: %s wrong endpoint type: %T", s.id, peer)
		return conn.ErrWrongEndpointType
	}
	dstIpp := ep.get()
	uc, fd, blackhole := s.getconn(dstIpp)

	if blackhole {
		return nil
	}
	if uc == nil {
		dst6 := dstIpp.Addr().Is6()
		// No socket for dstIpp's family (ex: v6 listener failed to open, or
		// use6 went stale after a reopen). Fall back to the other family's
		// socket and address, if the endpoint has one, instead of failing
		// every send with EAFNOSUPPORT.
		var alt netip.AddrPort
		if dst6 {
			alt = ep.v4
		} else {
			alt = ep.v6
		}
		if ipok(alt) {
			log.W("wg: bind: send: %s (%d) no socket (v6? %t) for %v; falling back to %v",
				s.id, fd, dst6, dstIpp, alt)
			dstIpp = alt
			s.use6.Store(dst6) // persist the working family
			uc, fd, blackhole = s.getconn(dstIpp)
		}
		if uc == nil {
			return syscall.EAFNOSUPPORT
		}
	}

	var floodWg = settings.FloodWireGuard.Load()
	var flooded, overwritten, unreach bool
	var nn int
	var errs error

	amnezia := s.amnezia.Load()
	hasAmnezia := amnezia.Set()

	for _, data := range buf {
		datalen := len(data) // grab the length before amnezia overwrites it
		bufok := datalen > 0

		if false && log.Verbose {
			log.VV("wg: bind: send: %s (%d) addr(%v) floodwg? %t; hasbuf? %t",
				s.id, fd, dstIpp, floodWg, bufok)
		}

		if !bufok {
			continue
		}

		anyProcessed = true
		anyTransportTyp = anyTransportTyp || transportType(data)

		overwritten = amnezia.send(&data)

		if !flooded && (floodWg || hasAmnezia) {
			switch datalen {
			case device.MessageInitiationSize:
				s.flood(fd, uc, ep, fkHandshake) // was probably a handshake
				flooded = true
			case device.MessageKeepaliveSize:
				s.flood(fd, uc, ep, fkKeepalive) // was probably a keepalive
				flooded = true
			}
		}

		n, serr := uc.WriteTo(data, ep.get2())

		if isUnreachable(serr) {
			unreach = true
			break
		}

		anyTimedout = anyTimedout || timedout(serr)
		if serr != nil { // TODO: &&  discard timeouts?
			errs = core.JoinErr(errs, serr)
		}

		nn += n
	}

	s.sendAddr.Store(&dstIpp)

	if errs != nil || log.Debug {
		loge(errs)("wg: bind: send: %s (%d) addr(%v) parcels(%d) tx(%d) (flooded? %t (enabled? %t) / overw? %t / trans? %t); unreach? %t, err? %v",
			s.id, fd, dstIpp, len(buf), nn, flooded, floodWg, overwritten, anyTransportTyp, unreach, errs)
	}
	if unreach {
		errs = ErrPeerUnreachable
	}

	return errs
}

// flood c with random-sized, non-sense (unencrypted) packets.
// this is okay to do because wireguard silently drops packets that won't decrypt.
// github.com/WireGuard/wireguard-go/blob/19ac233cc6/wireguard/device/send.go#L96
// github.com/GFW-knocker/wireguard/blob/8bd9f582b4/device/send.go#L98
func (s *StdNetBind) flood(fd int, c net.PacketConn, dst *StdNetEndpoint, why floodkind) {
	s.floodBa.Go(dst.get(), func() (int, error) {
		hdrlen := len(wgheader)
		hdr := make([]byte, hdrlen)
		copy(hdr, wgheader)

		hdr[0] = mlist[mrand.UintN(uint(len(mlist)))]
		_, _ = rand.Read(hdr[6:14])

		tot := max(mrand.Uint64N(maxFloodPkts+1), minFloodPkts)
		// go.dev/play/p/NkLihAUTqUO
		maxWaitMs := maxFloodDuration.Milliseconds() / int64(tot)
		expectedsent := make([]int, tot)

		// gfw-knocker generates much smaller pkts (18 + (10 to 30))
		// github.com/GFW-knocker/wireguard/blob/8bd9f582b4/device/send.go#L141
		padlen := uint64(maxFloodPktLen - hdrlen)
		pkt := make([]byte, maxFloodPktLen)
		var n int
		for i := range tot {
			sz := max(mrand.Uint64N(padlen+1), minFloodPktLen)
			_, _ = rand.Read(pkt[hdrlen:sz])
			copy(pkt[0:], hdr)

			sent, err := c.WriteTo(pkt, dst.get2())

			expectedsent[i] = hdrlen + int(sz)
			n += sent

			if log.Debug && err != nil { // log error iff in debug mode
				log.E("wg: bind: flood: %s (%d) %s %s: expected sent?(%v) / tot(%d); %v",
					s.id, fd, why, dst, expectedsent[:i], n, err)
				return n, err
			}

			wait := time.Duration(mrand.Int64N(maxWaitMs)) * time.Millisecond
			time.Sleep(wait)
		}

		if log.Debug {
			log.D("wg: bind: flood %s (%d) %s %s: expected sent?(%v) / tot(%d)",
				s.id, fd, why, dst, expectedsent, n)
		}
		return n, nil
	})
}

func (s *StdNetBind) BatchSize() int {
	return 1
}

// from: github.com/WireGuard/wireguard-go/blob/1417a47c8/conn/mark_unix.go
func (s *StdNetBind) SetMark(mark uint32) (err error) {
	// s.ipv4 and s.ipv6 are written by Open/Close under s.mu; read them here
	// under the same lock to avoid a data race.
	s.mu.RLock()
	uc4, _ := s.ipv4.(core.ControlConn) // may be nil
	uc6, _ := s.ipv6.(core.ControlConn) // may be nil
	s.mu.RUnlock()
	var operr error
	var raw4, raw6 syscall.RawConn
	fwmarkIoctl := 36 /* unix.SO_MARK */
	if uc4 != nil {
		if raw4, err = uc4.SyscallConn(); err == nil {
			if raw4 == nil {
				log.W("wg: bind: mark: %s setmark4: raw conn nil", s.id)
				return errNoRawConn
			}
			if err = raw4.Control(func(fd uintptr) {
				operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, int(mark))
			}); err == nil {
				err = operr
			}
		} // else: return err
	}
	if err == nil && uc6 != nil {
		if raw6, err = uc6.SyscallConn(); err == nil {
			if raw6 == nil {
				log.W("wg: bind: mark: %s setmark6: raw conn nil", s.id)
				return errNoRawConn
			}
			if err = raw6.Control(func(fd uintptr) {
				operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, int(mark))
			}); err == nil {
				err = operr
			}
		} // else: return err
	}
	log.I("wg: bind: mark: %s err? %v", s.id, err)
	return err
}

// asEndpoint returns a cached Endpoint for the given source address.
// Uses netip.AddrPort as map key to avoid string allocations in the hot recv path.
func (s *StdNetBind) asEndpoint(x net.Addr) (int, conn.Endpoint) {
	if x == nil {
		return -1, invalidStdNetEndpoint
	}

	var key netip.AddrPort
	switch a := x.(type) {
	case *net.UDPAddr:
		key = a.AddrPort()
	case *net.TCPAddr:
		key = a.AddrPort()
	default:
		ipp, err := netip.ParseAddrPort(x.String())
		if err != nil {
			return -1, invalidStdNetEndpoint
		}
		key = ipp
	}

	s.epmu.RLock()
	ep, ok := s.eps[key]
	sz := len(s.eps)
	s.epmu.RUnlock()

	if ok {
		return sz, ep
	}

	s.epmu.Lock()
	defer s.epmu.Unlock()
	ep, ok = s.eps[key]
	sz = len(s.eps)

	if ok {
		return sz, ep
	} // else: error out?

	if key.Addr().Is4() {
		ep = &StdNetEndpoint{v4: key}
	} else {
		ep = &StdNetEndpoint{v6: key}
	}

	s.eps[key] = ep
	return sz + 1, ep
}

func timedout(err error) bool {
	if err == nil {
		return false
	}
	x, ok := err.(interface {
		Timeout() bool
	})
	return ok && x.Timeout()
}

func loge(err error) log.LogFn {
	l := log.N // no-op
	if err != nil {
		l = log.W
	} else if log.Verbose {
		l = log.V
	}
	return l
}

func clos(c io.Closer) {
	core.CloseOp(c, core.CopRW)
}

func isUnreachable(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH)
}

func transportType(unobs []byte) (y bool) {
	return messageType(unobs, device.MessageTransportType)
}

// messageType reports whether unobs is of type t message.
// "unobs" must be free of Amnezia-like obfuscations.
func messageType(unobs []byte, t uint32) (y bool) {
	var typ uint32
	n := len(unobs)

	/*
		defer func() {
			if settings.Debug && !y {
				log.VV("wg: bind: messageType: len(%d) msgt(%d) == t(%d)? %t", n, typ, t, y)
			}
		}()
	*/

	if n < device.MinMessageSize {
		return
	}

	typ = binary.LittleEndian.Uint32(unobs)
	y = typ == t
	return
}

func ipok(ipp netip.AddrPort) bool {
	return ipp.IsValid() && !ipp.Addr().IsUnspecified() && !ipp.Addr().IsMulticast()
}

// iffam returns the address family name for logging.
func iffam(is6 bool) string {
	if is6 {
		return "v6"
	}
	return "v4"
}
