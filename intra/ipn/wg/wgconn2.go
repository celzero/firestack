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
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/ipn/multihost"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/conn"
)

// commit: github.com/WireGuard/wireguard-go/commit/3bb8fec7e

// StdNetBind2 implements Bind for all platforms.
// TODO: Remove usage of ipv{4,6}.PacketConn when net.UDPConn has comparable
// methods for sending and receiving multiple datagrams per-syscall. See the
// proposal in https://github.com/golang/go/issues/45886#issuecomment-1218301564.
type StdNetBind2 struct {
	ctx context.Context

	mu       sync.RWMutex // protects following fields
	id       string
	connect  connector
	observer rwobserver
	sendAddr atomic.Pointer[netip.AddrPort]   // may be invalid
	pm       *atomic.Pointer[multihost.MHMap] // peer ip:port or host => preferred-addrs
	amnezia  *atomic.Pointer[Amnezia]         // unused; amnezia/warp config, if any

	ipv4 *net.UDPConn
	ipv6 *net.UDPConn

	ipv4PC        *ipv4.PacketConn // will be nil on non-Linux
	ipv6PC        *ipv6.PacketConn // will be nil on non-Linux
	ipv4TxOffload bool
	ipv4RxOffload bool
	ipv6TxOffload bool
	ipv6RxOffload bool

	// these two fields are not guarded by mu
	udpAddrPool sync.Pool
	msgsPool    sync.Pool

	blackhole4 bool
	blackhole6 bool

	obsCh chan obsMsg // async observer delivery

	closed atomic.Bool // wgconn has been closed (can be reopened)
	ended  atomic.Bool // observer / connector are done (wgconn must remain closed)
}

type StdNetEndpoint2 struct {
	// AddrPort is the endpoint destination.
	netip.AddrPort
	// src is the current source address.
	src []byte
}

type batchReader interface {
	ReadBatch(ms []ipv6.Message, flags int) (int, error)
}

type batchWriter interface {
	WriteBatch(ms []ipv6.Message, flags int) (int, error)
}

type setGSOFunc func(control *[]byte, gsoSize uint16)

type getGSOFunc func(control []byte) (int, error)

type ErrUDPGSODisabled struct {
	onLaddr  string
	RetryErr error // err, if any, on retry; may be nil
}

const (
	// Exceeding these values results in EMSGSIZE. They account for layer3 and
	// layer4 headers. IPv6 does not need to account for itself as the payload
	// length field is self excluding.
	maxIPv4PayloadLen = 1<<16 - 1 - 20 - 8
	maxIPv6PayloadLen = 1<<16 - 1 - 8

	// this is a hard limit imposed by the kernel.
	udpSegmentMaxDatagrams = 64

	// github.com/WireGuard/wireguard-go/blob/12269c276/device/queueconstants_android.go#L13
	IdealBatchSize = conn.IdealBatchSize
)

var (
	zeroaddr     net.Addr = &net.UDPAddr{}
	zeroaddrport          = netip.AddrPort{}

	// If compilation fails here these are no longer the same underlying type.
	_ ipv6.Message = ipv4.Message{}

	_ conn.Bind     = (*StdNetBind2)(nil)
	_ conn.Endpoint = &StdNetEndpoint2{}
)

var errSplitOverflow = errors.New("wg: splitting coalesced packet resulted in overflow")

func (e ErrUDPGSODisabled) Error() string {
	return fmt.Sprintf("disabled udp gso on %s, NIC(s) may not support checksum offload", e.onLaddr)
}

func (e ErrUDPGSODisabled) Unwrap() error {
	return e.RetryErr
}

func NewEndpoint2(ctx context.Context, id string, d connector, pm *atomic.Pointer[multihost.MHMap], f rwobserver, a *atomic.Pointer[Amnezia]) *StdNetBind2 {
	s := &StdNetBind2{
		ctx:      ctx,
		id:       id,
		connect:  d,
		observer: f,
		pm:       pm,
		amnezia:  a,
		obsCh:    make(chan obsMsg, 8), // buffered for async delivery

		udpAddrPool: sync.Pool{
			New: func() any {
				return &net.UDPAddr{
					IP: make([]byte, 16),
				}
			},
		},

		msgsPool: sync.Pool{
			New: func() any {
				// ipv6.Message and ipv4.Message are interchangeable as they are
				// both aliases for x/net/internal/socket.Message.
				msgs := make([]ipv6.Message, IdealBatchSize)
				for i := range msgs {
					msgs[i].Buffers = make(net.Buffers, 1)
					msgs[i].OOB = make([]byte, 0, stickyControlSize+gsoControlSize)
				}
				return &msgs
			},
		},
	}
	core.Go("wg.obs2."+s.id, s.processObsMsg)
	context.AfterFunc(ctx, s.quit)
	return s
}

func (e *StdNetBind2) ParseEndpoint(s string) (conn.Endpoint, error) {
	/*host, portstr, err := net.SplitHostPort(s)
	if err != nil {
		log.E("wg: bind2: %s invalid endpoint in(%s); err: %v", e.id, s, err)
		return nil, err
	}
	port, err := strconv.Atoi(portstr)
	if err != nil {
		log.E("wg: bind2: %s invalid port in(%s); err: %v", e.id, s, err)
		return nil, err
	}*/
	// d.Add([]string{host}) // resolves host if needed
	d, err := e.pm.Load().Get(s)
	if err != nil || d == nil /*nilaway; can't happen*/ {
		log.E("wg: bind2: %s parse: invalid endpoint in(%s); err: %v", e.id, s, err)
		return nil, err
	}

	// do what tailscale does, and share a preferred endpoint regardless of "s"
	// github.com/tailscale/tailscale/blob/3a6d3f1a5b7/wgengine/magicsock/magicsock.go#L2568
	ipport := d.PreferredAddr()
	if !ipport.IsValid() || ipport.Addr().IsUnspecified() {
		log.E("wg: bind2: %s parse: invalid endpoint addr %v in(%s); out(%s, %s)", e.id, ipport, s, d.Names(), d.Addrs())
		// erroring out from here prevents PostConfig (handshake for this peer endpoint will always be zero)
		// github.com/WireGuard/wireguard-go/blob/12269c276173/device/uapi.go#L183
		return nil, errInvalidEndpoint
	}

	log.I("wg: bind2: %s new endpoint for %s, %v", e.id, s, ipport)
	return asEndpoint2(ipport), nil
}

func (e *StdNetEndpoint2) ClearSrc() {
	if len(e.src) > 0 {
		// truncate src, no need to reallocate.
		e.src = e.src[:0]
	}
}

func (e *StdNetEndpoint2) DstIP() netip.Addr {
	return e.AddrPort.Addr()
}

// See sosticky for implementations of SrcIP and SrcIfidx.

func (e *StdNetEndpoint2) DstToBytes() []byte {
	b, _ := e.AddrPort.MarshalBinary()
	return b
}

func (e *StdNetEndpoint2) DstToString() string {
	return e.AddrPort.String()
}

func (s *StdNetBind2) RemoteAddr() netip.AddrPort {
	if ptr := s.sendAddr.Load(); ptr != nil {
		return *ptr
	}
	return netip.AddrPort{}
}

func (s *StdNetBind2) listenNet(network string, port int) (*net.UDPConn, int, error) {
	if s.ended.Load() {
		return nil, 0, errEnded
	}

	var anyaddr netip.Addr
	if network == "udp4" {
		anyaddr = netip.IPv4Unspecified()
	} else {
		anyaddr = netip.IPv6Unspecified()
	}
	saddr := net.JoinHostPort(anyaddr.String(), fmt.Sprintf("%d", port))

	conn, err := s.connect(network, saddr)
	if err != nil {
		log.E("wg: bind2: %s %s: listen(%v); err: %v", s.id, network, saddr, err)
		return nil, 0, err
	}
	if conn == nil {
		log.E("wg: bind2: %s %s: listen(%v); conn nil", s.id, network, saddr)
		return nil, 0, errNoListen
	}

	laddr := conn.LocalAddr()
	if laddr == nil {
		log.E("wg: bind2: %s %s: listen(%v); local-addr nil", s.id, network, saddr)
		clos(conn)
		return nil, 0, errNoLocalAddr
	}
	uaddr, err := net.ResolveUDPAddr(
		laddr.Network(),
		laddr.String(),
	)
	if err != nil {
		log.E("wg: bind2: %s %s: listen(%v); resolve-addr err: %v", s.id, network, saddr, err)
		clos(conn)
		return nil, 0, err
	}
	if uaddr == nil {
		log.E("wg: bind2: %s %s: listen(%v); resolve-addr nil", s.id, network, saddr)
		clos(conn)
		return nil, 0, errNoLocalAddr
	}
	if settings.Debug {
		log.VV("wg: bind2: %s %s: listen(%v)", s.id, network, laddr)
	}
	// typecast is safe, because "network" is always udp[4|6]; see: Open
	if udpconn, ok := conn.(*net.UDPConn); ok {
		return udpconn, uaddr.Port, nil
	} else {
		clos(conn)
		return nil, 0, errNotUDP
	}
}

func (s *StdNetBind2) Open(uport uint16) ([]conn.ReceiveFunc, uint16, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ended.Load() {
		return nil, 0, errEnded
	}

	s.closed.Store(false)

	var err error
	var tries int

	if s.ipv4 != nil || s.ipv6 != nil {
		log.W("wg: bind2: %s already open", s.id)
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	// Attempt to open ipv4 and ipv6 listeners on the same port.
	// If uport is 0, we can retry on failure.
again:
	port := int(uport)
	var v4conn, v6conn *net.UDPConn

	// v4
	v4conn, port, err = s.listenNet("udp4", port)
	no4 := errors.Is(err, syscall.EAFNOSUPPORT)
	loge(err)("wg: bind2: %s #%d: listen4(%d); no4? %t err? %v", s.id, tries, port, no4, err)
	if err != nil && !no4 {
		return nil, 0, err
	}

	// v6: Listen on the same port as we're using for ipv4.
	v6conn, port, err = s.listenNet("udp6", port)
	busy := errors.Is(err, syscall.EADDRINUSE)
	no6 := errors.Is(err, syscall.EAFNOSUPPORT)
	loge(err)("wg: bind2: %s #%d listen6(%d); busy? %t no6? %t err? %v", s.id, tries, port, busy, no6, err)
	if uport == 0 && busy && tries < maxbindtries {
		clos(v4conn)
		tries++
		goto again
	}
	if err != nil && !no6 {
		clos(v4conn)
		return nil, 0, err
	}

	canBatch := supportsBatchRw()

	var fns []conn.ReceiveFunc
	if v4conn != nil {
		core.ChangeBufferSizesSockOpt(v4conn, wgreadsz, wgwritesz)
		s.ipv4TxOffload, s.ipv4RxOffload = supportsUDPOffload(v4conn)
		if canBatch {
			s.ipv4PC = ipv4.NewPacketConn(v4conn)
		}
		s.ipv4 = v4conn
		fns = append(fns, s.makeReceiveIPv4())
	}
	if v6conn != nil {
		core.ChangeBufferSizesSockOpt(v6conn, wgreadsz, wgwritesz)
		s.ipv6TxOffload, s.ipv6RxOffload = supportsUDPOffload(v6conn)
		if canBatch {
			s.ipv6PC = ipv6.NewPacketConn(v6conn)
		}
		s.ipv6 = v6conn
		fns = append(fns, s.makeReceiveIPv6())
	}

	log.I("wg: bind2: %s supports batch read/write? %t; has4? %t; has6 %t", s.id, canBatch, s.ipv4PC != nil, s.ipv6PC != nil)
	log.I("wg: bind2: %s opened port(%d) for v4? %t / v6? %t", s.id, port, v4conn != nil, v6conn != nil)

	if len(fns) == 0 {
		log.W("wg: bind2: %s no listeners", s.id)
		return nil, 0, syscall.EAFNOSUPPORT
	}

	var eerr error = nil
	if s.ended.Load() {
		eerr = errEnded
	}
	return fns, uint16(port), eerr
}

// processObsMsg launches a goroutine that drains obsCh and calls the
// observer synchronously for each message. The goroutine exits when s.ctx
// is cancelled or the channel is closed.
func (s *StdNetBind2) processObsMsg() {
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

func (s *StdNetBind2) drainObsCh() (n int) {
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
func (s *StdNetBind2) sendObsMsg(op PktDir, err error) {
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
		if settings.Debug { // warn if in debug mode
			log.W("wg: bind2: %s obs channel full (drained %d); dropping %s", s.id, drained, op)
		}
	}
}

func (s *StdNetBind2) receiveIP(
	br batchReader,
	conn *net.UDPConn,
	rxOffload bool,
	bufs [][]byte,
	sizes []int,
	eps []conn.Endpoint,
) (n int, err error) {
	defer core.Recover(core.Exit11, "wgconn2.recv."+s.id)

	anyProcessed := false
	anyTransportTyp := false
	defer func() {
		op := Rcv
		if !anyTransportTyp && anyProcessed {
			op = Crc
		}
		s.sendObsMsg(op, err)
	}()

	if conn == nil && br == nil {
		log.E("wg: bind2: %s receiveIP: no conns hasbatch? %t; hasconn? %t", s.id, br != nil, conn != nil)
		return 0, syscall.EINVAL
	}

	msgs := s.getMessages()
	defer s.putMessages(msgs)
	if msgs == nil || len(*msgs) <= 0 { // unlikely
		log.E("wg: bind2: %s no messages", s.id)
		return 0, syscall.ENOMEM
	}

	for i := range bufs {
		if i >= len(*msgs) { // unlikely as IdealBatchSize is a hard limit
			log.E("wg: bind2: %s receiveIP: limit: %d; too many messages (%d)", s.id, len(*msgs), len(bufs))
			// TODO: process bufs in next batch?
			break
		}
		msg := &(*msgs)[i]
		msg.Buffers[0] = bufs[i]
		msg.OOB = msg.OOB[:cap(msg.OOB)]
	}

	batch := false
	var numMsgs int
	if br != nil {
		if rxOffload {
			readAt := len(*msgs) - (IdealBatchSize / udpSegmentMaxDatagrams)
			numMsgs, err = br.ReadBatch((*msgs)[readAt:], 0)
			waddr := msgAddr(msgs)
			if err != nil {
				log.E("wg: bind2: %s GRO: readAt(%d) addr(%v) numMsgs(%d) err(%v)", s.id, readAt, waddr, numMsgs, err)
				return 0, err
			}

			numMsgs, err = splitCoalescedMessages(*msgs, readAt, getGSOSize)
			if err != nil {
				log.E("wg: bind2: %s GRO: splitCoalescedMessages(at: %d; from: %v) numMsgs(%d) err(%v)", s.id, readAt, waddr, numMsgs, err)
				return 0, err
			}
		} else {
			batch = true
			numMsgs, err = br.ReadBatch(*msgs, 0)
			if err != nil {
				log.E("wg: bind2: %s ReadBatch(sz: %d; from: %s) numMsgs(%d) err(%v)", s.id, len(*msgs), msgAddr(msgs), numMsgs, err)
				return 0, err
			}
		}
	} else {
		msg := &(*msgs)[0]
		msg.N, msg.NN, _, msg.Addr, err = conn.ReadMsgUDP(msg.Buffers[0], msg.OOB)
		if err != nil {
			log.E("wg: bind2: %s ReadMsgUDP(sz: %d; from: %v) err(%v)", s.id, msg.N, msg.Addr, err)
			return 0, err
		}
		numMsgs = 1
	}
	// TODO: loop not needed for non-Linux as getSrcFromControl is a no-op
	for i := 0; i < numMsgs; i++ {
		msg := &(*msgs)[i]
		sizes[i] = msg.N
		if sizes[i] == 0 {
			if settings.Debug {
				log.V("wg: bind2: %s zero-sized message from %v", s.id, msg.Addr)
			}
			continue
		}
		anyTransportTyp = anyTransportTyp || transportType(bufs[i])
		uaddr, ok := msg.Addr.(*net.UDPAddr)
		if !ok { // unlikely
			log.E("wg: bind2: %s invalid addr type %T %v", s.id, msg.Addr, msg.Addr)
			continue
		}
		ep := &StdNetEndpoint2{AddrPort: uaddr.AddrPort()} // TODO: remove allocation
		getSrcFromControl(msg.OOB[:msg.NN], ep)            // no-op on Android
		eps[i] = ep
		anyProcessed = true
	}
	if settings.Debug {
		log.VV("wg: bind2: %s received (batch? %t, offload? %t) %d messages", s.id, batch, rxOffload, numMsgs)
	}
	return numMsgs, nil
}

func (s *StdNetBind2) makeReceiveIPv4() conn.ReceiveFunc {
	// assign on stack to avoid closure related nil checks
	rawc := s.ipv4PC
	c := s.ipv4
	offload := s.ipv4RxOffload
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		return s.receiveIP(rawc, c, offload, bufs, sizes, eps)
	}
}

func (s *StdNetBind2) makeReceiveIPv6() conn.ReceiveFunc {
	// assign on stack to avoid closure related nil checks
	rawc := s.ipv6PC
	c := s.ipv6
	offload := s.ipv6RxOffload
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		return s.receiveIP(rawc, c, offload, bufs, sizes, eps)
	}
}

func (s *StdNetBind2) putMessages(msgs *[]ipv6.Message) {
	for i := range *msgs {
		// TODO: msg.Buffers[0] = msg.Buffers[0][:0]
		msg := &(*msgs)[i]
		msg.OOB = (*msgs)[i].OOB[:0]
		*msg = ipv6.Message{Buffers: msg.Buffers, OOB: msg.OOB}
	}
	s.msgsPool.Put(msgs)
}

func (s *StdNetBind2) getMessages() *[]ipv6.Message {
	m, ok := s.msgsPool.Get().(*[]ipv6.Message)
	if !ok { // unlikely
		log.W("wg: bind2: %s failed to get from msgpool", s.id)
		x := make([]ipv6.Message, IdealBatchSize)
		m = &x
	}
	return m
}

func (s *StdNetBind2) putUDPAddr(ua *net.UDPAddr) {
	s.udpAddrPool.Put(ua)
}

func (s *StdNetBind2) getUDPAddr() *net.UDPAddr {
	ua, ok := s.udpAddrPool.Get().(*net.UDPAddr)
	if !ok { // unlikely
		log.W("wg: bind2: %s failed to get from udpAddrPool", s.id)
		ua = &net.UDPAddr{IP: make([]byte, 16)}
	}
	return ua
}

// TODO: When all Binds handle IdealBatchSize, remove this dynamic function and
// rename the IdealBatchSize constant to BatchSize.
func (s *StdNetBind2) BatchSize() int {
	if supportsBatchRw() {
		return IdealBatchSize
	}
	return 1
}

func (s *StdNetBind2) Pause() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.blackhole4 = true
	s.blackhole6 = true

	log.I("wg: bind2: %s pausing... v4? %t, v6? %t", s.id, s.ipv4 != nil, s.ipv6 != nil)
	return true
}

func (s *StdNetBind2) Resume() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.blackhole4 = false
	s.blackhole6 = false

	log.I("wg: bind2: %s resuming... v4? %t, v6? %t", s.id, s.ipv4 != nil, s.ipv6 != nil)

	return true
}

func (s *StdNetBind2) Closed() bool {
	return s.closed.Load()
}

func (s *StdNetBind2) Close() error {
	// Do NOT do a pre-lock s.closed.Load() check here.
	// Open() writes s.closed under s.mu; a read outside the lock races with it.
	// The CAS below (also under s.mu) is the only correct guard.
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed.CompareAndSwap(false, true) {
		var err4, err6 error
		var addr4, addr6 net.Addr
		c4, c6 := s.ipv4, s.ipv6
		if c4 != nil {
			addr4 = c4.LocalAddr()
			err4 = c4.Close()
			s.ipv4 = nil
			s.ipv4PC = nil
		}
		if c6 != nil {
			addr6 = c6.LocalAddr()
			err6 = c6.Close()
			s.ipv6 = nil
			s.ipv6PC = nil
		}
		// resume if paused, so wireguard routines calling into send/recv error out
		s.blackhole4 = false
		s.blackhole6 = false
		s.ipv4TxOffload = false
		s.ipv4RxOffload = false
		s.ipv6TxOffload = false
		s.ipv6RxOffload = false

		s.sendObsMsg(Clo, nil)

		log.I("wg: bind2: %s close; addrs %v + %v; err4? %v err6? %v", s.id, addr4, addr6, err4, err6)
		return core.JoinErr(err4, err6)
	}
	log.W("wg: bind2: %s racing... ignored", s.id)
	return nil
}

func (s *StdNetBind2) quit() {
	_ = s.Close()
}

func (s *StdNetBind2) Send(bufs [][]byte, peer conn.Endpoint) (err error) {
	defer core.Recover(core.Exit11, "wgconn2.send."+s.id)

	anyTimedout := false
	anyProcessed := false
	anyTransportTyp := false
	defer func() {
		op := Snd
		if !anyTransportTyp && anyProcessed {
			op = Csn
		}
		if anyTimedout {
			err = os.ErrDeadlineExceeded
		}
		target := &ErrUDPGSODisabled{}
		if errors.As(err, target) {
			s.sendObsMsg(op, target.Unwrap())
		} else {
			s.sendObsMsg(op, err)
		}
	}()

	ep, ok := peer.(*StdNetEndpoint2)
	if !ok { // unlikely
		log.E("wg: bind2: %s wrong endpoint type %T", s.id, peer)
		return conn.ErrWrongEndpointType
	}

	s.mu.RLock()
	blackhole := s.blackhole4
	offload := s.ipv4TxOffload
	c := s.ipv4
	var br batchWriter = s.ipv4PC
	is6 := false
	if peer.DstIP().Is6() {
		blackhole = s.blackhole6
		offload = s.ipv6TxOffload
		c = s.ipv6
		br = s.ipv6PC
		is6 = true
	}
	s.mu.RUnlock()

	for _, data := range bufs {
		if len(data) > 0 {
			anyProcessed = true
			anyTransportTyp = anyTransportTyp || transportType(data)
		}
		if anyProcessed && anyTransportTyp {
			break
		}
	}

	if blackhole {
		return nil
	}
	if c == nil {
		return syscall.EAFNOSUPPORT
	}

	msgs := s.getMessages() // from msgspool
	defer s.putMessages(msgs)

	if msgs == nil || len(*msgs) <= 0 {
		log.E("wg: bind2: %s no messages", s.id)
		return syscall.ENOMEM
	}

	dst := addrport(peer, !is6)
	if !addrok(dst.Addr()) {
		log.E("wg: bind2: %s invalid destination %v", s.id, dst)
		return syscall.EINVAL
	}

	ua := s.getUDPAddr() // from udpAddrPool
	defer s.putUDPAddr(ua)
	*ua = *net.UDPAddrFromAddrPort(dst)
	s.sendAddr.Store(&dst)

	var retried bool
retry:
	if offload {
		n := coalesceMessages(ua, ep, bufs, *msgs, setGSOSize)
		// send coalesced msgs; ie, len(*msgs) <= len(bufs)
		if err = s.send(c, br, (*msgs)[:n], "gso"); err != nil {
			log.E("wg: bind2: %s gso: send(%d/%d) to %s; err(%v)", s.id, n, len(bufs), ua, err)
		}
		anyTimedout = anyTimedout || timedout(err)

		if shouldDisableUDPGSOOnError(err) { // err may be nil
			offload = false
			s.mu.Lock()
			if is6 {
				s.ipv6TxOffload = false
			} else {
				s.ipv4TxOffload = false
			}
			s.mu.Unlock()
			retried = true
			log.E("wg: bind2: %s gso: disabled on %s / v4? %t; err %v", s.id, ua, !is6, err)
			goto retry
		}
	} else {
		for i := range bufs {
			msg := &(*msgs)[i]
			// TODO: msg.N = len(bufs[i])
			msg.Addr = ua
			msg.Buffers[0] = bufs[i]
			setSrcControl(&msg.OOB, ep) // no-op on Android
		}
		// send all msgs
		if err = s.send(c, br, (*msgs)[:len(bufs)], "batch"); err != nil {
			log.E("wg: bind2: %s gso: send(%d) to %s (retry? %t); err(%v)", s.id, len(bufs), ua, retried, err)
		}
		anyTimedout = anyTimedout || timedout(err)
	}
	if retried {
		x := zeroaddr
		if a := c.LocalAddr(); a != nil {
			x = a
		}
		log.W("wg: bind2: %s disabled udp gso on %s; err %v", s.id, x, err)
		return ErrUDPGSODisabled{onLaddr: x.String(), RetryErr: err}
	}
	return err
}

func (s *StdNetBind2) send(conn *net.UDPConn, pc batchWriter, msgs []ipv6.Message, who string) (err error) {
	var n, start int

	batch := pc != nil && core.IsNotNil(pc)
	if batch {
		for {
			n, err = pc.WriteBatch(msgs[start:], 0)
			if err != nil || n == len(msgs[start:]) {
				break
			}
			start += n
		}
	} else {
		for _, msg := range msgs {
			addr, ok := msg.Addr.(*net.UDPAddr)
			if !ok { // unlikely
				log.E("wg: bind2: %s send: %s wrong addr type %s %T", s.id, who, msg.Addr, msg.Addr)
				continue
			}
			_, _, err = conn.WriteMsgUDP(msg.Buffers[0], msg.OOB, addr)
			if err != nil {
				log.E("wg: bind2: %s send: %s to %v; err %v", s.id, who, addr, err)
				break
			}
			n += 1
		}
	}
	if err != nil {
		log.E("wg: bind2: %s send: %s batch? %t; n(%d); err? %v", s.id, who, batch, n, err)
	} else {
		log.V("wg: bind2: %s send: %s batch? %t; n(%d); err? %v", s.id, who, batch, n, err)
	}
	return err
}

// asEndpoint2 returns an Endpoint containing ap.
// pooling disabled due to data race:
// github.com/WireGuard/wireguard-go/commit/334b605e726
func asEndpoint2(ap netip.AddrPort) *StdNetEndpoint2 {
	return &StdNetEndpoint2{
		AddrPort: ap,
	}
}

// from: github.com/WireGuard/wireguard-go/blob/1417a47c8/conn/mark_unix.go
func (s *StdNetBind2) SetMark(mark uint32) (err error) {
	// no-op for now
	return nil
}

func coalesceMessages(addr *net.UDPAddr, ep *StdNetEndpoint2, bufs [][]byte, msgs []ipv6.Message, setGSO setGSOFunc) int {
	var (
		base     = -1 // index of msg we are currently coalescing into
		gsoSize  int  // segmentation size of msgs[base]
		dgramCnt int  // number of dgrams coalesced into msgs[base]
		endBatch bool // tracking flag to start a new batch on next iteration of bufs
	)
	maxPayloadLen := maxIPv4PayloadLen
	if ep.DstIP().Is6() {
		maxPayloadLen = maxIPv6PayloadLen
	}
	for i, buf := range bufs {
		if i > 0 {
			curmsg := &msgs[base]
			msgLen := len(buf)
			baseLenBefore := len(curmsg.Buffers[0])
			freeBaseCap := cap(curmsg.Buffers[0]) - baseLenBefore
			if !endBatch &&
				msgLen+baseLenBefore <= maxPayloadLen &&
				msgLen <= gsoSize &&
				msgLen <= freeBaseCap &&
				dgramCnt < udpSegmentMaxDatagrams {
				curmsg.Buffers[0] = append(curmsg.Buffers[0], buf...)
				if i == len(bufs)-1 {
					setGSO(&curmsg.OOB, uint16(gsoSize))
				}
				dgramCnt++
				if msgLen < gsoSize {
					// A smaller than gsoSize packet on the tail is legal, but
					// it must end the batch.
					endBatch = true
				}
				continue
			}
		}
		if dgramCnt > 1 {
			setGSO(&msgs[base].OOB, uint16(gsoSize))
		}
		// Reset prior to incrementing base since we are preparing to start a
		// new potential batch.
		endBatch = false
		base++
		gsoSize = len(buf)
		nextmsg := &msgs[base]
		setSrcControl(&nextmsg.OOB, ep) // no-op on Android
		nextmsg.Buffers[0] = buf
		nextmsg.Addr = addr
		dgramCnt = 1
	}
	return base + 1
}

func splitCoalescedMessages(msgs []ipv6.Message, firstMsgAt int, getGSO getGSOFunc) (n int, err error) {
	for i := firstMsgAt; i < len(msgs); i++ {
		msg := &msgs[i]
		if msg.N == 0 {
			return n, err
		}
		var (
			gsoSize    int
			start      int
			end        = msg.N
			numToSplit = 1
		)
		gsoSize, err = getGSO(msg.OOB[:msg.NN])
		if err != nil {
			return n, err
		}
		if gsoSize > 0 {
			numToSplit = (msg.N + gsoSize - 1) / gsoSize
			end = gsoSize
		}
		for j := 0; j < numToSplit; j++ {
			if n > i {
				return n, errSplitOverflow
			}
			copied := copy(msgs[n].Buffers[0], msg.Buffers[0][start:end])
			msgs[n].N = copied
			msgs[n].Addr = msg.Addr
			start = end
			end += gsoSize
			if end > msg.N {
				end = msg.N
			}
			n++
		}
		if i != n-1 {
			// It is legal for bytes to move within msg.Buffers[0] as a result
			// of splitting, so we only zero the source msg len when it is not
			// the destination of the last split operation above.
			msg.N = 0
		}
	}
	return n, nil
}

func msgAddr(msgs *[]ipv6.Message) net.Addr {
	if msgs == nil || len(*msgs) <= 0 {
		return zeroaddr
	}
	return (*msgs)[0].Addr
}

func addrport(ep conn.Endpoint, as4 bool) netip.AddrPort {
	if a, ok := ep.(*StdNetEndpoint2); ok {
		if as4 {
			addr4 := a.AddrPort.Addr().Unmap()
			return netip.AddrPortFrom(addr4, a.Port())
		} else {
			addr6 := a.AddrPort.Addr()
			return netip.AddrPortFrom(addr6, a.Port())
		}
	}
	return zeroaddrport
}

func addrok(a netip.Addr) bool {
	return a.IsValid() && !a.IsUnspecified()
}
