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
	"runtime"
	"strconv"
	"sync"
	"syscall"

	"github.com/celzero/firestack/intra/ipn/multihost"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
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
	mu           sync.Mutex // protects following fields
	id           string
	ctl          protect.Controller
	listener     rwlistener
	lastSendAddr netip.AddrPort // may be invalid

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
}

type StdNetEndpoint2 struct {
	// AddrPort is the endpoint destination.
	netip.AddrPort
	// src is the current source address.
	src []byte
}

type batchReader interface {
	ReadBatch([]ipv6.Message, int) (int, error)
}

type batchWriter interface {
	WriteBatch([]ipv6.Message, int) (int, error)
}

type setGSOFunc func(control *[]byte, gsoSize uint16)

type getGSOFunc func(control []byte) (int, error)

type ErrUDPGSODisabled struct {
	onLaddr  string
	RetryErr error
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
	// If compilation fails here these are no longer the same underlying type.
	_ ipv6.Message = ipv4.Message{}

	_ conn.Bind     = (*StdNetBind2)(nil)
	_ conn.Endpoint = &StdNetEndpoint2{}
)

func (e ErrUDPGSODisabled) Error() string {
	return fmt.Sprintf("disabled UDP GSO on %s, NIC(s) may not support checksum offload", e.onLaddr)
}

func (e ErrUDPGSODisabled) Unwrap() error {
	return e.RetryErr
}

func NewEndpoint2(id string, ctl protect.Controller, f rwlistener) conn.Bind {
	return &StdNetBind2{
		id:       id,
		ctl:      ctl,
		listener: f,

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
}

func (e *StdNetBind2) ParseEndpoint(s string) (conn.Endpoint, error) {
	d := new(multihost.MH)
	host, portstr, err := net.SplitHostPort(s)
	if err != nil {
		log.E("wg: bind2: %s not a valid endpoint in(%s); err: %v", e.id, s, err)
		return nil, err
	}
	d.With([]string{host}) // resolves host if needed
	ips := d.Addrs()
	if len(ips) <= 0 {
		log.E("wg: bind2: %s not a valid endpoint in(%s); out(%s, %s)", e.id, s, d.Names(), d.Addrs())
		return nil, errInvalidEndpoint
	}
	port, err := strconv.Atoi(portstr)
	if err != nil {
		log.E("wg: bind2: %s not a valid port in(%s); err: %v", e.id, s, err)
		return nil, err
	}

	ipport := netip.AddrPortFrom(ips[0], uint16(port))
	log.I("wg: bind2: %s new endpoint %v", e.id, ipport)
	return asEndpoint2(ipport), err
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

func (s *StdNetBind2) listenNet(network string, port int) (*net.UDPConn, int, error) {
	lc := protect.MakeNsListenConfigExt(s.id, s.ctl, controlFns)
	wcaddr := ":" + strconv.Itoa(port) // wildcard address
	conn, err := lc.ListenPacket(context.Background(), network, wcaddr)
	if err != nil {
		return nil, 0, err
	}
	if conn == nil {
		return nil, 0, errNoListen
	}

	caddr := conn.LocalAddr()
	if caddr == nil {
		return nil, 0, errNoLocalAddr
	}
	src, err := net.ResolveUDPAddr(caddr.Network(), caddr.String())
	if err != nil {
		return nil, 0, err
	}
	if src == nil {
		return nil, 0, errNoLocalAddr
	}
	// typecast is safe; see Open
	if udpconn, ok := conn.(*net.UDPConn); ok {
		return udpconn, src.Port, nil
	} else {
		conn.Close()
		return nil, 0, errNotUDP
	}
}

func (s *StdNetBind2) Open(uport uint16) ([]conn.ReceiveFunc, uint16, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

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
	log.D("wg: bind2: %s listen4(%d); no4? %t err? %v", s.id, port, no4, err)
	if err != nil && !no4 {
		return nil, 0, err
	}

	// v6: Listen on the same port as we're using for ipv4.
	v6conn, port, err = s.listenNet("udp6", port)
	busy := errors.Is(err, syscall.EADDRINUSE)
	no6 := errors.Is(err, syscall.EAFNOSUPPORT)
	log.D("wg: bind2: %s listen6(%d); busy? %t no6? %t err? %v", s.id, port, busy, no6, err)
	if uport == 0 && busy && tries < 100 {
		v4conn.Close()
		tries++
		goto again
	}
	if err != nil && !no6 {
		v4conn.Close()
		return nil, 0, err
	}

	var fns []conn.ReceiveFunc
	if v4conn != nil {
		s.ipv4TxOffload, s.ipv4RxOffload = supportsUDPOffload(v4conn)
		if runtime.GOOS == "linux" || runtime.GOOS == "android" {
			s.ipv4PC = ipv4.NewPacketConn(v4conn)
		}
		s.ipv4 = v4conn
		fns = append(fns, s.makeReceiveIPv4())
	}
	if v6conn != nil {
		s.ipv6TxOffload, s.ipv6RxOffload = supportsUDPOffload(v6conn)
		if runtime.GOOS == "linux" || runtime.GOOS == "android" {
			s.ipv6PC = ipv6.NewPacketConn(v6conn)
		}
		s.ipv6 = v6conn
		fns = append(fns, s.makeReceiveIPv6())
	}

	log.I("wg: bind2: %s opened port(%d) for v4? %t v6? %t", s.id, port, v4conn != nil, v6conn != nil)

	if len(fns) == 0 {
		log.W("wg: bind2: %s no listeners", s.id)
		return nil, 0, syscall.EAFNOSUPPORT
	}

	return fns, uint16(port), nil
}

func (s *StdNetBind2) receiveIP(
	br batchReader,
	conn *net.UDPConn,
	rxOffload bool,
	bufs [][]byte,
	sizes []int,
	eps []conn.Endpoint,
) (n int, err error) {
	msgs := s.getMessages()
	for i := range bufs {
		(*msgs)[i].Buffers[0] = bufs[i]
		(*msgs)[i].OOB = (*msgs)[i].OOB[:cap((*msgs)[i].OOB)]
	}
	defer s.putMessages(msgs)
	var numMsgs int
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		if rxOffload {
			readAt := len(*msgs) - (IdealBatchSize / udpSegmentMaxDatagrams)
			numMsgs, err = br.ReadBatch((*msgs)[readAt:], 0)
			if err != nil {
				return 0, err
			}
			numMsgs, err = splitCoalescedMessages(*msgs, readAt, getGSOSize)
			if err != nil {
				return 0, err
			}
		} else {
			numMsgs, err = br.ReadBatch(*msgs, 0)
			if err != nil {
				return 0, err
			}
		}
	} else {
		msg := &(*msgs)[0]
		msg.N, msg.NN, _, msg.Addr, err = conn.ReadMsgUDP(msg.Buffers[0], msg.OOB)
		if err != nil {
			return 0, err
		}
		numMsgs = 1
	}
	for i := 0; i < numMsgs; i++ {
		msg := &(*msgs)[i]
		sizes[i] = msg.N
		if sizes[i] == 0 {
			continue
		}
		addrPort := msg.Addr.(*net.UDPAddr).AddrPort()
		ep := &StdNetEndpoint2{AddrPort: addrPort} // TODO: remove allocation
		getSrcFromControl(msg.OOB[:msg.NN], ep)
		eps[i] = ep
	}
	return numMsgs, nil
}

func (s *StdNetBind2) makeReceiveIPv4() conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		return s.receiveIP(s.ipv4PC, s.ipv4, s.ipv4RxOffload, bufs, sizes, eps)
	}
}

func (s *StdNetBind2) makeReceiveIPv6() conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		return s.receiveIP(s.ipv6PC, s.ipv6, s.ipv6RxOffload, bufs, sizes, eps)
	}
}

func (s *StdNetBind2) putMessages(msgs *[]ipv6.Message) {
	for i := range *msgs {
		(*msgs)[i].OOB = (*msgs)[i].OOB[:0]
		(*msgs)[i] = ipv6.Message{Buffers: (*msgs)[i].Buffers, OOB: (*msgs)[i].OOB}
	}
	s.msgsPool.Put(msgs)
}

func (s *StdNetBind2) getMessages() *[]ipv6.Message {
	return s.msgsPool.Get().(*[]ipv6.Message)
}

// TODO: When all Binds handle IdealBatchSize, remove this dynamic function and
// rename the IdealBatchSize constant to BatchSize.
func (s *StdNetBind2) BatchSize() int {
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		return IdealBatchSize
	}
	return 1
}

func (s *StdNetBind2) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var err1, err2 error
	if s.ipv4 != nil {
		err1 = s.ipv4.Close()
		s.ipv4 = nil
		s.ipv4PC = nil
	}
	if s.ipv6 != nil {
		err2 = s.ipv6.Close()
		s.ipv6 = nil
		s.ipv6PC = nil
	}
	s.blackhole4 = false
	s.blackhole6 = false
	s.ipv4TxOffload = false
	s.ipv4RxOffload = false
	s.ipv6TxOffload = false
	s.ipv6RxOffload = false
	return errors.Join(err1, err2)
}

func (s *StdNetBind2) Send(bufs [][]byte, endpoint conn.Endpoint) error {
	s.mu.Lock()
	blackhole := s.blackhole4
	conn := s.ipv4
	offload := s.ipv4TxOffload
	br := batchWriter(s.ipv4PC)
	is6 := false
	if endpoint.DstIP().Is6() {
		blackhole = s.blackhole6
		conn = s.ipv6
		br = s.ipv6PC
		is6 = true
		offload = s.ipv6TxOffload
	}
	s.mu.Unlock()

	if blackhole {
		return nil
	}
	if conn == nil {
		return syscall.EAFNOSUPPORT
	}

	msgs := s.getMessages()
	defer s.putMessages(msgs)
	ua := s.udpAddrPool.Get().(*net.UDPAddr)
	defer s.udpAddrPool.Put(ua)
	if is6 {
		as16 := endpoint.DstIP().As16()
		copy(ua.IP, as16[:])
		ua.IP = ua.IP[:16]
	} else {
		as4 := endpoint.DstIP().As4()
		copy(ua.IP, as4[:])
		ua.IP = ua.IP[:4]
	}
	ua.Port = int(endpoint.(*StdNetEndpoint2).Port())
	var (
		retried bool
		err     error
	)
retry:
	if offload {
		n := coalesceMessages(ua, endpoint.(*StdNetEndpoint2), bufs, *msgs, setGSOSize)
		err = s.send(conn, br, (*msgs)[:n])
		if err != nil && offload && errShouldDisableUDPGSO(err) {
			offload = false
			s.mu.Lock()
			if is6 {
				s.ipv6TxOffload = false
			} else {
				s.ipv4TxOffload = false
			}
			s.mu.Unlock()
			retried = true
			goto retry
		}
	} else {
		for i := range bufs {
			(*msgs)[i].Addr = ua
			(*msgs)[i].Buffers[0] = bufs[i]
			setSrcControl(&(*msgs)[i].OOB, endpoint.(*StdNetEndpoint2))
		}
		err = s.send(conn, br, (*msgs)[:len(bufs)])
	}
	if retried {
		return ErrUDPGSODisabled{onLaddr: conn.LocalAddr().String(), RetryErr: err}
	}
	return err
}

func (s *StdNetBind2) send(conn *net.UDPConn, pc batchWriter, msgs []ipv6.Message) error {
	var (
		n     int
		err   error
		start int
	)
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		for {
			n, err = pc.WriteBatch(msgs[start:], 0)
			if err != nil || n == len(msgs[start:]) {
				break
			}
			start += n
		}
	} else {
		for _, msg := range msgs {
			_, _, err = conn.WriteMsgUDP(msg.Buffers[0], msg.OOB, msg.Addr.(*net.UDPAddr))
			if err != nil {
				break
			}
		}
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
			msgLen := len(buf)
			baseLenBefore := len(msgs[base].Buffers[0])
			freeBaseCap := cap(msgs[base].Buffers[0]) - baseLenBefore
			if msgLen+baseLenBefore <= maxPayloadLen &&
				msgLen <= gsoSize &&
				msgLen <= freeBaseCap &&
				dgramCnt < udpSegmentMaxDatagrams &&
				!endBatch {
				msgs[base].Buffers[0] = append(msgs[base].Buffers[0], buf...)
				if i == len(bufs)-1 {
					setGSO(&msgs[base].OOB, uint16(gsoSize))
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
		setSrcControl(&msgs[base].OOB, ep)
		msgs[base].Buffers[0] = buf
		msgs[base].Addr = addr
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
				return n, errors.New("splitting coalesced packet resulted in overflow")
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
