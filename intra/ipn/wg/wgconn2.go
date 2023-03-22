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
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
)

// StdNetBind2 implements Bind for all platforms. While Windows has its own Bind
// (see bind_windows.go), it may fall back to StdNetBind2.
// TODO: Remove usage of ipv{4,6}.PacketConn when net.UDPConn has comparable
// methods for sending and receiving multiple datagrams per-syscall. See the
// proposal in https://github.com/golang/go/issues/45886#issuecomment-1218301564.
type StdNetBind2 struct {
	mu   sync.Mutex // protects following fields
	lc   *net.ListenConfig
	ipv4 *net.UDPConn
	ipv6 *net.UDPConn

	udpAddrPool  sync.Pool // following fields are not guarded by mu
	ipv4MsgsPool sync.Pool
	ipv6MsgsPool sync.Pool
}

func NewBind2(ctl protect.Controller) conn.Bind {
	return &StdNetBind2{
		lc: protect.MakeNsListenConfig(ctl),

		udpAddrPool: sync.Pool{
			New: func() any {
				return &net.UDPAddr{
					IP: make([]byte, 16),
				}
			},
		},

		ipv4MsgsPool: sync.Pool{
			New: func() any {
				msgs := make([]ipv4.Message, conn.IdealBatchSize)
				for i := range msgs {
					msgs[i].Buffers = make(net.Buffers, 1)
					msgs[i].OOB = make([]byte, 0) // unused
				}
				return &msgs
			},
		},

		ipv6MsgsPool: sync.Pool{
			New: func() any {
				msgs := make([]ipv6.Message, conn.IdealBatchSize)
				for i := range msgs {
					msgs[i].Buffers = make(net.Buffers, 1)
					msgs[i].OOB = make([]byte, 0) // unused
				}
				return &msgs
			},
		},
	}
}

type StdNetEndpoint2 struct {
	// AddrPort is the endpoint destination.
	netip.AddrPort
	// src is the current sticky source address and interface index, if supported.
	src struct {
		netip.Addr
		ifidx int32
	}
}

var (
	_ conn.Bind     = (*StdNetBind2)(nil)
	_ conn.Endpoint = &StdNetEndpoint2{}
)

func (*StdNetBind2) ParseEndpoint(s string) (conn.Endpoint, error) {
	e, err := netip.ParseAddrPort(s)
	return asEndpoint2(e), err
}

func (e *StdNetEndpoint2) ClearSrc() {
	e.src.ifidx = 0
	e.src.Addr = netip.Addr{}
}

func (e *StdNetEndpoint2) DstIP() netip.Addr {
	return e.AddrPort.Addr()
}

func (e *StdNetEndpoint2) SrcIP() netip.Addr {
	return e.src.Addr
}

func (e *StdNetEndpoint2) SrcIfidx() int32 {
	return e.src.ifidx
}

func (e *StdNetEndpoint2) DstToBytes() []byte {
	b, _ := e.AddrPort.MarshalBinary()
	return b
}

func (e *StdNetEndpoint2) DstToString() string {
	return e.AddrPort.String()
}

func (e *StdNetEndpoint2) SrcToString() string {
	return e.src.Addr.String()
}

func (s *StdNetBind2) listenNet(network string, port int) (*net.UDPConn, int, error) {
	// TODO: github.com/WireGuard/wireguard-go/blob/1417a47c8/conn/controlfns_unix.go
	conn, err := s.lc.ListenPacket(context.Background(), network, ":"+strconv.Itoa(port))
	if err != nil {
		return nil, 0, err
	}

	// Retrieve port.
	caddr := conn.LocalAddr()
	src, err := net.ResolveUDPAddr(caddr.Network(), caddr.String())
	if err != nil {
		return nil, 0, err
	}
	return conn.(*net.UDPConn), src.Port, nil
}

func (s *StdNetBind2) Open(uport uint16) ([]conn.ReceiveFunc, uint16, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var err error
	var tries int

	if s.ipv4 != nil || s.ipv6 != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	// Attempt to open ipv4 and ipv6 listeners on the same port.
	// If uport is 0, we can retry on failure.
again:
	port := int(uport)
	var v4conn, v6conn *net.UDPConn

	// v4
	v4conn, port, err = s.listenNet("udp4", port)
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		return nil, 0, err
	}

	// v6: Listen on the same port as we're using for ipv4.
	v6conn, port, err = s.listenNet("udp6", port)
	if uport == 0 && errors.Is(err, syscall.EADDRINUSE) && tries < 100 {
		v4conn.Close()
		tries++
		goto again
	}
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		v4conn.Close()
		return nil, 0, err
	}

	var fns []conn.ReceiveFunc
	if v4conn != nil {
		fns = append(fns, s.makeReceiveIPv4(v4conn))
		s.ipv4 = v4conn
	}
	if v6conn != nil {
		fns = append(fns, s.makeReceiveIPv6(v6conn))
		s.ipv6 = v6conn
	}
	if len(fns) == 0 {
		return nil, 0, syscall.EAFNOSUPPORT
	}

	return fns, uint16(port), nil
}

func (s *StdNetBind2) makeReceiveIPv4(uc *net.UDPConn) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		msgs := s.ipv4MsgsPool.Get().(*[]ipv4.Message)
		defer s.ipv4MsgsPool.Put(msgs)
		for i := range bufs {
			(*msgs)[i].Buffers[0] = bufs[i]
		}
		var numMsgs int

		msg := &(*msgs)[0]
		msg.N, msg.NN, _, msg.Addr, err = uc.ReadMsgUDP(msg.Buffers[0], msg.OOB)
		if err != nil {
			return 0, err
		}
		numMsgs = 1
		for i := 0; i < numMsgs; i++ {
			msg := &(*msgs)[i]
			sizes[i] = msg.N
			addrPort := msg.Addr.(*net.UDPAddr).AddrPort()
			ep := asEndpoint2(addrPort)
			eps[i] = ep
		}
		return numMsgs, nil
	}
}

func (s *StdNetBind2) makeReceiveIPv6(uc *net.UDPConn) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		msgs := s.ipv4MsgsPool.Get().(*[]ipv6.Message)
		defer s.ipv4MsgsPool.Put(msgs)
		for i := range bufs {
			(*msgs)[i].Buffers[0] = bufs[i]
		}
		var numMsgs int

		msg := &(*msgs)[0]
		msg.N, msg.NN, _, msg.Addr, err = uc.ReadMsgUDP(msg.Buffers[0], msg.OOB)
		if err != nil {
			return 0, err
		}
		numMsgs = 1

		for i := 0; i < numMsgs; i++ {
			msg := &(*msgs)[i]
			sizes[i] = msg.N
			addrPort := msg.Addr.(*net.UDPAddr).AddrPort()
			ep := asEndpoint2(addrPort)
			eps[i] = ep
		}
		return numMsgs, nil
	}
}

// TODO: When all Binds handle IdealBatchSize, remove this dynamic function and
// rename the IdealBatchSize constant to BatchSize.
func (s *StdNetBind2) BatchSize() int {
	return 1
}

func (s *StdNetBind2) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var err1, err2 error
	if s.ipv4 != nil {
		err1 = s.ipv4.Close()
		s.ipv4 = nil
	}
	if s.ipv6 != nil {
		err2 = s.ipv6.Close()
		s.ipv6 = nil
	}

	if err1 != nil {
		return err1
	}
	return err2
}

func (s *StdNetBind2) Send(bufs [][]byte, endpoint conn.Endpoint) error {
	s.mu.Lock()
	conn := s.ipv4
	is6 := false
	if endpoint.DstIP().Is6() {
		conn = s.ipv6
		is6 = true
	}
	s.mu.Unlock()

	if conn == nil {
		return syscall.EAFNOSUPPORT
	}
	if is6 {
		return s.send6(conn, endpoint, bufs)
	} else {
		return s.send4(conn, endpoint, bufs)
	}
}

func (s *StdNetBind2) send4(conn *net.UDPConn, ep conn.Endpoint, bufs [][]byte) error {
	ua := s.udpAddrPool.Get().(*net.UDPAddr)
	as4 := ep.DstIP().As4()
	copy(ua.IP, as4[:])
	ua.IP = ua.IP[:4]
	ua.Port = int(ep.(*StdNetEndpoint2).Port())
	msgs := s.ipv4MsgsPool.Get().(*[]ipv4.Message)
	for i, buf := range bufs {
		(*msgs)[i].Buffers[0] = buf
		(*msgs)[i].Addr = ua
	}
	var err error

	for i, buf := range bufs {
		_, _, err = conn.WriteMsgUDP(buf, (*msgs)[i].OOB, ua)
		if err != nil {
			break
		}
	}

	s.udpAddrPool.Put(ua)
	s.ipv4MsgsPool.Put(msgs)
	return err
}

func (s *StdNetBind2) send6(conn *net.UDPConn, ep conn.Endpoint, bufs [][]byte) error {
	ua := s.udpAddrPool.Get().(*net.UDPAddr)
	as16 := ep.DstIP().As16()
	copy(ua.IP, as16[:])
	ua.IP = ua.IP[:16]
	ua.Port = int(ep.(*StdNetEndpoint2).Port())
	msgs := s.ipv6MsgsPool.Get().(*[]ipv6.Message)
	for i, buf := range bufs {
		(*msgs)[i].Buffers[0] = buf
		(*msgs)[i].Addr = ua
	}
	var err error
	for i, buf := range bufs {
		_, _, err = conn.WriteMsgUDP(buf, (*msgs)[i].OOB, ua)
		if err != nil {
			break
		}
	}
	s.udpAddrPool.Put(ua)
	s.ipv6MsgsPool.Put(msgs)
	return err
}

// endpointPool2 contains a re-usable set of mapping from netip.AddrPort to Endpoint.
// This exists to reduce allocations: Putting a netip.AddrPort in an Endpoint allocates,
// but Endpoints are immutable, so we can re-use them.
var endpointPool2 = sync.Pool{
	New: func() any {
		return make(map[netip.AddrPort]*StdNetEndpoint2)
	},
}

// asEndpoint2 returns an Endpoint containing ap.
func asEndpoint2(ap netip.AddrPort) *StdNetEndpoint2 {
	m := endpointPool.Get().(map[netip.AddrPort]*StdNetEndpoint2)
	defer endpointPool.Put(m)
	e, ok := m[ap]
	if !ok {
		e = &StdNetEndpoint2{AddrPort: ap}
		m[ap] = e
	}
	return e
}

// from: github.com/WireGuard/wireguard-go/blob/1417a47c8/conn/mark_unix.go
func (s *StdNetBind2) SetMark(mark uint32) (err error) {
	var operr error
	var raw4, raw6 syscall.RawConn
	fwmarkIoctl := 36 /* unix.SO_MARK */
	if s.ipv4 != nil {
		if raw4, err = s.ipv4.SyscallConn(); err == nil {
			if err = raw4.Control(func(fd uintptr) {
				operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, int(mark))
			}); err == nil {
				err = operr
			}
		} // else: return err
	}
	if err == nil && s.ipv6 != nil {
		if raw6, err = s.ipv6.SyscallConn(); err == nil {
			if err = raw6.Control(func(fd uintptr) {
				operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, int(mark))
			}); err == nil {
				err = operr
			}
		} // else: return err
	}
	log.W("wg: failed to set mark on socket: %v", err)
	return nil
}
