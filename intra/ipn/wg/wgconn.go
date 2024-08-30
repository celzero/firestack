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
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/ipn/multihost"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
)

// from: github.com/WireGuard/wireguard-go/blob/ebbd4a433/conn/bind_std.go

const maxbindtries = 50
const wgtimeout = 60 * time.Second

var (
	errInvalidEndpoint = errors.New("wg: bind: no endpoint")
	errNoLocalAddr     = errors.New("wg: bind: no local address")
	errNoRawConn       = errors.New("wg: bind: no raw conn")
	errNotUDP          = errors.New("wg: bind: not a UDP conn")
	errNoListen        = errors.New("wg: bind: listen failed")
)

type rwlistener func(op string, err error)

type StdNetBind struct {
	id string
	d  *net.ListenConfig
	mh *multihost.MH

	mu         sync.Mutex // protects following fields
	ipv4       *net.UDPConn
	ipv6       *net.UDPConn
	blackhole4 bool
	blackhole6 bool

	listener     rwlistener
	lastSendAddr netip.AddrPort // may be invalid
}

func NewEndpoint(id string, ctl protect.Controller, ep *multihost.MH, f rwlistener) *StdNetBind {
	dialer := protect.MakeNsListener(id, ctl)
	return &StdNetBind{id: id, d: dialer, mh: ep, listener: f}
}

type StdNetEndpoint netip.AddrPort

var (
	_ conn.Bind     = (*StdNetBind)(nil)
	_ conn.Endpoint = StdNetEndpoint{}
)

func (e *StdNetBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	d := e.mh
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
	// do what tailscale does, and share a preferred endpoint regardless of "s"
	// github.com/tailscale/tailscale/blob/3a6d3f1a5b7/wgengine/magicsock/magicsock.go#L2568
	// d.Add([]string{host}) // resolves host if needed
	ipport := d.PreferredAddr()
	if !ipport.IsValid() || ipport.Addr().IsUnspecified() {
		log.E("wg: bind: %s invalid endpoint addr %v in(%s); out(%s, %s)", e.id, ipport, s, d.Names(), d.Addrs())
		// erroring out from here prevents PostConfig (handshake for this peer endpoint will always be zero)
		// github.com/WireGuard/wireguard-go/blob/12269c276173/device/uapi.go#L183
		return nil, errInvalidEndpoint
	}

	log.I("wg: bind: %s new shared endpoint for %s %v", e.id, s, ipport)
	return asEndpoint(ipport), nil
}

func (StdNetEndpoint) ClearSrc() {} // not supported

func (e StdNetEndpoint) DstIP() netip.Addr {
	return (netip.AddrPort)(e).Addr()
}

func (e StdNetEndpoint) SrcIP() netip.Addr {
	return netip.Addr{} // not supported
}

func (e StdNetEndpoint) DstToBytes() []byte {
	b, _ := (netip.AddrPort)(e).MarshalBinary()
	return b
}

func (e StdNetEndpoint) DstToString() string {
	return (netip.AddrPort)(e).String()
}

func (e StdNetEndpoint) SrcToString() string {
	return ""
}

func (s *StdNetBind) RemoteAddr() netip.AddrPort {
	return s.lastSendAddr
}

func (s *StdNetBind) listenNet(network string, port int) (*net.UDPConn, int, error) {
	ctx := context.Background()
	saddr := ":" + strconv.Itoa(port)
	conn, err := s.d.ListenPacket(ctx, network, saddr)
	if err != nil {
		log.E("wg: bind: %s %s: listen(%v); err: %v", s.id, network, saddr, err)
		return nil, 0, err
	}
	if conn == nil {
		log.E("wg: bind: %s %s: listen(%v); conn nil", s.id, network, saddr)
		return nil, 0, errNoListen
	}

	laddr := conn.LocalAddr()
	if laddr == nil {
		log.E("wg: bind: %s %s: listen(%v); local-addr nil", s.id, network, saddr)
		return nil, 0, errNoLocalAddr
	}
	uaddr, err := net.ResolveUDPAddr(
		laddr.Network(),
		laddr.String(),
	)
	if err != nil {
		return nil, 0, err
	}
	if uaddr == nil {
		return nil, 0, errNoLocalAddr
	}
	log.V("wg: bind: %s %s: listen(%v)", s.id, network, laddr)
	// typecast is safe, because "network" is always udp[4|6]; see: Open
	if udpconn, ok := conn.(*net.UDPConn); ok {
		return udpconn, uaddr.Port, nil
	} else {
		clos(conn)
		return nil, 0, errNotUDP
	}
}

func (bind *StdNetBind) Open(uport uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	var err error
	var tries int

	if bind.ipv4 != nil || bind.ipv6 != nil {
		log.W("wg: bind: %s already open", bind.id)
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	// Attempt to open ipv4 and ipv6 listeners on the same port.
	// If uport is 0, we can retry on failure.
again:
	port := int(uport)
	var ipv4, ipv6 *net.UDPConn

	ipv4, port, err = bind.listenNet("udp4", port)
	no4 := errors.Is(err, syscall.EAFNOSUPPORT)
	log.D("wg: bind: %s #%d listen4(%d); no4? %t err? %v", bind.id, tries, port, no4, err)
	if err != nil && !no4 {
		return nil, 0, err
	}

	// Listen on the same port as we're using for ipv4.
	ipv6, port, err = bind.listenNet("udp6", port)
	busy := errors.Is(err, syscall.EADDRINUSE)
	no6 := errors.Is(err, syscall.EAFNOSUPPORT)
	log.D("wg: bind: %s #%d listen6(%d); busy? %t no6? %t err? %v", bind.id, tries, port, busy, no6, err)
	if uport == 0 && busy && tries < maxbindtries {
		clos(ipv4)
		tries++
		goto again
	}
	if err != nil && !no6 {
		clos(ipv4)
		return nil, 0, err
	}

	var fns []conn.ReceiveFunc
	if ipv4 != nil {
		bind.ipv4 = ipv4
		fns = append(fns, bind.makeReceiveFn(ipv4))
	}
	if ipv6 != nil {
		bind.ipv6 = ipv6
		fns = append(fns, bind.makeReceiveFn(ipv6))
	}

	log.I("wg: bind: %s opened port(%d) for v4? %t v6? %t", bind.id, port, ipv4 != nil, ipv6 != nil)
	if len(fns) == 0 {
		return nil, 0, syscall.EAFNOSUPPORT
	}
	return fns, uint16(port), nil
}

func (bind *StdNetBind) Close() error {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	var err1, err2 error
	v4, v6 := bind.ipv4, bind.ipv6
	if v4 != nil {
		err1 = v4.Close()
		bind.ipv4 = nil
	}
	if v6 != nil {
		err2 = v6.Close()
		bind.ipv6 = nil
	}
	bind.blackhole4 = false
	bind.blackhole6 = false

	log.I("wg: bind: %s close; err4? %v err6? %v", bind.id, err1, err2)
	return errors.Join(err1, err2)
}

func (s *StdNetBind) makeReceiveFn(uc *net.UDPConn) conn.ReceiveFunc {
	// github.com/WireGuard/wireguard-go/blob/469159ecf/device/device.go#L531
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		defer func() {
			s.listener("r", err)
		}()

		numMsgs := 0
		b := bufs[0]

		extend(uc, wgtimeout)
		n, addr, err := uc.ReadFromUDPAddrPort(b)
		if err == nil {
			numMsgs++
		}

		for i := 0; i < numMsgs; i++ {
			sizes[i] = n
			eps[i] = asEndpoint(addr)
		}

		s := fmt.Sprintf("wg: bind: %s recvFrom(%v): %d / err? %v", s.id, addr, n, err)
		if err == nil || timedout(err) {
			log.D(s)
		} else {
			log.E(s)
		}
		return numMsgs, err
	}
}

func timedout(err error) bool {
	if err == nil {
		return false
	}
	x, ok := err.(net.Error)
	return ok && x.Timeout()
}

func (s *StdNetBind) Send(buf [][]byte, peer conn.Endpoint) (err error) {
	defer func() {
		s.listener("w", err)
	}()

	where, ok := peer.(StdNetEndpoint)
	if !ok {
		log.E("wg: bind: send: %s wrong endpoint type: %T", s.id, peer)
		return conn.ErrWrongEndpointType
	}
	// the peer endpoint
	dst := netip.AddrPort(where)

	s.mu.Lock()
	blackhole := s.blackhole4
	uc := s.ipv4
	noconn := uc == nil
	if dst.Addr().Is6() {
		blackhole = s.blackhole6
		uc = s.ipv6
		noconn = uc == nil
	}
	s.mu.Unlock()

	var data []byte
	if len(buf) > 0 && len(buf[0]) > 0 {
		data = buf[0]
	}
	bufok := len(data) > 0

	log.V("wg: bind: send: %s addr(%v) blackhole? %t; noconn? %t; hasbuf? %t", s.id, dst, blackhole, noconn, bufok)

	if blackhole || !bufok {
		return nil
	}
	if noconn {
		return syscall.EAFNOSUPPORT
	}

	s.lastSendAddr = dst

	extend(uc, wgtimeout)
	n, err := uc.WriteToUDPAddrPort(data, dst)

	loge(err, "wg: bind: send: %s addr(%v) n(%d); err? %v", s.id, dst, n, err)
	return err
}

func (s *StdNetBind) BatchSize() int {
	return 1
}

// from: github.com/WireGuard/wireguard-go/blob/1417a47c8/conn/mark_unix.go
func (s *StdNetBind) SetMark(mark uint32) (err error) {
	var operr error
	var raw4, raw6 syscall.RawConn
	fwmarkIoctl := 36 /* unix.SO_MARK */
	if s.ipv4 != nil {
		if raw4, err = s.ipv4.SyscallConn(); err == nil {
			if raw4 == nil {
				log.W("wg: bind: %s setmark4: raw conn nil", s.id)
				return errNoRawConn
			}
			if err = raw4.Control(func(fd uintptr) {
				operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, int(mark))
			}); err == nil {
				err = operr
			}
		} // else: return err
	}
	if err == nil && s.ipv6 != nil {
		if raw6, err = s.ipv6.SyscallConn(); err == nil {
			if raw6 == nil {
				log.W("wg: bind: %s setmark6: raw conn nil", s.id)
				return errNoRawConn
			}
			if err = raw6.Control(func(fd uintptr) {
				operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, int(mark))
			}); err == nil {
				err = operr
			}
		} // else: return err
	}
	log.I("wg: bind: %s set mark; err? %v", err, s.id)
	return nil
}

// from: github.com/WireGuard/wireguard-go/1417a47c8/conn/boundif_android.go
func (s *StdNetBind) PeekLookAtSocketFd4() (fd int, err error) {
	raw4, err := s.ipv4.SyscallConn()
	if err != nil {
		log.W("wg: bind: peek4: %s syscall conn; err? %v", s.id, err)
		return -1, err
	}
	if raw4 == nil {
		log.W("wg: bind: peek4: %s raw conn nil", s.id)
		return -1, errNoRawConn
	}
	err = raw4.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		log.W("wg: bind: control4: %s syscall conn; err? %v", s.id, err)
		return -1, err
	}
	log.D("wg: bind: peek4: %s fd(%d)", s.id, fd)
	return
}

func (s *StdNetBind) PeekLookAtSocketFd6() (fd int, err error) {
	raw6, err := s.ipv6.SyscallConn()
	if err != nil {
		log.W("wg: bind: peek6: %s syscall conn; err? %v", s.id, err)
		return -1, err
	}
	if raw6 == nil {
		log.W("wg: bind: peek6: %s raw conn nil", s.id)
		return -1, errNoRawConn
	}
	err = raw6.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		log.W("wg: bind: control6: %s syscall conn; err? %v", s.id, err)
		return -1, err
	}
	log.D("wg: bind: peek6: %s fd(%d)", s.id, fd)
	return
}

// asEndpoint returns an Endpoint containing ap.
// pooling disabled due to data race:
// github.com/WireGuard/wireguard-go/commit/334b605e726
func asEndpoint(ap netip.AddrPort) conn.Endpoint {
	return StdNetEndpoint(ap)
}

func loge(err error, msg string, rest ...any) {
	l := log.V
	if err != nil {
		l = log.W
	}
	l(msg, rest...)
}

func extend(c net.Conn, t time.Duration) {
	if c != nil && core.IsNotNil(c) {
		_ = c.SetDeadline(time.Now().Add(t))
	}
}

func clos(c io.Closer) {
	core.CloseOp(c, core.CopRW)
}
