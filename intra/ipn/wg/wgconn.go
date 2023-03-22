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
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"github.com/celzero/firestack/intra/log"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
)

const maxbindtries = 10

// StdNetBind is meant to be a temporary solution on platforms for which
// the sticky socket / source caching behavior has not yet been implemented.
// It uses the Go's net package to implement networking.
// See LinuxSocketBind for a proper implementation on the Linux platform.
type StdNetBind struct {
	mu         sync.Mutex // protects following fields
	ipv4       *net.UDPConn
	ipv6       *net.UDPConn
	blackhole4 bool
	blackhole6 bool
}

func NewBind() conn.Bind {
	return &StdNetBind{}
}

type StdNetEndpoint netip.AddrPort

var (
	_ conn.Bind     = (*StdNetBind)(nil)
	_ conn.Endpoint = StdNetEndpoint{}
)

func (*StdNetBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	e, err := netip.ParseAddrPort(s)
	return asEndpoint(e), err
}

func (StdNetEndpoint) ClearSrc() {}

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

func (s *StdNetBind) listenNet(network string, port int) (*net.UDPConn, int, error) {
	conn, err := net.ListenUDP(network, &net.UDPAddr{Port: port})
	if err != nil {
		return nil, 0, err
	}

	// Retrieve port.
	laddr := conn.LocalAddr()
	uaddr, err := net.ResolveUDPAddr(
		laddr.Network(),
		laddr.String(),
	)
	if err != nil {
		return nil, 0, err
	}
	return conn, uaddr.Port, nil
}

func (bind *StdNetBind) Open(uport uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	var err error
	var tries int

	if bind.ipv4 != nil || bind.ipv6 != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	// Attempt to open ipv4 and ipv6 listeners on the same port.
	// If uport is 0, we can retry on failure.
again:
	port := int(uport)
	var ipv4, ipv6 *net.UDPConn

	ipv4, port, err = bind.listenNet("udp4", port)
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		return nil, 0, err
	}

	// Listen on the same port as we're using for ipv4.
	ipv6, port, err = bind.listenNet("udp6", port)
	if uport == 0 && errors.Is(err, syscall.EADDRINUSE) && tries < maxbindtries {
		ipv4.Close()
		tries++
		goto again
	}
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		ipv4.Close()
		return nil, 0, err
	}
	var fns []conn.ReceiveFunc
	if ipv4 != nil {
		fns = append(fns, bind.makeReceiveFn(ipv4))
		bind.ipv4 = ipv4
	}
	if ipv6 != nil {
		fns = append(fns, bind.makeReceiveFn(ipv6))
		bind.ipv6 = ipv6
	}
	if len(fns) == 0 {
		return nil, 0, syscall.EAFNOSUPPORT
	}
	return fns, uint16(port), nil
}

func (bind *StdNetBind) Close() error {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	var err1, err2 error
	if bind.ipv4 != nil {
		err1 = bind.ipv4.Close()
		bind.ipv4 = nil
	}
	if bind.ipv6 != nil {
		err2 = bind.ipv6.Close()
		bind.ipv6 = nil
	}
	bind.blackhole4 = false
	bind.blackhole6 = false
	if err1 != nil {
		return err1
	}
	return err2
}

func (s *StdNetBind) makeReceiveFn(uc *net.UDPConn) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		numMsgs := 0
		b := bufs[0]

		n, addr, err := uc.ReadFromUDPAddrPort(b)
		if err == nil {
			numMsgs++
		}

		for i := 0; i < numMsgs; i++ {
			sizes[i] = n
			eps[i] = asEndpoint(addr)
		}
		return numMsgs, err
	}
}

func (bind *StdNetBind) Send(buf [][]byte, endpoint conn.Endpoint) error {
	var err error
	nend, ok := endpoint.(StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	addrPort := netip.AddrPort(nend)

	bind.mu.Lock()
	blackhole := bind.blackhole4
	uc := bind.ipv4
	if addrPort.Addr().Is6() {
		blackhole = bind.blackhole6
		uc = bind.ipv6
	}
	bind.mu.Unlock()

	if blackhole {
		return nil
	}
	if uc == nil {
		return syscall.EAFNOSUPPORT
	}
	_, err = uc.WriteToUDPAddrPort(buf[0], addrPort)
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

// from: github.com/WireGuard/wireguard-go/1417a47c8/conn/boundif_android.go
func (s *StdNetBind) PeekLookAtSocketFd4() (fd int, err error) {
	sysconn, err := s.ipv4.SyscallConn()
	if err != nil {
		return -1, err
	}
	err = sysconn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return -1, err
	}
	return
}

func (s *StdNetBind) PeekLookAtSocketFd6() (fd int, err error) {
	sysconn, err := s.ipv6.SyscallConn()
	if err != nil {
		return -1, err
	}
	err = sysconn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return -1, err
	}
	return
}

// endpointPool contains a re-usable set of mapping from netip.AddrPort to Endpoint.
// This exists to reduce allocations: Putting a netip.AddrPort in an Endpoint allocates,
// but Endpoints are immutable, so we can re-use them.
var endpointPool = sync.Pool{
	New: func() any {
		return make(map[netip.AddrPort]conn.Endpoint)
	},
}

// asEndpoint returns an Endpoint containing ap.
func asEndpoint(ap netip.AddrPort) conn.Endpoint {
	m := endpointPool.Get().(map[netip.AddrPort]conn.Endpoint)
	defer endpointPool.Put(m)
	e, ok := m[ap]
	if !ok {
		e = conn.Endpoint(StdNetEndpoint(ap))
		m[ap] = e
	}
	return e
}
