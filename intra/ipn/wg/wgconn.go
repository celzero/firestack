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
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"sync"
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

const maxbindtries = 50
const wgtimeout = 60 * time.Second

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
)

const (
	minFloodPkts     = 3
	maxFloodPkts     = minFloodPkts * 10
	maxFloodDuration = 3 * time.Second
	minFloodInterval = 30 * time.Second // flood once every 30s

	minFloodPktLen = 28  // bytes; must be > len(wgheader)
	maxFloodPktLen = 138 // must be >> minFloodPktLen; < device.MessageInitiationSize?
)

var (
	errInvalidEndpoint = errors.New("wg: bind: no endpoint")
	errNoLocalAddr     = errors.New("wg: bind: no local address")
	errNoRawConn       = errors.New("wg: bind: no raw conn")
	errNotUDP          = errors.New("wg: bind: not a UDP conn")
	errNoListen        = errors.New("wg: bind: listen failed")
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

type rwlistener func(op string, err error)
type connector func(network, to string) (net.PacketConn, error)

type StdNetBind struct {
	id      string
	connect connector
	mh      *multihost.MH

	reserved []byte // overwrite the 3 wg reserved bytes
	floodBa  *core.Barrier[int, netip.AddrPort]

	mu         sync.Mutex // protects following fields
	ipv4       *net.UDPConn
	ipv6       *net.UDPConn
	blackhole4 bool
	blackhole6 bool

	listener     rwlistener
	lastSendAddr netip.AddrPort // may be invalid
}

// TODO: get d, ep, f, rb through an Opts bag?
func NewEndpoint(id string, d connector, ep *multihost.MH, f rwlistener, rb [3]byte) *StdNetBind {
	return &StdNetBind{
		id:       id,
		connect:  d,
		mh:       ep,
		listener: f,
		reserved: rb[:3],
		floodBa:  core.NewKeyedBarrier[int, netip.AddrPort](minFloodInterval),
	}
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
	saddr := ":" + strconv.Itoa(port)
	conn, err := s.connect(network, saddr)
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

	var overwriteReserved = s.overwriteReserved()
	var experimentalWg = settings.ExperimentalWireGuard.Load()
	var flooded, overwritten bool
	var nn int
	var errs error
	for _, data := range buf {
		bufok := len(data) > 0

		log.V("wg: bind: send: %s addr(%v) exp? %t, blackhole? %t; noconn? %t; hasbuf? %t",
			s.id, dst, experimentalWg, blackhole, noconn, bufok)

		if blackhole || !bufok {
			return nil
		}
		if noconn {
			return syscall.EAFNOSUPPORT
		}

		if experimentalWg {
			// overwrite the 3 reserved bytes on non-random packets
			if overwriteReserved {
				if len(data) > 3 && isWgMsgType(data[0]) {
					// from: github.com/bepass-org/warp-plus/blob/19ac233cc6/wireguard/device/peer.go#L138
					copy(data[1:4], s.reserved)
					overwritten = true
				}
				if !flooded && !overwritten {
					if len(data) == device.MessageInitiationSize {
						go s.flood(uc, dst, fkHandshake) // probably a handshake
						flooded = true
					} else if len(data) == device.MessageKeepaliveSize {
						go s.flood(uc, dst, fkKeepalive) // probably a keepalive
						flooded = true
					}
				}
			}
		}

		extend(uc, wgtimeout)
		n, serr := uc.WriteToUDPAddrPort(data, dst)

		errs = errors.Join(errs, serr)
		nn += n
	}

	s.lastSendAddr = dst

	loge(err, "wg: bind: send: %s addr(%v) parcels(%d) tx(%d) (exp? %t: flooded? %t / any-overwritten? %t); err? %v",
		s.id, dst, len(buf), nn, experimentalWg, flooded, overwritten, errs)
	return err
}

// github.com/WireGuard/wireguard-go/blob/12269c2761/device/send.go#L456
// github.com/WireGuard/wireguard-go/blob/12269c2761/device/noise-protocol.go#L56
func isWgMsgType(x byte) bool {
	// 1: MsgInitiation, 2: MsgResponse, 3: MsgCookieReply, 4: MsgTransport
	return x >= 1 && x <= 4
}

// flood c with random-sized, non-sense (unencrypted) packets.
// this is okay to do because wireguard silently drops packets that won't decrypt.
// github.com/WireGuard/wireguard-go/blob/19ac233cc6/wireguard/device/send.go#L96
// github.com/GFW-knocker/wireguard/blob/8bd9f582b4/device/send.go#L98
func (s *StdNetBind) flood(c *net.UDPConn, dst netip.AddrPort, why floodkind) (int, error) {
	return s.floodBa.DoIt(dst, func() (int, error) {
		hdrlen := len(wgheader)
		hdr := make([]byte, hdrlen)
		copy(hdr, wgheader)

		hdr[0] = mlist[mrand.UintN(uint(len(mlist)))]
		_, _ = rand.Read(hdr[6:14])

		tot := mrand.Uint64N(maxFloodPkts + 1)
		if tot < minFloodPkts {
			tot = minFloodPkts
		}
		// go.dev/play/p/NkLihAUTqUO
		maxWaitMs := maxFloodDuration.Milliseconds() / int64(tot)
		expectedsent := make([]int, tot)

		// gfw-knocker generates much smaller pkts (18 + (10 to 30))
		// github.com/GFW-knocker/wireguard/blob/8bd9f582b4/device/send.go#L141
		padlen := uint64(maxFloodPktLen - hdrlen)
		pkt := make([]byte, maxFloodPktLen)
		var n int
		for i := uint64(0); i < tot; i++ {
			sz := mrand.Uint64N(padlen + 1)
			if sz < minFloodPktLen {
				sz = minFloodPktLen
			}
			_, _ = rand.Read(pkt[hdrlen:sz])
			copy(pkt[0:], hdr)

			extend(c, wgtimeout)
			sent, err := c.WriteToUDPAddrPort(pkt, dst)

			expectedsent[i] = hdrlen + int(sz)
			n += sent

			if err != nil {
				log.E("wg: bind: %s flood %s %s: expected sent?(%v) / tot(%d); %v",
					s.id, why, dst, expectedsent[:i], n, err)
				return n, err
			}

			wait := time.Duration(mrand.Int64N(maxWaitMs)) * time.Millisecond
			time.Sleep(wait)
		}

		log.I("wg: bind: %s flood %s %s: expected sent?(%v) / tot(%d)",
			s.id, why, dst, expectedsent, n)
		return n, nil
	})
}

func (s *StdNetBind) overwriteReserved() bool {
	return len(s.reserved) == 3 &&
		s.reserved[0] != 0 ||
		s.reserved[1] != 0 ||
		s.reserved[2] != 0
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
