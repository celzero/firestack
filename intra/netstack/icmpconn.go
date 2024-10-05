// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// from: github.com/WireGuard/wireguard-go/blob/5819c6af/tun/netstack/tun.go

package netstack

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var (
	errStub            = errors.New("not implemented")
	errIPProtoMismatch = fmt.Errorf("ping write: mismatched protocols")
	errWrongAddr       = errors.New("ping write: wrong address type")
)

type GICMPConn struct {
	nic      tcpip.NICID
	src      PingAddr
	dst      PingAddr
	is6      bool
	wq       waiter.Queue
	ep       tcpip.Endpoint
	deadline *time.Timer
}

var _ core.ICMPConn = (*GICMPConn)(nil)

type PingAddr struct{ addr netip.Addr }

func (ipp PingAddr) String() string {
	return ipp.addr.String()
}

func (ipp PingAddr) Network() string {
	if ipp.addr.Is4() {
		return "ping4"
	} else if ipp.addr.Is6() {
		return "ping6"
	}
	return "ping"
}

func (ipp PingAddr) Addr() netip.Addr {
	return ipp.addr
}

func PingAddrFromAddr(addr netip.Addr) *PingAddr {
	return &PingAddr{addr}
}

func DialPingAddr(s *stack.Stack, nic tcpip.NICID, laddr, raddr netip.Addr) (*GICMPConn, error) {
	if !laddr.IsValid() && !raddr.IsValid() {
		return nil, errors.New("ping dial: invalid address")
	}
	v6 := laddr.Is6() || raddr.Is6()
	bind := laddr.IsValid()
	if !bind {
		if v6 {
			laddr = netip.IPv6Unspecified()
		} else {
			laddr = netip.IPv4Unspecified()
		}
	}

	tn := icmp.ProtocolNumber4
	pn := ipv4.ProtocolNumber
	if v6 {
		tn = icmp.ProtocolNumber6
		pn = ipv6.ProtocolNumber
	}

	var wq waiter.Queue
	ep, tcpipErr := s.NewEndpoint(tn, pn, &wq)
	if tcpipErr != nil || ep == nil {
		return nil, fmt.Errorf("ping socket: endpoint: %s", tcpipErr)
	}
	pc := &GICMPConn{
		nic:      nic,
		src:      PingAddr{laddr},
		is6:      v6,
		ep:       ep,
		deadline: time.NewTimer(time.Hour << 10),
	}
	pc.deadline.Stop()

	if bind {
		fa, _ := fullAddrFrom(nic, netip.AddrPortFrom(laddr, 0))
		if tcpipErr = pc.ep.Bind(fa); tcpipErr != nil {
			return nil, fmt.Errorf("ping bind: %s", tcpipErr)
		}
	}

	if raddr.IsValid() {
		pc.dst = PingAddr{raddr}
		fa, _ := fullAddrFrom(nic, netip.AddrPortFrom(raddr, 0))
		if tcpipErr = pc.ep.Connect(fa); tcpipErr != nil {
			return nil, fmt.Errorf("ping connect: %s", tcpipErr)
		}
	} // unconnected

	return pc, nil
}

func (pc *GICMPConn) LocalAddr() net.Addr {
	return pc.src
}

func (pc *GICMPConn) RemoteAddr() net.Addr {
	return pc.dst
}

func (pc *GICMPConn) Close() error {
	pc.deadline.Reset(0)
	if ep := pc.ep; ep != nil {
		go ep.Close() // Close holds ep.mu
	}
	return nil
}

func (pc *GICMPConn) SetWriteDeadline(t time.Time) error {
	return errStub
}

func (pc *GICMPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	var ip netip.Addr
	switch v := addr.(type) {
	case *PingAddr:
		ip = v.addr
	case *net.IPAddr:
		ip, _ = netip.AddrFromSlice(v.IP)
	case *net.UDPAddr:
		ip, _ = netip.AddrFromSlice(v.IP)
	default:
		return 0, errWrongAddr
	}
	if !((ip.Is4() && !pc.is6) || (ip.Is6() && pc.is6)) {
		return 0, errIPProtoMismatch
	}

	buf := bytes.NewReader(p)
	remote, _ := fullAddrFrom(pc.nic, netip.AddrPortFrom(ip, 0))
	// won't block, no deadlines
	n64, tcpipErr := pc.ep.Write(buf, tcpip.WriteOptions{
		To: &remote,
	})

	// may overflow on 32-bit systems
	return int(n64), e(tcpipErr) // may be nil
}

func (pc *GICMPConn) Write(p []byte) (n int, err error) {
	return pc.WriteTo(p, &pc.dst)
}

func (pc *GICMPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	e, notifyCh := waiter.NewChannelEntry(waiter.EventIn)
	pc.wq.EventRegister(&e)
	defer pc.wq.EventUnregister(&e)

	select {
	case <-pc.deadline.C:
		return 0, nil, os.ErrDeadlineExceeded
	case <-notifyCh:
	}

	w := tcpip.SliceWriter(p)

	res, tcpipErr := pc.ep.Read(&w, tcpip.ReadOptions{
		NeedRemoteAddr: true,
	})
	if tcpipErr != nil {
		return 0, nil, fmt.Errorf("ping read: %s", tcpipErr)
	}

	remoteAddr, _ := netip.AddrFromSlice(res.RemoteAddr.Addr.AsSlice())
	return res.Count, &PingAddr{remoteAddr}, nil
}

func (pc *GICMPConn) Read(p []byte) (n int, err error) {
	n, _, err = pc.ReadFrom(p)
	return
}

func (pc *GICMPConn) SetDeadline(t time.Time) error {
	// pc.SetWriteDeadline is unimplemented

	return pc.SetReadDeadline(t)
}

func (pc *GICMPConn) SetReadDeadline(t time.Time) error {
	pc.deadline.Reset(time.Until(t))
	return nil
}

func fullAddrFrom(nic tcpip.NICID, ipp netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	var protoNumber tcpip.NetworkProtocolNumber
	var nsdaddr tcpip.Address
	if !ipp.IsValid() {
		// TODO: use unspecified address like in PingConn?
		return tcpip.FullAddress{}, 0
	}
	if ipp.Addr().Is4() {
		protoNumber = ipv4.ProtocolNumber
		nsdaddr = tcpip.AddrFrom4(ipp.Addr().As4())
	} else {
		protoNumber = ipv6.ProtocolNumber
		nsdaddr = tcpip.AddrFrom16(ipp.Addr().As16())
	}
	log.V("wg: dial: translate ipp: %v -> %v", ipp, nsdaddr)
	return tcpip.FullAddress{
		NIC:  nic,
		Addr: nsdaddr,
		Port: ipp.Port(), // may be 0
	}, protoNumber
}
