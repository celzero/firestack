// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//    SPDX-License-Identifier: MIT
//
//    Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.

// from: github.com/WireGuard/wireguard-go/blob/5819c6af/tun/netstack/tun.go

package ipn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var (
	errNoSuchHost        = errors.New("no such host")
	errNumericPort       = errors.New("port must be numeric")
	errNoSuitableAddress = errors.New("no suitable address found")
	errMissingAddress    = errors.New("missing address")
)

const (
	wgdnstimeout = time.Second * 5
	wgbarrierttl = time.Second * 10
)

// intra/tcp.go expects dst conns to confirm to core.TCPConn
var _ core.TCPConn = (*gonet.TCPConn)(nil)

// intra/udp.go expects dst conns to confirm to core.UDPConn
var _ core.UDPConn = (*gonet.UDPConn)(nil)

// --------------------------------------------------------------------
// dns dialer
// --------------------------------------------------------------------

func (net *wgtun) LookupHost(host string) (addrs []netip.Addr, err error) {
	return net.LookupContextHost(context.Background(), host)
}

func (tnet *wgtun) LookupContextHost(ctx context.Context, host string) ([]netip.Addr, error) {
	if len(host) <= 0 || (!tnet.hasV6 && !tnet.hasV4) {
		return nil, &net.DNSError{Err: errNoSuchHost.Error(), Name: host, IsNotFound: true}
	}
	zlen := len(host)
	if strings.IndexByte(host, ':') != -1 {
		if zidx := strings.LastIndexByte(host, '%'); zidx != -1 {
			zlen = zidx
		}
	}
	if ip, err := netip.ParseAddr(host[:zlen]); err == nil {
		return []netip.Addr{ip}, nil
	}

	// TODO: resolve via wireguard's DNS
	// dialers.For returns from cache (which may be stale)
	if ips := dialers.For(host); len(ips) <= 0 {
		log.D("wg: dial: lookup failed %q: no ips %v", host, ips)
		return nil, &net.DNSError{Err: errNoSuchHost.Error(), Name: host, IsNotFound: true}
	} else {
		return ips, nil
	}
}

// --------------------------------------------------------------------
// generic dialer
// --------------------------------------------------------------------

func (tnet *wgtun) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	var acceptV4, acceptV6 bool
	switch network {
	case "tcp", "udp", "ping":
		acceptV4 = true
		acceptV6 = true
	case "tcp4", "udp4", "ping4":
		acceptV4 = true
	case "tcp6", "udp6", "ping6":
		acceptV6 = true
	default:
		log.W("wg: dial: unknown network %q", network)
		return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError(network)}
	}

	var host string
	var port int
	if network == "ping" || network == "ping4" || network == "ping6" {
		host = address
	} else {
		var sport string
		var err error
		host, sport, err = net.SplitHostPort(address)
		if err != nil {
			log.W("wg: dial: invalid address %q: %v", address, err)
			return nil, &net.OpError{Op: "dial", Err: err}
		}
		port, err = strconv.Atoi(sport)
		if err != nil || port < 0 || port > 65535 {
			log.W("wg: dial: invalid port %q: %v", sport, err)
			return nil, &net.OpError{Op: "dial", Err: errNumericPort}
		}
	}

	rv, _ := tnet.reqbarrier.Do(host, resolve(tnet, host))
	if rv.Err != nil {
		log.W("wg: dial: lookup failed %q: %v", host, rv.Err)
		return nil, &net.OpError{Op: "dial", Err: rv.Err}
	}

	allAddrs := rv.Val
	var addrs []netip.AddrPort
	for _, ip := range allAddrs {
		if (ip.Is4() && acceptV4) || (ip.Is6() && acceptV6) {
			addrs = append(addrs, netip.AddrPortFrom(ip, uint16(port)))
		}
	}
	if len(addrs) == 0 && len(allAddrs) != 0 {
		log.W("wg: dial: no suitable address for %q / %v", host, allAddrs)
		return nil, &net.OpError{Op: "dial", Err: errNoSuitableAddress}
	}

	var errs error
	for i, addr := range addrs {
		var c net.Conn
		var err error
		switch network {
		case "tcp", "tcp4", "tcp6":
			c, err = tnet.DialTCPAddrPort(addr)
		case "udp", "udp4", "udp6":
			c, err = tnet.DialUDPAddrPort(netip.AddrPort{}, addr)
		case "ping", "ping4", "ping6":
			c, err = tnet.DialPingAddr(netip.Addr{}, addr.Addr())
		}
		log.I("wg: dial: %s: #%d %v", network, i, addr)
		if err == nil {
			dialers.Confirm2(host, addr.Addr())
			return c, nil
		}
		dialers.Disconfirm(host, addr.Addr())
		errs = errors.Join(errs, err)
	}
	if errs == nil {
		errs = &net.OpError{Op: "dial", Err: errMissingAddress}
	}
	log.W("wg: dial: %s: %v failed: %v", network, addrs, errs)
	return nil, errs
}

func resolve(tnet *wgtun, host string) core.Work[[]netip.Addr] {
	return func() ([]netip.Addr, error) {
		return tnet.LookupHost(host)
	}
}

// --------------------------------------------------------------------
// tcp and udp dialers
// --------------------------------------------------------------------

func fullAddrFrom(ipport netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	var protoNumber tcpip.NetworkProtocolNumber
	var nsdaddr tcpip.Address
	if ipport.Addr().Is4() {
		protoNumber = ipv4.ProtocolNumber
		nsdaddr = tcpip.AddrFrom4(ipport.Addr().As4())
	} else {
		protoNumber = ipv6.ProtocolNumber
		nsdaddr = tcpip.AddrFrom16(ipport.Addr().As16())
	}
	log.V("wg: dial: translate ipp: %v -> %v", ipport, nsdaddr)
	return tcpip.FullAddress{
		NIC:  wgnic,
		Addr: nsdaddr,
		Port: ipport.Port(),
	}, protoNumber
}

func ipportFrom(addr any) (ipp netip.AddrPort) {
	var err error
	switch addr := addr.(type) {
	case *net.TCPAddr:
		if ip, ok := netip.AddrFromSlice(addr.IP); ok {
			ipp = netip.AddrPortFrom(ip, uint16(addr.Port))
		} else {
			log.W("wg: dial: invalid tcp addr: %v", addr)
		}
	case *net.UDPAddr:
		if ip, ok := netip.AddrFromSlice(addr.IP); ok {
			ipp = netip.AddrPortFrom(ip, uint16(addr.Port))
		} else {
			log.W("wg: dial: invalid udp addr: %v", addr)
		}
	case string:
		// may error if addr is an IP addr without port
		if ipp, err = netip.ParseAddrPort(addr); err != nil {
			if ip, err2 := netip.ParseAddr(addr); err2 == nil {
				ipp = netip.AddrPortFrom(ip, 0)
			} else {
				log.W("wg: dial: addr: %v; err1: %v / err2: %v", addr, err, err2)
			}
		}
	default:
		log.W("wg: dial: unknown addr type: %T %v", addr, addr)
	}
	log.V("wg: dial: translate addr: %v -> %v", addr, ipp)
	return ipp
}

func (net *wgtun) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (*gonet.TCPConn, error) {
	faddr, protocol := fullAddrFrom(addr)
	return gonet.DialContextTCP(ctx, net.stack, faddr, protocol)
}

func (net *wgtun) DialContextTCP(ctx context.Context, addr *net.TCPAddr) (*gonet.TCPConn, error) {
	if addr == nil {
		return net.DialContextTCPAddrPort(ctx, netip.AddrPort{})
	}

	return net.DialContextTCPAddrPort(ctx, ipportFrom(addr))
}

func (net *wgtun) DialTCPAddrPort(addr netip.AddrPort) (*gonet.TCPConn, error) {
	faddr, protocol := fullAddrFrom(addr)
	return gonet.DialTCP(net.stack, faddr, protocol)
}

func (net *wgtun) DialTCP(addr *net.TCPAddr) (*gonet.TCPConn, error) {
	if addr == nil {
		return net.DialTCPAddrPort(netip.AddrPort{})
	}
	return net.DialTCPAddrPort(ipportFrom(addr))
}

func (net *wgtun) ListenTCPAddrPort(addr netip.AddrPort) (*gonet.TCPListener, error) {
	fa, pn := fullAddrFrom(addr)
	return gonet.ListenTCP(net.stack, fa, pn)
}

func (net *wgtun) ListenTCP(addr *net.TCPAddr) (*gonet.TCPListener, error) {
	if addr == nil {
		return net.ListenTCPAddrPort(netip.AddrPort{})
	}
	return net.ListenTCPAddrPort(ipportFrom(addr))
}

func (net *wgtun) DialUDPAddrPort(laddr, raddr netip.AddrPort) (*gonet.UDPConn, error) {
	var src, dst *tcpip.FullAddress
	var protocol tcpip.NetworkProtocolNumber
	if laddr.IsValid() || laddr.Port() > 0 {
		var addr tcpip.FullAddress
		addr, protocol = fullAddrFrom(laddr)
		src = &addr
	}
	if raddr.IsValid() || raddr.Port() > 0 {
		var addr tcpip.FullAddress
		addr, protocol = fullAddrFrom(raddr)
		dst = &addr
	}

	return gonet.DialUDP(net.stack, src, dst, protocol)
}

func (net *wgtun) ListenUDPAddrPort(laddr netip.AddrPort) (*gonet.UDPConn, error) {
	return net.DialUDPAddrPort(laddr, netip.AddrPort{})
}

func (net *wgtun) DialUDP(laddr, raddr *net.UDPAddr) (*gonet.UDPConn, error) {
	var src, dst netip.AddrPort
	if laddr != nil {
		src = ipportFrom(laddr)
	}
	if raddr != nil {
		dst = ipportFrom(raddr)
	}

	return net.DialUDPAddrPort(src, dst)
}

func (net *wgtun) ListenUDP(laddr *net.UDPAddr) (*gonet.UDPConn, error) {
	return net.DialUDP(laddr, nil)
}

// --------------------------------------------------------------------
// icmp dialer
// --------------------------------------------------------------------

type PingConn struct {
	src      PingAddr
	dst      PingAddr
	wq       waiter.Queue
	ep       tcpip.Endpoint
	deadline *time.Timer
}

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

func (net *wgtun) DialPingAddr(laddr, raddr netip.Addr) (*PingConn, error) {
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

	pc := &PingConn{
		src:      PingAddr{laddr},
		deadline: time.NewTimer(time.Hour << 10),
	}
	pc.deadline.Stop()

	ep, tcpipErr := net.stack.NewEndpoint(tn, pn, &pc.wq)
	if tcpipErr != nil || ep == nil {
		return nil, fmt.Errorf("ping socket: endpoint: %s", tcpipErr)
	}
	pc.ep = ep

	if bind {
		fa, _ := fullAddrFrom(netip.AddrPortFrom(laddr, 0))
		if tcpipErr = pc.ep.Bind(fa); tcpipErr != nil {
			return nil, fmt.Errorf("ping bind: %s", tcpipErr)
		}
	}

	if raddr.IsValid() {
		pc.dst = PingAddr{raddr}
		fa, _ := fullAddrFrom(netip.AddrPortFrom(raddr, 0))
		if tcpipErr = pc.ep.Connect(fa); tcpipErr != nil {
			return nil, fmt.Errorf("ping connect: %s", tcpipErr)
		}
	}

	return pc, nil
}

func (net *wgtun) ListenPingAddr(laddr netip.Addr) (*PingConn, error) {
	return net.DialPingAddr(laddr, netip.Addr{})
}

func (net *wgtun) DialPing(laddr, raddr *PingAddr) (*PingConn, error) {
	var src, dst netip.Addr
	if laddr != nil {
		src = laddr.addr
	}
	if raddr != nil {
		dst = raddr.addr
	}
	return net.DialPingAddr(src, dst)
}

func (net *wgtun) ListenPing(laddr *PingAddr) (*PingConn, error) {
	var src netip.Addr
	if laddr != nil {
		src = laddr.addr
	}
	return net.ListenPingAddr(src)
}

func (pc *PingConn) LocalAddr() net.Addr {
	return pc.src
}

func (pc *PingConn) RemoteAddr() net.Addr {
	return pc.dst
}

func (pc *PingConn) Close() error {
	pc.deadline.Reset(0)
	ep := pc.ep
	if ep != nil {
		ep.Close()
	}
	return nil
}

func (pc *PingConn) SetWriteDeadline(t time.Time) error {
	return errors.New("not implemented")
}

func (pc *PingConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	var ip netip.Addr
	switch v := addr.(type) {
	case *PingAddr:
		ip = v.addr
	case *net.IPAddr:
		ip, _ = netip.AddrFromSlice(v.IP)
	default:
		return 0, fmt.Errorf("ping write: wrong net.Addr type")
	}
	if !((ip.Is4() && pc.src.addr.Is4()) || (ip.Is6() && pc.src.addr.Is6())) {
		return 0, fmt.Errorf("ping write: mismatched protocols")
	}

	buf := bytes.NewReader(p)
	remote, _ := fullAddrFrom(netip.AddrPortFrom(ip, 0))
	// won't block, no deadlines
	n64, tcpipErr := pc.ep.Write(buf, tcpip.WriteOptions{
		To: &remote,
	})
	if tcpipErr != nil {
		return int(n64), fmt.Errorf("ping write: %s", tcpipErr)
	}

	return int(n64), nil
}

func (pc *PingConn) Write(p []byte) (n int, err error) {
	return pc.WriteTo(p, &pc.dst)
}

func (pc *PingConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
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

func (pc *PingConn) Read(p []byte) (n int, err error) {
	n, _, err = pc.ReadFrom(p)
	return
}

func (pc *PingConn) SetDeadline(t time.Time) error {
	// pc.SetWriteDeadline is unimplemented

	return pc.SetReadDeadline(t)
}

func (pc *PingConn) SetReadDeadline(t time.Time) error {
	pc.deadline.Reset(time.Until(t))
	return nil
}
