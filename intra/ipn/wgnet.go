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
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
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

// intra/tcp expects dst conns to confirm to core.TCPConn
var _ core.TCPConn = (*gonet.TCPConn)(nil)

// intra/udp expects dst conns to confirm to core.UDPConn
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

	rv, _ := tnet.ba.Do(host, resolve(tnet, host))
	if rv.Err != nil {
		log.W("wg: dial: lookup failed %q: %v", host, rv.Err)
		return nil, &net.OpError{Op: "dial", Err: rv.Err}
	}

	allAddrs := rv.Val // may be nil but shouldn't be if rv.Err is nil
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
			c, err = tnet.DialPing(netip.Addr{}, addr.Addr())
		}
		log.I("wg: dial: %s: #%d %v", network, i, addr)
		if err == nil {
			dialers.Confirm(host, addr.Addr())
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

// addrok return true if the address is valid and not unspecified.
func addrok(ipp netip.AddrPort) bool {
	return ipp.IsValid() && !ipp.Addr().IsUnspecified() && ipp.Port() > 0
}

func fullAddrFrom(ipp netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
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
		NIC:  wgnic,
		Addr: nsdaddr,
		Port: ipp.Port(), // may be 0
	}, protoNumber
}

func (tnet *wgtun) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (*gonet.TCPConn, error) {
	faddr, protocol := fullAddrFrom(addr)
	return gonet.DialContextTCP(ctx, tnet.stack, faddr, protocol)
}

func (tnet *wgtun) DialTCPAddrPort(addr netip.AddrPort) (*gonet.TCPConn, error) {
	faddr, protocol := fullAddrFrom(addr)
	return gonet.DialTCP(tnet.stack, faddr, protocol)
}

func (tnet *wgtun) ListenTCPAddrPort(addr netip.AddrPort) (*gonet.TCPListener, error) {
	fa, pn := fullAddrFrom(addr)
	return gonet.ListenTCP(tnet.stack, fa, pn)
}

func (tnet *wgtun) DialUDPAddrPort(laddr, raddr netip.AddrPort) (*gonet.UDPConn, error) {
	var src, dst *tcpip.FullAddress
	var protocol tcpip.NetworkProtocolNumber
	if addrok(laddr) {
		var addr tcpip.FullAddress
		addr, protocol = fullAddrFrom(laddr)
		src = &addr
	} // else: unbound; src must be left nil
	if addrok(raddr) {
		var addr tcpip.FullAddress
		addr, protocol = fullAddrFrom(raddr)
		dst = &addr
	} // else: unconnected; dst must be left nil

	// if src is non-nil, addrs are acquired on wgnic;
	// ep.Bind -> ep.BindAndThen -> ep.net.BindAndThen -> ep.checkV4Mapped
	// github.com/google/gvisor/blob/932d9dc6/pkg/tcpip/stack/addressable_endpoint_state.go#L644
	return gonet.DialUDP(tnet.stack, src, dst, protocol)
}

func (tnet *wgtun) ListenUDPAddrPort(laddr netip.AddrPort) (*gonet.UDPConn, error) {
	return tnet.DialUDPAddrPort(laddr, netip.AddrPort{})
}

func (tnet *wgtun) DialUDP(laddr, raddr *net.UDPAddr) (*gonet.UDPConn, error) {
	var src, dst netip.AddrPort
	if laddr != nil {
		src = laddr.AddrPort()
	}
	if raddr != nil {
		dst = raddr.AddrPort()
	}

	return tnet.DialUDPAddrPort(src, dst)
}

func (tnet *wgtun) ListenUDP(laddr *net.UDPAddr) (*gonet.UDPConn, error) {
	return tnet.DialUDP(laddr, nil)
}

func (tnet *wgtun) ListenPing(laddr netip.Addr) (*netstack.GICMPConn, error) {
	return netstack.DialPingAddr(tnet.stack, wgnic, laddr, netip.Addr{})
}

func (tnet *wgtun) DialPing(laddr, raddr netip.Addr) (*netstack.GICMPConn, error) {
	return netstack.DialPingAddr(tnet.stack, wgnic, laddr, raddr)
}
