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

// intra/tcp expects dst conns to confirm to core.TCPConn
var _ core.TCPConn = (*gonet.TCPConn)(nil)

// intra/udp expects dst conns to confirm to core.UDPConn
var _ core.UDPConn = (*gonet.UDPConn)(nil)

// --------------------------------------------------------------------
// dns dialer
// --------------------------------------------------------------------

func (tnet *wgtun) LookupContextHost(ctx context.Context, host string) ([]netip.Addr, error) {
	if len(host) <= 0 || (!tnet.hasV6.Load() && !tnet.hasV4.Load()) {
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

	// dialers.Resolve returns from cache (which may be stale)
	if ips, err := dialers.Resolve(host, tnet.ID().V()); len(ips) <= 0 {
		if err == nil {
			err = errNoSuchHost
		}
		log.D("wg: %s dial: lookup failed %q: no ips; err: %v", tnet.id, host, err)
		return nil, &net.DNSError{Err: err.Error(), Name: host, IsNotFound: true}
	} else {
		return ips, nil
	}
}

// --------------------------------------------------------------------
// generic dialer
// --------------------------------------------------------------------

func (tnet *wgtun) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return tnet.dial(ctx, network, "", address)
}

func (tnet *wgtun) dial(ctx context.Context, network, local, remote string) (net.Conn, error) {
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
		log.W("wg: %s dial: unknown network %q for %s => %s", tnet.id, network, local, remote)
		return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError(network)}
	}

	var host string
	var port int
	if network == "ping" || network == "ping4" || network == "ping6" {
		host = remote
	} else {
		var sport string
		var err error
		host, sport, err = net.SplitHostPort(remote)
		if err != nil {
			log.W("wg: %s dial: invalid address %q: %v", tnet.id, remote, err)
			return nil, &net.OpError{Op: "dial", Err: err}
		}
		port, err = strconv.Atoi(sport)
		if err != nil || port < 0 || port > 65535 {
			log.W("wg: %s dial: invalid port %q: %v", tnet.id, sport, err)
			return nil, &net.OpError{Op: "dial", Err: errNumericPort}
		}
	}

	// allAddrs may be nil but shouldn't be when reserr is not nil
	allAddrs, reserr := tnet.LookupContextHost(ctx, host)
	if reserr != nil {
		log.W("wg: %s dial: lookup failed %q: %v", tnet.id, host, reserr)
		return nil, &net.OpError{Op: "dial", Err: reserr}
	}

	var addrs []netip.AddrPort
	for _, ip := range allAddrs {
		if (ip.Is4() && acceptV4) || (ip.Is6() && acceptV6) {
			addrs = append(addrs, netip.AddrPortFrom(ip, uint16(port)))
		}
	}
	if len(addrs) == 0 && len(allAddrs) != 0 {
		log.W("wg: %s dial: no suitable address for %q / %v", tnet.id, host, allAddrs)
		return nil, &net.OpError{Op: "dial", Err: errNoSuitableAddress}
	}

	var laddr4, laddr6 netip.AddrPort
	if _, port, err := net.SplitHostPort(local); err == nil {
		portno, _ := strconv.Atoi(port)
		laddr4 = netip.AddrPortFrom(anyaddr4, uint16(portno))
		laddr6 = netip.AddrPortFrom(anyaddr6, uint16(portno))
	}

	var errs error
	for i, raddr := range addrs {
		laddr := laddr6 // laddr6 may be invalid
		if raddr.Addr().Is4() {
			laddr = laddr4 // laddr4 may be invalid
		}
		var c net.Conn
		var err error
		switch network {
		case "tcp", "tcp4", "tcp6":
			c, err = tnet.DialTCPAddrPort(ctx, laddr, raddr)
		case "udp", "udp4", "udp6":
			c, err = tnet.DialUDPAddrPort(laddr, raddr)
		case "ping", "ping4", "ping6":
			c, err = tnet.DialPing(laddr, raddr)
		}
		log.I("wg: %s dial: %s: #%d %s => %s", tnet.id, network, i, laddr, raddr)
		if err == nil {
			dialers.Confirm(host, raddr.Addr())
			return c, nil
		}
		dialers.Disconfirm(host, raddr.Addr())
		errs = core.JoinErr(errs, err)
	}
	errs = core.OneErr(errs, errMissingAddress)
	log.W("wg: %s dial: %s: %s failed: %v", tnet.id, network, addrs, errs)
	return nil, errs
}

// --------------------------------------------------------------------
// tcp and udp dialers
// --------------------------------------------------------------------

func fullAddrFrom(by string, ipp netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber, bool) {
	var protoNumber tcpip.NetworkProtocolNumber
	var nsdaddr tcpip.Address
	if !ipp.IsValid() {
		// TODO: use unspecified address like in PingConn?
		return tcpip.FullAddress{}, 0, false
	}
	if ipp.Addr().Is4() {
		protoNumber = ipv4.ProtocolNumber
		nsdaddr = tcpip.AddrFrom4(ipp.Addr().As4())
	} else {
		protoNumber = ipv6.ProtocolNumber
		nsdaddr = tcpip.AddrFrom16(ipp.Addr().As16())
	}
	log.VV("wg: dial: %s translate ipp: %v => %v", by, ipp, nsdaddr)
	return tcpip.FullAddress{
		NIC:  wgnic,
		Addr: nsdaddr,
		Port: ipp.Port(), // may be 0
	}, protoNumber, true
}

func (tnet *wgtun) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (*gonet.TCPConn, error) {
	if faddr, protocol, ok := fullAddrFrom("tcp", addr); ok {
		return gonet.DialContextTCP(ctx, tnet.stack, faddr, protocol)
	}
	log.W("wg: %s: tcp: dial: invalid addr %s", tnet.id, addr)
	return nil, errInvalidAddr
}

func (tnet *wgtun) DialTCPAddrPort(ctx context.Context, laddr, raddr netip.AddrPort) (*gonet.TCPConn, error) {
	remote, protocol, _ := fullAddrFrom("tcp:remote", raddr) // prefer "proto" from remote
	local, _, _ := fullAddrFrom("tcp:local", laddr)
	// return gonet.DialTCP(tnet.stack, remote, protocol)
	return gonet.DialTCPWithBind(
		ctx,
		tnet.stack,
		local,  // may be zero value
		remote, // should not be zero value
		protocol,
	)
}

func (tnet *wgtun) ListenTCPAddrPort(addr netip.AddrPort) (*gonet.TCPListener, error) {
	if fa, pn, ok := fullAddrFrom("tcp:listen", addr); ok {
		return gonet.ListenTCP(tnet.stack, fa, pn)
	}
	log.W("wg: %s: tcp: listen: invalid addr %s", tnet.id, addr)
	return nil, errInvalidAddr
}

func (tnet *wgtun) DialUDPAddrPort(laddr, raddr netip.AddrPort) (*gonet.UDPConn, error) {
	var src, dst *tcpip.FullAddress
	var protocol tcpip.NetworkProtocolNumber

	if srcaddr, srcprotocol, ok := fullAddrFrom("udp:local", laddr); ok {
		protocol = srcprotocol
		if !srcaddr.Addr.Unspecified() {
			src = &srcaddr
		} // else: unbound; src must be left nil
	} // else: laddr not valid
	if dstaddr, dstprotocol, ok := fullAddrFrom("udp:remote", raddr); ok {
		protocol = dstprotocol
		if !dstaddr.Addr.Unspecified() {
			dst = &dstaddr
		} // else: unconnected; dst must be left nil
	} // else: raddr not valid

	// iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
	if protocol == 0 { // gonet.DialUDP panics on unsupported protos
		log.W("wg: %s: udp: dial: zero proto; %s => %s", tnet.id, laddr, raddr)
		return nil, errInvalidAddr
	}

	// if src is non-nil, addrs are acquired on wgnic;
	// ep.Bind => ep.BindAndThen => ep.net.BindAndThen => ep.checkV4Mapped
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

func (tnet *wgtun) DialPing(local, remote netip.AddrPort) (*netstack.GICMPConn, error) {
	return netstack.DialPingAddr(tnet.stack, wgnic, local.Addr(), remote.Addr())
}
