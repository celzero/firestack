// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dialers

import (
	"crypto/tls"
	"net"
	"net/netip"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/protect"
	"golang.org/x/net/proxy"
)

// rdials is a union type for protect.RDial, net.Dialer, tls.Dialer
type rdials interface {
	*protect.RDial | *protect.RDialer | *tls.Dialer | *proxy.Dialer
}

// rconns is a union type for net.UDPConn, net.TCPConn, icmp.PacketConn, net.TCPListener
type rconns interface {
	*net.Conn | *net.PacketConn | *net.UDPConn | *net.TCPConn | *net.TCPListener
}

type dialFn[D rdials, C rconns] func(dialer D, network string, local, remote netip.AddrPort) (C, error)
type connFn[D rdials] func(dialer D, network string, local, remote netip.AddrPort) (net.Conn, error)

// adaptRDial adapts a connectFn[protect.RDial] to a dialFn
func adaptRDial[D *protect.RDial, C *net.Conn](f connFn[D]) dialFn[D, C] {
	return func(d D, network string, laddr, raddr netip.AddrPort) (cc C, err error) {
		c, err := f(d, network, laddr, raddr)
		if err != nil {
			clos(c)
			return nil, err
		}
		if c == nil || core.IsNil(c) { // go.dev/play/p/SsmqM00d2oH
			return nil, errNilConn
		}
		return &c, nil
	}
}

// adaptRDialer adapts a connectFn[protect.RDialer] to a dialFn
func adaptRDialer[D *protect.RDialer, C *net.Conn](f connFn[D]) dialFn[D, C] {
	return func(d D, network string, laddr, raddr netip.AddrPort) (cc C, err error) {
		c, err := f(d, network, laddr, raddr)
		if err != nil {
			clos(c)
			return nil, err
		}
		if c == nil || core.IsNil(c) {
			return nil, errNilConn
		}
		return &c, nil
	}
}

// adaptTlsDial adapts a connectFn[tls.Dialer] to a dialFn
func adaptTlsDial[D *tls.Dialer, C *net.Conn](f connFn[D]) dialFn[D, C] {
	return func(d D, network string, laddr, raddr netip.AddrPort) (cc C, err error) {
		c, err := f(d, network, laddr, raddr)
		if err != nil {
			clos(c)
			return nil, err
		}
		if c == nil || core.IsNil(c) {
			return nil, errNilConn
		}
		return &c, nil
	}
}

func adaptProxyDial[D *proxy.Dialer, C *net.Conn](f connFn[D]) dialFn[D, C] {
	return func(d D, network string, laddr, raddr netip.AddrPort) (cc C, err error) {
		c, err := f(d, network, laddr, raddr)
		if err != nil {
			clos(c)
			return nil, err
		}
		if c == nil || core.IsNil(c) { // go.dev/play/p/SsmqM00d2oH
			return nil, errNilConn
		}
		return &c, nil
	}
}

func unPtr[P any, Q any](p *P, q Q) (P, Q) {
	// go.dev/play/p/XRrCepATeIi
	if p == nil || core.IsNil(p) {
		var zz P
		return zz, q
	}
	return *p, q
}
