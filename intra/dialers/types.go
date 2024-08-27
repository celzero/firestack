// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dialers

import (
	"net"
	"net/netip"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/protect"
)

// rconn is a union type for net.UDPConn, net.TCPConn, icmp.PacketConn, net.TCPListener
type rconn interface {
	*net.Conn | *net.PacketConn | *net.UDPConn | *net.TCPConn | *net.TCPListener
}

type mkrconn[C rconn] func(*protect.RDial, string, netip.Addr, int) (C, error)
type mkconn func(*protect.RDial, string, netip.Addr, int) (net.Conn, error)

// adaptc adapts a mkconn to a mkrconn
func adaptc(f mkconn) mkrconn[*net.Conn] {
	return func(d *protect.RDial, network string, ip netip.Addr, port int) (cc *net.Conn, err error) {
		c, err := f(d, network, ip, port)
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
