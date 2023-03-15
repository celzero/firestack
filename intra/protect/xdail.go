// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package protect

import (
	"net"
)

// XDial confirms to x.Dialer interface but discards local-addresses
type XDial struct {
	*net.Dialer
}

func (d *XDial) Dial(network, addr string) (net.Conn, error) {
	return d.Dialer.Dial(network, addr)
}

func (d *XDial) DialTCP(network string, laddr, raddr *net.TCPAddr) (*net.TCPConn, error) {
	// grab a mutex if mutating LocalAddr
	// d.Dialer.LocalAddr = laddr
	c, err := d.Dialer.Dial(network, raddr.String())
	// d.Dialer.LocalAddr = nil
	return c.(*net.TCPConn), err
}

func (d *XDial) DialUDP(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	// grab a mutex if mutating LocalAddr
	// d.Dialer.LocalAddr = laddr
	c, err := d.Dialer.Dial(network, raddr.String())
	// d.Dialer.LocalAddr = nil
	return c.(*net.UDPConn), err
}
