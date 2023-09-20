// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package protect

import (
	"net"

	"golang.org/x/net/proxy"
)

// Adapter to keep gomobile happy as it can't export net.Conn
type Conn interface {
	// Read reads data coming from remote.
	Read(data []byte) (int, error)

	// Write writes data to remote.
	Write(data []byte) (int, error)

	// Close closes the connection.
	Close() error
}

// XDial confirms to x.Dialer interface but discards local-addresses
type XDial struct {
	proxy.Dialer
}

func (d *XDial) Dial(network, addr string) (net.Conn, error) {
	return d.Dialer.Dial(network, addr)
}

func (d *XDial) DialTCP(network string, laddr, raddr *net.TCPAddr) (*net.TCPConn, error) {
	// grab a mutex if mutating LocalAddr
	// d.Dialer.LocalAddr = laddr
	if c, err := d.Dialer.Dial(network, raddr.String()); err != nil {
		return nil, err
	} else if tc, ok := c.(*net.TCPConn); ok {
		// d.Dialer.LocalAddr = nil
		return tc, nil
	} else {
		if tc != nil {
			tc.Close()
		}
		return nil, net.ErrWriteToConnected
	}
}

func (d *XDial) DialUDP(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	// grab a mutex if mutating LocalAddr
	// d.Dialer.LocalAddr = laddr
	if c, err := d.Dialer.Dial(network, raddr.String()); err != nil {
		return nil, err
	} else if uc, ok := c.(*net.UDPConn); ok {
		// d.Dialer.LocalAddr = nil
		return uc, nil
	} else {
		if uc != nil {
			uc.Close()
		}
		return nil, net.ErrWriteToConnected
	}
}
