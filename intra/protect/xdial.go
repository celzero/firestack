// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package protect

import (
	"errors"
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

type RDialer interface {
	// Dial creates a connection to the given address,
	// the resulting net.Conn must be a *net.TCPConn if
	// network is "tcp" or "tcp4" or "tcp6" and must be
	// a *net.UDPConn if network is "udp" or "udp4" or "udp6".
	Dial(network string, addr string) (Conn, error)
}

var errNoConn = errors.New("not a dialer")
var errNoTCP = errors.New("not a tcp dialer")
var errNoUDP = errors.New("not a udp dialer")

// RDial discards local-addresses
type RDial struct {
	Dialer  proxy.Dialer
	RDialer RDialer
}

func (d *RDial) dial(network, addr string) (Conn, error) {
	if d.Dialer != nil {
		return d.Dialer.Dial(network, addr)
	}
	if d.RDialer != nil {
		return d.RDialer.Dial(network, addr)
	}
	return nil, errNoConn
}

func (d *RDial) Dial(network, addr string) (net.Conn, error) {
	if c, err := d.dial(network, addr); err != nil {
		return nil, err
	} else if cc, ok := c.(net.Conn); ok {
		return cc, nil
	} else {
		if c != nil {
			c.Close()
		}
		return nil, errNoConn
	}
}

func (d *RDial) DialTCP(network string, laddr, raddr *net.TCPAddr) (*net.TCPConn, error) {
	// grab a mutex if mutating LocalAddr
	// d.Dialer.LocalAddr = laddr
	if c, err := d.Dial(network, raddr.String()); err != nil {
		return nil, err
	} else if tc, ok := c.(*net.TCPConn); ok {
		// d.Dialer.LocalAddr = nil
		return tc, nil
	} else {
		if tc != nil {
			tc.Close()
		}
		return nil, errNoTCP
	}
}

func (d *RDial) DialUDP(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	// grab a mutex if mutating LocalAddr
	// d.Dialer.LocalAddr = laddr
	if c, err := d.Dial(network, raddr.String()); err != nil {
		return nil, err
	} else if uc, ok := c.(*net.UDPConn); ok {
		// d.Dialer.LocalAddr = nil
		return uc, nil
	} else {
		if uc != nil {
			uc.Close()
		}
		return nil, errNoUDP
	}
}
