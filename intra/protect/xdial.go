// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package protect

import (
	"errors"
	"io"
	"net"

	"github.com/celzero/firestack/intra/log"
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
	Owner   string       // owner tag
	Dialer  proxy.Dialer // may be nil
	RDialer RDialer      // may be nil
}

func (d *RDial) dial(network, addr string) (Conn, error) {
	usedialer := d.Dialer != nil
	userdialer := d.RDialer != nil
	if usedialer {
		return d.Dialer.Dial(network, addr)
	}
	if userdialer {
		return d.RDialer.Dial(network, addr)
	}
	log.V("xdial: Dial: (r? %t / o: %s) %s %s", userdialer, d.Owner, network, addr)
	return nil, errNoConn
}

func (d *RDial) Dial(network, addr string) (net.Conn, error) {
	if c, err := d.dial(network, addr); err != nil {
		return nil, err
	} else if cc, ok := c.(net.Conn); ok {
		return cc, nil
	} else {
		log.W("xdial: Dial: (%s) %T is not %T (ok? %t); other errs: %v", d.Owner, c, cc, ok, err)
		clos(c)
		return nil, errNoConn
	}
}

func clos(c io.Closer) {
	if c != nil {
		c.Close()
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
		log.W("xdial: DialTCP: (%s) %T is not %T (ok? %t); other errs: %v", d.Owner, c, tc, ok, err)
		// some proxies like wgproxy, socks5 do not vend *net.TCPConn
		clos(c)
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
		log.W("xdial: DialUDP: (%s) %T is not %T (ok? %t); other errs: %v", d.Owner, c, uc, ok, err)
		// some proxies like wgproxy, socks5 do not vend *net.UDPConn
		clos(c)
		return nil, errNoUDP
	}
}
