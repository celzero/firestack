// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package protect

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/celzero/firestack/intra/log"
	"golang.org/x/net/proxy"
)

// Adapter to keep gomobile happy as it can't export net.Conn
type Conn = net.Conn

type PacketConn = net.PacketConn

type Listener = net.Listener

type RDialer interface {
	// Dial creates a connection to the given address,
	// the resulting net.Conn must be a *net.TCPConn if
	// network is "tcp" or "tcp4" or "tcp6" and must be
	// a *net.UDPConn if network is "udp" or "udp4" or "udp6".
	Dial(network, addr string) (Conn, error)
	// Announce announces the local address. network must be
	// packet-oriented ("udp" or "udp4" or "udp6").
	Announce(network, local string) (PacketConn, error)
	// Accept creates a listener on the local address. network
	// must be stream-oriented ("tcp" or "tcp4" or "tcp6").
	Accept(network, local string) (Listener, error)
}

// RDial discards local-addresses
type RDial struct {
	Owner   string            // owner tag
	Dialer  proxy.Dialer      // may be nil
	Listen  *net.ListenConfig // may be nil
	RDialer RDialer           // may be nil
}

var (
	errNoDialer    = errors.New("not a dialer")
	errNoTCP       = errors.New("not a tcp dialer")
	errNoUDP       = errors.New("not a udp dialer")
	errNoAnnouncer = errors.New("not an announcer")
	errNoAcceptor  = errors.New("not an acceptor")
	errNoUDPMux    = errors.New("not a udp announcer")
	errNoTCPMux    = errors.New("not a tcp announcer")
	errAnnounce    = errors.New("cannot announce network")
	errAccept      = errors.New("cannot accept network")
)

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
	return nil, errNoDialer
}

func (d *RDial) Dial(network, addr string) (net.Conn, error) {
	if cc, err := d.dial(network, addr); err != nil {
		return nil, err
	} else {
		return cc, nil
	}
}

func (d *RDial) Accept(network, local string) (Listener, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errAccept
	}
	uselistener := d.Listen != nil
	userdialer := d.RDialer != nil
	if !uselistener && !userdialer {
		log.V("xdial: Accept: (r? %t / o: %s) %s %s", userdialer, d.Owner, network, local)
		return nil, errNoAcceptor
	}
	if uselistener {
		if ln, err := d.Listen.Listen(context.Background(), network, local); err == nil {
			return ln, nil
		} else {
			return nil, err
		}
	}
	return d.RDialer.Accept(network, local)
}

func (d *RDial) Announce(network, local string) (PacketConn, error) {
	if network != "udp" && network != "udp4" && network != "udp6" {
		return nil, errAnnounce
	}
	// todo: check if local is a local address or empty (any)
	// diailing (proxy.Dial/net.Dial/etc) on wildcard addresses (ex: ":8080" or "" or "localhost:1025")
	// is not equivalent to listening/announcing. see: github.com/golang/go/issues/22827
	uselistener := d.Listen != nil
	userdialer := d.RDialer != nil
	if !uselistener && !userdialer {
		log.V("xdial: Announce: (r? %t / o: %s) %s %s", userdialer, d.Owner, network, local)
		return nil, errNoAnnouncer
	}
	if uselistener {
		if pc, err := d.Listen.ListenPacket(context.Background(), network, local); err == nil {
			switch x := pc.(type) {
			case *net.UDPConn:
				return x, nil
			default:
				log.W("xdial: Announce: addr(%s) for owner(%s): failed; %T is not net.UDPConn; other errs: %v", local, d.Owner, x, err)
				clos(pc)
				return nil, errNoUDPMux
			}
		} else {
			return nil, err
		}
	}
	return d.RDialer.Announce(network, local)
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

// AnnounceUDP announces the local address. network must be "udp" or "udp4" or "udp6".
func (d *RDial) AnnounceUDP(network, local string) (*net.UDPConn, error) {
	if c, err := d.Announce(network, local); err != nil {
		return nil, err
	} else if uc, ok := c.(*net.UDPConn); ok {
		return uc, nil
	} else {
		log.W("xdial: AnnounceUDP: (%s) %T is not %T (ok? %t); other errs: %v", d.Owner, c, uc, ok, err)
		clos(c)
		return nil, errNoUDPMux
	}
}

// AcceptTCP creates a listener on the local address. network must be "tcp" or "tcp4" or "tcp6".
func (d *RDial) AcceptTCP(network string, local string) (*net.TCPListener, error) {
	if ln, err := d.Accept(network, local); err != nil {
		return nil, err
	} else if tl, ok := ln.(*net.TCPListener); ok {
		return tl, nil
	} else {
		log.W("xdial: AcceptTCP: (%s) %T is not %T (ok? %t); other errs: %v", d.Owner, ln, tl, ok, err)
		clos(ln)
		return nil, errNoTCPMux
	}
}
