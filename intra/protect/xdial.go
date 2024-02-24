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

type RDialer interface {
	// Dial creates a connection to the given address,
	// the resulting net.Conn must be a *net.TCPConn if
	// network is "tcp" or "tcp4" or "tcp6" and must be
	// a *net.UDPConn if network is "udp" or "udp4" or "udp6".
	Dial(network, addr string) (Conn, error)
	// Announce announces the local address. network must be
	// packet-oriented ("udp" or "udp4" or "udp6") conn.
	// (the returned conn is actually a protect.PacketConn;
	// protect.Conn is used in signature to make gobind happy
	// as it does not support exporting interfaces with fns
	// that return more than 2 values, like ReadFrom does).
	Announce(network, local string) (PacketConn, error)
}

// RDial discards local-addresses
type RDial struct {
	Owner    string            // owner tag
	Dialer   proxy.Dialer      // may be nil
	Listener *net.ListenConfig // may be nil
	RDialer  RDialer           // may be nil
}

var (
	errNoConn    = errors.New("not a dialer")
	errNoTCP     = errors.New("not a tcp dialer")
	errNoUDP     = errors.New("not a udp dialer")
	errNoConnMux = errors.New("not an announcer")
	errNoUDPMux  = errors.New("not a udp announcer")
	errAnnounce  = errors.New("cannot announce network")
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
	return nil, errNoConn
}

func (d *RDial) Dial(network, addr string) (net.Conn, error) {
	if cc, err := d.dial(network, addr); err != nil {
		return nil, err
	} else {
		clos(cc)
		return nil, errNoConn
	}
}

func (d *RDial) Announce(network, local string) (PacketConn, error) {
	if network != "udp" && network != "udp4" && network != "udp6" {
		return nil, errAnnounce
	}
	// todo: check if local is a local address or empty (any)
	// diailing (proxy.Dial/net.Dial/etc) on wildcard addresses (ex: ":8080" or "" or "localhost:1025")
	// is not equivalent to listening/announcing. see: github.com/golang/go/issues/22827
	uselistener := d.Listener != nil
	userdialer := d.RDialer != nil
	if uselistener {
		if pc, err := d.Listener.ListenPacket(context.Background(), network, local); err == nil {
			switch x := pc.(type) {
			case *net.UDPConn:
				return x, err
			default:
				log.W("xdial: Announce: addr(%s) for owner(%s): failed; %T is not net.UDPConn; other errs: %v", local, d.Owner, x, err)
				clos(pc)
				return nil, errNoUDPMux
			}
		} else {
			return nil, err
		}
	}
	if userdialer {
		return d.RDialer.Announce(network, local)
	}
	log.V("xdial: Announce: (r? %t / o: %s) %s %s", userdialer, d.Owner, network, local)
	return nil, errNoConnMux
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
