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
	"net/netip"
	"strconv"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
)

var (
	anyaddr4        = netip.IPv4Unspecified()
	anyaddr6        = netip.IPv6Unspecified()
	alwaysDualStack = true
)

// Adapter to keep gomobile happy as it can't export net.Conn
type Conn = net.Conn

type PacketConn = net.PacketConn

type MinConn = core.MinConn

type Listener = net.Listener

type DialFn func(network, addr string) (net.Conn, error)

type RDialer interface {
	// Handle uniquely identifies the concrete type backing this dialer.
	// Useful as a phantom reference to this dialer.
	// github.com/hashicorp/terraform/blob/325d18262/internal/configs/configschema/decoder_spec.go#L32
	Handle() uintptr
	// Dial creates a connection to the given address,
	// the resulting net.Conn must be a *net.TCPConn if
	// network is "tcp" or "tcp4" or "tcp6" and must be
	// a *net.UDPConn if network is "udp" or "udp4" or "udp6".
	Dial(network, addr string) (Conn, error)
	// DialBind is like Dial but creates a connection to
	// the remote address bounded from the local port (not ip).
	// If local is invalid ip:port (ip must be present but not used),
	// it delegates to Dial(network, remote).
	DialBind(network, local, remote string) (Conn, error)
	// Announce announces the local address. network must be
	// packet-oriented ("udp" or "udp4" or "udp6").
	Announce(network, local string) (PacketConn, error)
	// Accept creates a listener on the local address. network
	// must be stream-oriented ("tcp" or "tcp4" or "tcp6").
	Accept(network, local string) (Listener, error)
	// Probe listens on the local address for ICMP packets sent
	// over UDP. Network must be "udp" or "udp4" or "udp6".
	Probe(network, local string) (PacketConn, error)
}

// RDial adapts dialers and listeners to RDialer.
// It always discards bind address.
type RDial struct {
	owner string // owner tag
	ctx   context.Context
	// local dialer
	dialer     *net.Dialer       // may be nil; used by exit, base, grounded
	listen     *net.ListenConfig // may be nil; used by exit, base, grounded
	listenICMP *icmplistener     // may be nil; used by exit, base, grounded
}

var _ RDialer = (*RDial)(nil)

var (
	errNoTCP     = errors.New("not a tcp dialer")
	errNoUDP     = errors.New("not a udp dialer")
	errNoUDPMux  = errors.New("not a udp announcer")
	errNoTCPMux  = errors.New("not a tcp announcer")
	errNoICMPL3  = errors.New("not an ip:icmp listener")
	errNoSysConn = errors.New("no syscall.Conn")
	errAnnounce  = errors.New("cannot announce network")
	errAccept    = errors.New("cannot accept network")
)

// Handle implements RDialer.
func (d *RDial) Handle() uintptr {
	return core.Loc(d)
}

func (d *RDial) context() context.Context {
	if d.ctx != nil {
		return d.ctx
	}
	return context.Background()
}

func (d *RDial) dial(network, addr string) (net.Conn, error) {
	return d.dialer.DialContext(d.context(), network, addr)
}

// Dial implements RDialer.
func (d *RDial) Dial(network, addr string) (net.Conn, error) {
	return d.dial(network, addr)
}

func (d *RDial) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, addr)
}

func (d *RDial) cloneDialer() *net.Dialer {
	var rd *net.Dialer = new(net.Dialer)
	// shallow copy: go.dev/play/p/tuadSFN3glj
	*rd = *d.dialer
	return rd
}

// DialBind implements RDialer.
func (d *RDial) DialBind(network, local, remote string) (net.Conn, error) {
	var onlyport netip.AddrPort
	rd := d.cloneDialer()

	if _, port, err := net.SplitHostPort(local); err == nil {
		// uport may be 0, which is "valid"
		uport, _ := strconv.Atoi(port) // should not error

		anyaddr := anyaddr6
		if !alwaysDualStack {
			anyaddr = anyaddr4
		}
		switch network {
		case "tcp4":
			anyaddr = anyaddr4
		case "tcp6":
			anyaddr = anyaddr6
		}
		if !alwaysDualStack {
			// ipp invalid when local is without ip; ex: ":port"
			if ipp, _ := netip.ParseAddrPort(local); ipp.Addr().Is4() {
				anyaddr = anyaddr4
			}
		}
		// ip addr binding is left upto dialer's Control
		// which is "namespace" aware (on Android)
		onlyport = netip.AddrPortFrom(anyaddr, uint16(uport))
	} else { // okay for local to be invalid; called by retrier.DialTCP
		log.VV("xdial: DialBind: (o: %s); %s %s=>%s; why: laddr nil",
			d.owner, network, local, remote)
	}

	switch network {
	case "tcp", "tcp4", "tcp6":
		if alwaysDualStack {
			network = "tcp"
		}
		if onlyport.IsValid() { // valid even when port is 0
			rd.LocalAddr = net.TCPAddrFromAddrPort(onlyport)
			log.V("xdial: DialBind: (o: %s); %s %s=>%s",
				d.owner, network, rd.LocalAddr, remote)
		}
	case "udp", "udp4", "udp6":
		if alwaysDualStack {
			network = "udp"
		}
		if onlyport.IsValid() { // valid even when port is 0
			rd.LocalAddr = net.UDPAddrFromAddrPort(onlyport)
			log.V("xdial: DialBind: (o: %s); %s %s=>%s",
				d.owner, network, rd.LocalAddr, remote)
		}
	default:
		log.W("xdial: DialBind: (o: %s); %s %s=>%s; err: unsupported network",
			d.owner, network, local, remote)
	}

	// equivalent to d.dial() if LocalAddr is not set
	return rd.Dial(network, remote)
}

// Accept implements RDialer interface.
func (d *RDial) Accept(network, local string) (net.Listener, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errAccept
	}
	return d.listen.Listen(d.context(), network, local)
}

// Announce implements RDialer.
func (d *RDial) Announce(network, local string) (net.PacketConn, error) {
	if network != "udp" && network != "udp4" && network != "udp6" {
		log.T("xdial: Announce: invalid network %s", network)
		return nil, errAnnounce
	}
	// todo: check if local is a local address or empty (any)
	// diailing (proxy.Dial/net.Dial/etc) on wildcard addresses (ex: ":8080" or "" or "localhost:1025")
	// is not equivalent to listening/announcing. see: github.com/golang/go/issues/22827
	if pc, err := d.listen.ListenPacket(d.context(), network, local); err == nil {
		switch x := pc.(type) {
		case *net.UDPConn:
			return x, nil
		default:
			log.T("xdial: Announce (o: %s): addr(%s) failed; %T is not net.UDPConn; other errs: %v", d.owner, local, x, err)
			clos(pc)
			return nil, errNoUDPMux
		}
	} else {
		return nil, err
	}
}

// Probe implements RDialer.
func (d *RDial) Probe(network, local string) (PacketConn, error) {
	if network == "udp" {
		ip, _ := netip.ParseAddrPort(local)
		ipok := ip.IsValid()
		if ipok && ip.Addr().Is4() {
			network = "udp4"
		} else if ipok && ip.Addr().Is6() {
			network = "udp6"
		}
	}
	if network != "udp4" && network != "udp6" {
		return nil, errAnnounce
	}
	// todo: check if local is a local address or empty (any)
	// drop port if present
	if ip, _, err := net.SplitHostPort(local); err == nil {
		local = ip
	}

	return d.listenICMP.listenICMP(network, local)
}

// DialTCP creates a net.TCPConn to raddr.
// Helper method for d.Dial("tcp", laddr.String(), raddr.String())
func (d *RDial) DialTCP(network string, laddr, raddr *net.TCPAddr) (*net.TCPConn, error) {
	if c, err := d.DialBind(network, laddr.String(), raddr.String()); err != nil {
		return nil, err
	} else if tc, ok := c.(*net.TCPConn); ok {
		return tc, nil
	} else {
		log.T("xdial: DialTCP: (%s) to %s => %s, %T is not %T (ok? %t); other errs: %v",
			d.owner, laddr, raddr, c, tc, ok, err)
		// some proxies like wgproxy, socks5 do not vend *net.TCPConn
		// also errors if retrier (core.DuplexConn) is looped back here
		clos(c)
		return nil, errNoTCP
	}
}

// DialUDP creates a net.UDPConn to raddr.
// Helper method for d.Dial("udp", laddr.String(), raddr.String())
func (d *RDial) DialUDP(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	if c, err := d.DialBind(network, laddr.String(), raddr.String()); err != nil {
		return nil, err
	} else if uc, ok := c.(*net.UDPConn); ok {
		return uc, nil
	} else {
		log.T("xdial: DialUDP: (%s) to %s => %s, %T is not %T (ok? %t); other errs: %v",
			d.owner, laddr, raddr, c, uc, ok, err)
		// some proxies like wgproxy, socks5 do not vend *net.UDPConn
		clos(c)
		return nil, errNoUDP
	}
}

// AnnounceUDP announces the local address. network must be "udp" or "udp4" or "udp6".
// Helper method for d.Announce("udp", local)
func (d *RDial) AnnounceUDP(network, local string) (*net.UDPConn, error) {
	if c, err := d.Announce(network, local); err != nil {
		return nil, err
	} else if uc, ok := c.(*net.UDPConn); ok {
		return uc, nil
	} else {
		log.T("xdial: AnnounceUDP: (%s) from %s, %T is not %T (ok? %t); other errs: %v",
			d.owner, local, c, uc, ok, err)
		clos(c)
		return nil, errNoUDPMux
	}
}

// AcceptTCP creates a listener on the local address. network must be "tcp" or "tcp4" or "tcp6".
// Helper method for d.Accept("tcp", local)
func (d *RDial) AcceptTCP(network string, local string) (*net.TCPListener, error) {
	if ln, err := d.Accept(network, local); err != nil {
		return nil, err
	} else if tl, ok := ln.(*net.TCPListener); ok {
		return tl, nil
	} else {
		log.T("xdial: AcceptTCP: (%s) from %s, %T is not %T (ok? %t); other errs: %v",
			d.owner, local, ln, tl, ok, err)
		clos(ln)
		return nil, errNoTCPMux
	}
}

// ProbeICMP listens on the local address for ICMP packets sent over UDP.
// network must be "udp" or "udp4" or "udp6". Helper method for d.Probe("udp", local)
func (d *RDial) ProbeICMP(network, local string) (net.PacketConn, error) {
	return d.Probe(network, local)
}

func clos(c io.Closer) {
	core.Close(c)
}
