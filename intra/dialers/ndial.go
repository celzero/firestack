// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dialers

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect/ipmap"
)

type netConnectFunc func(*net.Dialer, string, netip.Addr, int) (net.Conn, error)

var errNotUDPConn = errors.New("listener: not a UDPConn")

func netConnect(d *net.Dialer, proto string, ip netip.Addr, port int) (net.Conn, error) {
	if d == nil {
		log.E("ndial: netConnect: nil dialer")
		return nil, errNoDialer
	} else if !ipok(ip) {
		log.E("ndial: netConnect: invalid ip", ip)
		return nil, errNoIps
	}
	return d.Dial(proto, addrstr(ip, port))
}

func netdial(d *net.Dialer, network, addr string, connect netConnectFunc) (net.Conn, error) {
	start := time.Now()

	log.D("ndial: dialing %s", addr)
	domain, portstr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	// cannot dial into a wildcard address
	// while, listen is unsupported
	if len(domain) == 0 {
		return nil, net.InvalidAddrError(addr)
	}
	port, err := strconv.Atoi(portstr)
	if err != nil {
		return nil, err
	}

	var errs error
	ips := ipm.Get(domain)
	dontretry := ips.OneIPOnly() // just one IP, no retries possible
	confirmed := ips.Confirmed()
	confirmedIPOK := ipok(confirmed)

	defer func() {
		dur := time.Since(start)
		log.D("ndial: duration: %s; failed %s; confirmed? %s, sz: %d", dur, addr, confirmed, ips.Size())
	}()

	if confirmedIPOK {
		log.V("ndial: dialing confirmed ip %s for %s", confirmed, addr)
		conn, cerr := connect(d, network, confirmed, port)
		if conn == nil && err == nil {
			err = errNoConn
		}
		if cerr == nil {
			log.V("ndial: confirmed ip working %s for %s", confirmed, addr)
			return conn, nil
		} else {
			errs = errors.Join(errs, cerr)
			ips.Disconfirm(confirmed)
			log.W("ndial: confirmed ip %s for %s failed with err %v", confirmed, addr, cerr)
		}
	}

	if dontretry { // no retries possible
		if !confirmedIPOK {
			log.E("ndial: ip %s not ok for %s", confirmed, addr)
			errs = errors.Join(errs, errNoIps)
		}
		return nil, errs
	}

	ipset := ips.Addrs()
	allips, failingopen := maybeFilter(ipset, confirmed)
	if len(allips) <= 0 || failingopen {
		var ok bool
		if ips, ok = renew(domain, ips); ok {
			ipset = ips.Addrs()
			allips, failingopen = maybeFilter(ipset, confirmed)
		}
		log.D("ndial: renew ips for %s; ok? %t; failingopen? %t", addr, ok, failingopen)
	}
	log.D("ndial: trying all ips %d %v for %s, failingopen? %t",
		len(allips), allips, addr, failingopen)
	for _, ip := range allips {
		end := time.Since(start)
		if end > dialRetryTimeout {
			log.D("ndial: timeout %s for %s", end, addr)
			break
		}
		if ipok(ip) {
			log.V("ndial: dialing ip %s for %s", ip, addr)
			conn, err := connect(d, network, ip, port)
			if conn == nil && err == nil {
				err = errNoConn
			}
			if err == nil {
				confirm(ips, ip)
				log.I("ndial: confirming working ip %s for %s", ip, addr)
				return conn, nil
			} else {
				errs = errors.Join(errs, err)
				log.W("ndial: ip %s for %s failed with err %v", ip, addr, err)
			}
		} else {
			log.D("ndial: ip %s not ok for %s", ip, addr)
		}
	}

	if len(ipset) <= 0 {
		errs = errNoIps
	}

	return nil, errs
}

// NetDial connects to the address on the named network using net.Dialer.
func NetDial(d *net.Dialer, network, addr string) (net.Conn, error) {
	return netdial(d, network, addr, netConnect)
}

// NetListenPacket listens for UDP on local address using cfg.
// Returned net.Conn is guaranteed to be a *net.UDPConn.
func NetListenPacket(cfg *net.ListenConfig, network, local string) (net.PacketConn, error) {
	if cfg == nil {
		log.E("ndial: NetListenPacket: nil listen config")
		return nil, errNoListener
	}
	if c, err := cfg.ListenPacket(context.Background(), network, local); err == nil {
		if conn, ok := c.(*net.UDPConn); ok {
			return conn, nil
		} else {
			log.W("ndial: NetListenPacket: p(%s) %T not a net.UDPConn; src: %s", network, c, local)
			clos(conn)
			return nil, errNotUDPConn
		}
	} else {
		return nil, err
	}
}

// NetListen listens for TCP on local address using cfg.
func NetListen(cfg *net.ListenConfig, network, local string) (net.Listener, error) {
	if cfg == nil {
		log.E("ndial: NetListen: nil listen config")
		return nil, errNoListener
	}
	return cfg.Listen(context.Background(), network, local)
}

func clos(c ...core.MinConn) {
	core.CloseConn(c...)
}

func confirm(ips *ipmap.IPSet, ip netip.Addr) {
	if ips != nil && ipok(ip) {
		ips.Confirm(ip)
	}
}
