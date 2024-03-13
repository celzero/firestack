// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dialers

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/celzero/firestack/intra/log"
)

type netConnectFunc func(*net.Dialer, string, netip.Addr, int) (net.Conn, error)

var errNotUDPConn = errors.New("listener: not a UDPConn")

func netConnect(d *net.Dialer, proto string, ip netip.Addr, port int) (net.Conn, error) {
	if d == nil {
		log.E("ndial: netConnect: nil dialer")
		return nil, errNoDialer
	}
	switch proto {
	case "tcp", "tcp4", "tcp6":
		fallthrough
	case "udp", "udp4", "udp6":
		fallthrough
	default:
		return d.Dial(proto, addr(ip, port))
	}
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
	confirmed := ips.Confirmed()
	if ipok(confirmed) {
		if conn, cerr := connect(d, network, confirmed, port); cerr == nil {
			log.V("ndial: found working ip %s for %s", confirmed, addr)
			return conn, nil
		} else {
			errs = errors.Join(errs, cerr)
			ips.Disconfirm(confirmed)
			log.D("ndial: confirmed ip %s for %s failed with err %v", confirmed, addr, cerr)
		}
	}

	ipset := ips.Addrs()
	allips := filter(ipset, confirmed)
	if len(allips) <= 0 {
		var ok bool
		if ips, ok = renew(domain, ips); ok {
			ipset = ips.Addrs()
			allips = filter(ipset, confirmed)
		}
		log.D("ndial: renew ips for %s; ok? %t", addr, ok)
	}
	log.D("ndial: trying all ips %d for %s", len(allips), addr)
	for _, ip := range allips {
		end := time.Since(start)
		if end > dialRetryTimeout {
			log.D("ndial: timeout %s for %s", end, addr)
			break
		}
		if ipok(ip) {
			if conn, err := connect(d, network, ip, port); err == nil {
				ips.Confirm(ip)
				log.I("ndial: found working ip %s for %s", ip, addr)
				return conn, nil
			} else {
				errs = errors.Join(errs, err)
				log.W("ndial: ip %s for %s failed with err %v", ip, addr, err)
			}
		} else {
			log.D("ndial: ip %s not ok for %s", ip, addr)
		}
	}

	dur := time.Since(start)
	log.D("ndial: duration: %s; failed %s", dur, addr)

	if len(ipset) <= 0 {
		errs = errNoIps
	}

	return nil, errs
}

// NetDial connects to the address on the named network using net.Dialer.
func NetDial(d *net.Dialer, network, addr string) (net.Conn, error) {
	return netdial(d, network, addr, netConnect)
}

// NetListen listens for UDP on local address using cfg.
// Returned net.Conn is guaranteed to be a *net.UDPConn.
func NetListen(cfg *net.ListenConfig, network, local string) (net.PacketConn, error) {
	if cfg == nil {
		log.E("ndial: NetListen: nil listen config")
		return nil, errNoListener
	}
	if c, err := cfg.ListenPacket(context.Background(), network, local); err == nil {
		if conn, ok := c.(*net.UDPConn); ok {
			return conn, nil
		} else {
			log.W("ndial: NetListen: p(%s) %T not a net.UDPConn; src: %s", network, c, local)
			clos(conn)
			return nil, errNotUDPConn
		}
	} else {
		return nil, err
	}
}

func clos(c io.Closer) {
	if c != nil {
		c.Close()
	}
}
