// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dialers

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/celzero/firestack/intra/log"
)

type netConnectFunc func(*net.Dialer, string, netip.Addr, int) (net.Conn, error)

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

	var conn net.Conn
	var errs error
	ips := ipm.Get(domain)
	confirmed := ips.Confirmed()
	if confirmed.IsValid() {
		if conn, err := connect(d, network, confirmed, port); err == nil {
			log.V("ndial: found working ip %s for %s", confirmed, addr)
			return conn, nil
		}
		errs = errors.Join(errs, err)
		ips.Disconfirm(confirmed)
		log.D("ndial: confirmed ip %s for %s failed with err %v", confirmed, addr, err)
	}

	ipset := ips.Addrs()
	allips := filter(ipset, confirmed)
	if len(allips) <= 0 {
		var ok bool
		if ips, ok = Renew(domain, ips.Seed()); ok {
			ipset = ips.Addrs()
			allips = filter(ipset, confirmed)
		}
		log.D("ndial: renew ips for %s; ok? %t", addr, ok)
	}
	log.D("ndial: trying all ips %d for %s", len(allips), addr)
	for _, ip := range allips {
		if conn, err = connect(d, network, ip, port); err == nil {
			ips.Confirm(ip)
			log.I("ndial: found working ip %s for %s", ip, addr)
			return conn, nil
		}
		errs = errors.Join(errs, err)
		log.W("ndial: ip %s for %s failed with err %v", ip, addr, err)
	}

	dur := time.Since(start)
	log.D("ndial: duration: %s; failed %s", dur, addr)

	if len(ipset) <= 0 {
		errs = errNoIps
	}

	return nil, errs
}

func NetDial(d *net.Dialer, network, addr string) (net.Conn, error) {
	return netdial(d, network, addr, netConnect)
}
