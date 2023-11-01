// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dialers

import (
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/celzero/firestack/intra/log"
)

type netConnectFunc func(*net.Dialer, string, netip.Addr, int) (net.Conn, error)

func netConnect(d *net.Dialer, proto string, ip netip.Addr, port int) (net.Conn, error) {
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
	// TODO: Improve IP fallback strategy with parallelism and Happy Eyeballs.
	var conn net.Conn
	ips := ipm.Get(domain)
	confirmed := ips.Confirmed()
	if confirmed.IsValid() {
		if conn, err := connect(d, network, confirmed, port); err == nil {
			log.V("ndial: found working ip %s for %s", confirmed, addr)
			return conn, nil
		}
		ips.Disconfirm(confirmed)
		log.D("ndial: confirmed ip %s for %s failed with err %v", confirmed, addr, err)
	}

	allips := filter(ips.GetAll(), confirmed)
	if len(allips) <= 0 {
		log.D("ndial: renew ips for %s", addr)
		Renew(domain, ips.Seed())
		allips = filter(ips.GetAll(), confirmed)
	}
	log.D("ndial: trying all ips %d for %s", len(allips), addr)
	for _, ip := range allips {
		if conn, err = connect(d, network, ip, port); err == nil {
			ips.Confirm(ip)
			log.I("ndial: found working ip %s for %s", ip, addr)
			return conn, nil
		}
		log.W("ndial: ip %s for %s failed with err %v", ip, addr, err)
	}

	dur := time.Since(start)
	log.D("ndial: duration: %s; failed %s", dur, addr)

	return nil, errNoIps
}

func NetDial(d *net.Dialer, network, addr string) (net.Conn, error) {
	return netdial(d, network, addr, netConnect)
}
