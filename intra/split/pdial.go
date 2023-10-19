// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package split

import (
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/celzero/firestack/intra/log"
	"golang.org/x/net/proxy"
)

type proxyConnectFunc func(proxy.Dialer, string, netip.Addr, int) (net.Conn, error)

func proxyConnect(d proxy.Dialer, proto string, ip netip.Addr, port int) (net.Conn, error) {
	switch proto {
	case "tcp", "tcp4", "tcp6":
		fallthrough
	case "udp", "udp4", "udp6":
		fallthrough
	default:
		return d.Dial(proto, addr(ip, port))
	}
}

func proxydial(d proxy.Dialer, network, addr string, connect proxyConnectFunc) (net.Conn, error) {
	start := time.Now()

	log.D("pdial: dialing %s", addr)
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
			return conn, nil
		}
		ips.Disconfirm(confirmed)
		log.D("pdial: confirmed IP %s for %s failed with err %v", confirmed, addr, err)
	}

	allips := filter(ips.GetAll(), confirmed)
	if len(allips) <= 0 {
		log.D("ndial: renew IPs for %s", addr)
		Renew(domain, ips.Seed())
		allips = filter(ips.GetAll(), confirmed)
	}
	log.D("pdial: trying all IPs %d for %s", len(allips), addr)
	for _, ip := range allips {
		if conn, err = connect(d, network, ip, port); err == nil {
			ips.Confirm(ip)
			log.I("pdial: found working IP %s for %s", ip, addr)
			return conn, nil
		}
	}

	dur := time.Since(start).Seconds()
	log.D("pdial: duration: %ss; failed %s", dur, addr)

	// for example, socks5 proxy does not support dialing hostnames
	return nil, errNoIps
}

func ProxyDial(d proxy.Dialer, network, addr string) (net.Conn, error) {
	return proxydial(d, network, addr, proxyConnect)
}
