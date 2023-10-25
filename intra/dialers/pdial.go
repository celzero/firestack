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
		log.E("pdial: split host port failed with err %v", err)
		return nil, err
	}
	// cannot dial into a wildcard address; listen is unsupported
	if len(domain) == 0 {
		log.E("pdial: no domain")
		return nil, net.InvalidAddrError(addr)
	}
	port, err := strconv.Atoi(portstr)
	if err != nil {
		log.E("pdial: no port")
		return nil, err
	}
	// TODO: Improve IP fallback strategy with parallelism and Happy Eyeballs.
	var conn net.Conn
	s1 := time.Now()
	ips := ipm.Get(domain)
	confirmed := ips.Confirmed()
	if confirmed.IsValid() {
		if conn, err = connect(d, network, confirmed, port); err == nil {
			log.V("pdial: found working ip %s for %s; duration: %s", confirmed, addr, time.Since(s1))
			return conn, nil
		}
		ips.Disconfirm(confirmed)
		log.D("pdial: confirmed ip %s for %s failed with err %v", confirmed, addr, err)
	}

	s2 := time.Now()
	allips := filter(ips.GetAll(), confirmed)
	if len(allips) <= 0 {
		var ok bool
		if ok = Renew(domain, ips.Seed()); ok {
			allips = filter(ips.GetAll(), confirmed)
		}
		log.D("pdial: renew ips for %s; ok? %t", addr, ok)
	}
	log.D("pdial: trying all %d ips for %s; duration: %s", len(allips), addr, time.Since(s2))

	s3 := time.Now()
	for i, ip := range allips {
		if conn, err = connect(d, network, ip, port); err == nil {
			ips.Confirm(ip)
			log.I("pdial: found working ip%d %s for %s; duration: %s to %s", i, ip, addr, time.Since(s3))
			return conn, nil
		}
		log.W("pdial: ip %s for %s failed with err %v", ip, addr, err)
	}

	dur := time.Since(start).Seconds()
	log.D("pdial: duration: %ds; failed %s", dur*1000, addr)

	// for example, socks5 proxy does not support dialing hostnames
	return nil, errNoIps
}

func ProxyDial(d proxy.Dialer, network, addr string) (net.Conn, error) {
	return proxydial(d, network, addr, proxyConnect)
}
