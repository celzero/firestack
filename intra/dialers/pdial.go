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
	"golang.org/x/net/proxy"
)

type proxyConnectFunc func(proxy.Dialer, string, netip.Addr, int) (net.Conn, error)

func proxyConnect(d proxy.Dialer, proto string, ip netip.Addr, port int) (net.Conn, error) {
	if d == nil {
		log.E("odial: proxyConnect: nil dialer")
		return nil, errNoDialer
	} else if !ipok(ip) {
		log.E("odial: proxyConnect: invalid ip", ip)
		return nil, errNoIps
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

	var conn net.Conn
	var errs error
	s1 := time.Now()
	ips := ipm.Get(domain)
	confirmed := ips.Confirmed()
	if ipok(confirmed) {
		log.V("pdial: trying confirmed ip %s for %s; duration: %s", confirmed, addr, time.Since(s1))
		if conn, err = connect(d, network, confirmed, port); err == nil {
			log.V("pdial: found working ip %s for %s; duration: %s", confirmed, addr, time.Since(s1))
			return conn, nil
		}
		errs = errors.Join(errs, err)
		ips.Disconfirm(confirmed)
		log.D("pdial: confirmed ip %s for %s failed with err %v", confirmed, addr, err)
	}

	s2 := time.Now()
	ipset := ips.Addrs()
	allips := maybeFilter(ipset, confirmed)
	if len(allips) <= 0 {
		var ok bool
		if ips, ok = renew(domain, ips); ok {
			ipset = ips.Addrs()
			allips = maybeFilter(ipset, confirmed)
		}
		log.D("pdial: renew ips for %s; ok? %t", addr, ok)
	}
	log.D("pdial: trying all %d ips for %s; duration: %s", len(allips), addr, time.Since(s2))

	s3 := time.Now()
	for i, ip := range allips {
		end := time.Since(start)
		if end > dialRetryTimeout {
			log.D("pdial: timeout %s for %s", end, addr)
			break
		}
		if ipok(ip) {
			log.V("pdial: trying ip%d %s for %s; duration: %s", i, ip, addr, time.Since(s3))
			if conn, err = connect(d, network, ip, port); err == nil {
				ips.Confirm(ip)
				log.I("pdial: found working ip%d %s for %s; duration: %s", i, ip, addr, time.Since(s3))
				return conn, nil
			}
			errs = errors.Join(errs, err)
			log.W("pdial: ip %s for %s failed with err %v", ip, addr, err)
		} else {
			log.D("pdial: ip %s not ok for %s", ip, addr)
		}
	}

	dur := time.Since(start)
	log.D("pdial: duration: %s; failed %s", dur, addr)

	if len(ipset) <= 0 {
		errs = errNoIps
	}

	// for example, socks5 proxy does not support dialing hostnames
	return nil, errs
}

// ProxyDial tries to connect to addr using d
func ProxyDial(d proxy.Dialer, network, addr string) (net.Conn, error) {
	return proxydial(d, network, addr, proxyConnect)
}

// ProxyDials tries to connect to addr using each dialer in dd
func ProxyDials(dd []proxy.Dialer, network, addr string) (c net.Conn, err error) {
	tot := len(dd)
	for i, d := range dd {
		c, err = proxydial(d, network, addr, proxyConnect)
		if err != nil {
			log.W("pdial: trying %s dialer of %d / %d to %s", network, i, tot, addr)
			err = errors.Join(err)
		} else {
			err = nil
			return
		}
	}
	return
}
