// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dialers

import (
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/celzero/firestack/intra/log"
)

type tlsConnectFunc func(*tls.Dialer, string, string, netip.Addr, int) (net.Conn, error)

func tlsConnect(d *tls.Dialer, proto, sni string, ip netip.Addr, port int) (net.Conn, error) {
	if d == nil {
		log.E("tlsdial: tlsConnect: nil dialer")
		return nil, errNoDialer
	}
	switch proto {
	case "tcp", "tcp4", "tcp6":
		fallthrough
	case "udp", "udp4", "udp6":
		fallthrough
	default:
		if d.Config == nil {
			d.Config = &tls.Config{
				ServerName: sni,
			}
		} else if len(d.Config.ServerName) <= 0 {
			d.Config.ServerName = sni
		}
		return d.Dial(proto, addr(ip, port))
	}
}

func tlsdial(d *tls.Dialer, network, addr string, connect tlsConnectFunc) (net.Conn, error) {
	start := time.Now()

	log.D("tlsdial: dialing %s", addr)
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
		if conn, err := connect(d, network, domain, confirmed, port); err == nil {
			log.V("tlsdial: found working ip %s for %s", confirmed, addr)
			return conn, nil
		}
		errs = errors.Join(errs, err)
		ips.Disconfirm(confirmed)
		log.D("tlsdial: confirmed ip %s for %s failed with err %v", confirmed, addr, err)
	}

	allips := filter(ips.GetAll(), confirmed)
	if len(allips) <= 0 {
		var ok bool
		if ok = Renew(domain, ips.Seed()); ok {
			allips = filter(ips.GetAll(), confirmed)
		}
		log.D("tlsdial: renew ips for %s; ok? %t", addr, ok)
	}
	log.D("tlsdial: trying all ips %d for %s", len(allips), addr)
	for _, ip := range allips {
		if conn, err = connect(d, network, domain, ip, port); err == nil {
			ips.Confirm(ip)
			log.I("tlsdial: found working ip %s for %s", ip, addr)
			return conn, nil
		}
		errs = errors.Join(errs, err)
		log.W("tlsdial: ip %s for %s failed with err %v", ip, addr, err)
	}

	dur := time.Since(start)
	log.D("tlsdial: duration: %s; failed %s", dur, addr)

	return nil, errors.Join(errs, errNoIps)
}

func TlsDial(d *tls.Dialer, network, addr string) (net.Conn, error) {
	return tlsdial(d, network, addr, tlsConnect)
}
