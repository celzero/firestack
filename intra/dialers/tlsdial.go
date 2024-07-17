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
	} else if !ipok(ip) {
		log.E("tlsdial: tlsConnect: invalid ip", ip)
		return nil, errNoIps
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
				MinVersion: tls.VersionTLS12,
			}
		} else if len(d.Config.ServerName) <= 0 {
			d.Config.ServerName = sni
		}
		return d.Dial(proto, addrstr(ip, port))
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
	var errs error
	ips := ipm.Get(domain)
	dontretry := ips.OneIPOnly() // just one IP, no retries possible
	confirmed := ips.Confirmed()
	confirmedIPOK := ipok(confirmed)

	defer func() {
		dur := time.Since(start)
		log.D("tlsdial: duration: %s; failed %s; confirmed? %s, sz: %d", dur, addr, confirmed, ips.Size())
	}()

	if confirmedIPOK {
		log.V("tlsdial: confirmed ip %s for %s", confirmed, addr)
		if conn, cerr := connect(d, network, domain, confirmed, port); cerr == nil {
			log.V("tlsdial: found working ip %s for %s", confirmed, addr)
			return conn, nil
		} else {
			errs = errors.Join(errs, cerr)
			ips.Disconfirm(confirmed)
			log.D("tlsdial: confirmed ip %s for %s failed with err %v", confirmed, addr, cerr)
		}
	}

	if dontretry {
		if !confirmedIPOK {
			log.E("tlsdial: ip %s not ok for %s", confirmed, addr)
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
		log.D("tlsdial: renew ips for %s; ok? %t, failingopen? %t", addr, ok, failingopen)
	}
	log.D("tlsdial: trying all ips %d for %s", len(allips), addr)
	for _, ip := range allips {
		end := time.Since(start)
		if end > dialRetryTimeout {
			log.D("pdial: timeout %s for %s", end, addr)
			break
		}
		if ipok(ip) {
			log.V("tlsdial: trying ip %s for %s", ip, addr)
			if conn, err := connect(d, network, domain, ip, port); err == nil {
				confirm(ips, ip)
				log.I("tlsdial: found working ip %s for %s", ip, addr)
				return conn, nil
			} else {
				errs = errors.Join(errs, err)
				log.W("tlsdial: ip %s for %s failed with err %v", ip, addr, err)
			}
		} else {
			log.D("tlsdial: ip %s for %s is not ok", ip, addr)
		}
	}

	if len(ipset) <= 0 {
		errs = errNoIps
	}

	return nil, errs
}

func TlsDial(d *tls.Dialer, network, addr string) (net.Conn, error) {
	return tlsdial(d, network, addr, tlsConnect)
}
