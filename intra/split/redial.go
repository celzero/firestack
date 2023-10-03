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
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/protect/ipmap"
)

var ipm ipmap.IPMap = ipmap.NewIPMap()

func tcpaddr(ip netip.Addr, port int) *net.TCPAddr {
	return &net.TCPAddr{IP: ip.AsSlice(), Port: port}
}

func Renew(hostname string, addrs []string) bool {
	ips := ipm.Of(hostname, addrs)
	return ips != nil && !ips.Empty()
}

func For(hostname string) []netip.Addr {
	ipset := ipm.Get(hostname)
	if ipset != nil {
		return ipset.GetAll()
	}
	return nil
}

func Confirm(hostname string, addr net.Addr) bool {
	ips := ipm.GetAny(hostname)
	if ips != nil {
		if ip, err := netip.ParseAddr(addr.String()); err == nil {
			ips.Confirm(ip)
			return true
		} // not ok
	} // not ok
	return false
}

func Disconfirm(hostname string, ip net.Addr) bool {
	ips := ipm.GetAny(hostname)
	if ips != nil {
		if ip, err := netip.ParseAddr(ip.String()); err == nil {
			ips.Disconfirm(ip)
			return true
		} // not ok
	} // not ok
	return false
}

func ReDial(dialer *protect.RDial, network, addr string) (net.Conn, error) {
	start := time.Now()
	log.D("redial: dialing %s", addr)
	domain, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}

	// TODO: Improve IP fallback strategy with parallelism and Happy Eyeballs.
	var conn net.Conn
	ips := ipm.Get(domain)
	confirmed := ips.Confirmed()
	if confirmed.IsValid() {
		log.D("redial: trying IP %s for addr %s", confirmed, addr)
		if conn, err = DialWithSplitRetry(dialer, tcpaddr(confirmed, port)); err == nil {
			log.I("redial: confirmed IP %s worked for %s", confirmed, addr)
			return conn, nil
		}
		go ips.Disconfirm(confirmed)
		log.D("redial: IP %s for %s failed with err %v", confirmed, addr, err)
	}

	allips := ips.GetAll()
	log.D("redial: trying all IPs %d for %s", len(allips), addr)
	for _, ip := range allips {
		// confirmed already tried above
		if ip.Compare(confirmed) == 0 || !ip.IsValid() {
			continue
		}
		if conn, err = DialWithSplitRetry(dialer, tcpaddr(ip, port)); err == nil {
			go ips.Confirm(ip)
			log.I("redial: found working IP %s for %s", ip, addr)
			return conn, nil
		}
	}

	log.W("redial: dur: %ss; renew %s", time.Since(start).Seconds(), addr)
	go Renew(domain, ips.Seed())

	return dialer.Dial(network, addr)
}
