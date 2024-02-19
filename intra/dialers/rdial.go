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
	"github.com/celzero/firestack/intra/protect"
)

type connectFunc func(*protect.RDial, string, netip.Addr, int) (net.Conn, error)

func filter(ips []netip.Addr, exclude netip.Addr) []netip.Addr {
	filtered := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if ip.Compare(exclude) == 0 || !ip.IsValid() {
			continue
		}
		filtered = append(filtered, ip)
	}
	return filtered
}

// ipConnect dials into ip:port using the provided dialer and returns a net.Conn
// net.Conn is guaranteed to be either net.UDPConn or net.TCPConn
func ipConnect(d *protect.RDial, proto string, ip netip.Addr, port int) (net.Conn, error) {
	if d == nil {
		log.E("rdial: ipConnect: nil dialer")
		return nil, errNoDialer
	}
	switch proto {
	case "tcp", "tcp4", "tcp6":
		return d.DialTCP(proto, nil, tcpaddr(ip, port))
	case "udp", "udp4", "udp6":
		return d.DialUDP(proto, nil, udpaddr(ip, port))
	default:
		return d.Dial(proto, addr(ip, port))
	}
}

// ipConnect2 dials into ip:port using the provided dialer and returns a net.Conn
// net.Conn may not be any among net.UDPConn or net.TCPConn or core.UDPConn or core.TCPConn
func ipConnect2(d *protect.RDial, proto string, ip netip.Addr, port int) (net.Conn, error) {
	if d == nil {
		log.E("rdial: ipConnect: nil dialer")
		return nil, errNoDialer
	}
	return d.Dial(proto, addr(ip, port))
}

func doSplit(port int) bool {
	// HTTPS or DoT
	return port == 443 || port == 853
}

func splitIpConnect(d *protect.RDial, proto string, ip netip.Addr, port int) (net.Conn, error) {
	if d == nil {
		log.E("rdial: splitIpConnect: nil dialer")
		return nil, errNoDialer
	}
	switch proto {
	case "tcp", "tcp4", "tcp6":
		if doSplit(port) { // split tls client-hello for https requests
			return DialWithSplitRetry(d, tcpaddr(ip, port))
		}
		return d.DialTCP(proto, nil, tcpaddr(ip, port))
	case "udp", "udp4", "udp6":
		return d.DialUDP(proto, nil, udpaddr(ip, port))
	default:
		return d.Dial(proto, addr(ip, port))
	}
}

func splitIpConnect2(d *protect.RDial, proto string, ip netip.Addr, port int) (net.Conn, error) {
	if d == nil {
		log.E("rdial: splitIpConnect: nil dialer")
		return nil, errNoDialer
	}
	switch proto {
	case "tcp", "tcp4", "tcp6":
		if doSplit(port) { // split tls client-hello for https requests
			return DialWithSplit(d, tcpaddr(ip, port))
		}
		return d.DialTCP(proto, nil, tcpaddr(ip, port))
	case "udp", "udp4", "udp6":
		return d.DialUDP(proto, nil, udpaddr(ip, port))
	default:
		return d.Dial(proto, addr(ip, port))
	}
}

func commondial(d *protect.RDial, network, addr string, connect connectFunc) (net.Conn, error) {
	start := time.Now()

	log.D("rdial: commondial: dialing (host:port) %s", addr)
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
		if conn, err = connect(d, network, confirmed, port); err == nil {
			log.V("rdial: commondial: found working ip %s for %s", confirmed, addr)
			return conn, nil
		}
		errs = errors.Join(errs, err)
		ips.Disconfirm(confirmed)
		log.D("rdial: commondial: confirmed ip %s for %s failed with err %v", confirmed, addr, err)
	}

	ipset := ips.Addrs()
	allips := filter(ipset, confirmed)
	if len(allips) <= 0 {
		var ok bool
		if ips, ok = renew(domain, ips); ok {
			ipset = ips.Addrs()
			allips = filter(ipset, confirmed)
		}
		log.D("rdial: renew ips for %s; ok? %t", addr, ok)
	}
	log.D("rdial: commondial: trying all ips %d for %s", len(allips), addr)
	for _, ip := range allips {
		if conn, err = connect(d, network, ip, port); err == nil {
			ips.Confirm(ip)
			log.I("rdial: commondial: found working ip %s for %s", ip, addr)
			return conn, nil
		}
		errs = errors.Join(errs, err)
		log.W("rdial: commondial: ip %s for %s failed with err %v", ip, addr, err)
	}

	dur := time.Since(start)
	log.D("rdial: commondial: duration: %s; failed %s", dur, addr)

	if len(ipset) <= 0 {
		errs = errNoIps
	}

	return nil, errs
}

func Listen(d *protect.RDial, network, local string) (net.PacketConn, error) {
	if d == nil {
		log.E("rdial: Announce: nil dialer")
		return nil, errNoListener
	}
	return d.AnnounceUDP(network, local)
}

// Dial dials into addr using the provided dialer and returns a net.Conn,
// which is guaranteed to be either net.UDPConn or net.TCPConn
func Dial(d *protect.RDial, network, addr string) (net.Conn, error) {
	return commondial(d, network, addr, ipConnect)
}

// Dial2 dials into addr using the provided dialer and returns a net.Conn
func Dial2(d *protect.RDial, network, addr string) (net.Conn, error) {
	return commondial(d, network, addr, ipConnect2)
}

// SplitDial dials into addr splitting ClientHello if the first connection
// is unsuccessful. Using the provided dialer it returns a net.Conn,
// which may not be net.UDPConn or net.TCPConn
func SplitDial(d *protect.RDial, network, addr string) (net.Conn, error) {
	return commondial(d, network, addr, splitIpConnect)
}

// SplitDial2 is like SplitDial except it splits ClientHello in all TLS connections.
func SplitDial2(d *protect.RDial, network, addr string) (net.Conn, error) {
	return commondial(d, network, addr, splitIpConnect2)
}

// SplitDialWithTls dials into addr using the provided dialer and returns a tls.Conn
func SplitDialWithTls(d *protect.RDial, cfg *tls.Config, addr string) (net.Conn, error) {
	c, err := commondial(d, "tcp", addr, splitIpConnect)
	if err != nil {
		return c, err
	}
	tlsconn := tls.Client(c, cfg)
	err = tlsconn.Handshake()
	return tlsconn, err
}
