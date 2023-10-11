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

type connectFunc func(*protect.RDial, string, netip.Addr, int) (net.Conn, error)

var ipm ipmap.IPMap = ipmap.NewIPMap()

func addr(ip netip.Addr, port int) string {
	return net.JoinHostPort(ip.String(), strconv.Itoa(port))
}

func tcpaddr(ip netip.Addr, port int) *net.TCPAddr {
	// ip must never be a wildcard address and must be unmapped
	// go.dev/play/p/UopgKYEMJtw
	return &net.TCPAddr{IP: ip.AsSlice(), Port: port}
}

func udpaddr(ip netip.Addr, port int) *net.UDPAddr {
	// ip must never be a wildcard address and must be unmapped
	// go.dev/play/p/UopgKYEMJtw
	return &net.UDPAddr{IP: ip.AsSlice(), Port: port}
}

func Renew(hostname string, addrs []string) bool {
	if len(hostname) <= 0 {
		return false
	}
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

func Mapper(m ipmap.IPMapper) {
	log.I("split: mapper ok? %t", m != nil)
	// usually set just the once
	ipm.With(m)
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

func ipConnect(d *protect.RDial, proto string, ip netip.Addr, port int) (net.Conn, error) {
	switch proto {
	case "tcp", "tcp4", "tcp6":
		return d.DialTCP(proto, nil, tcpaddr(ip, port))
	case "udp", "udp4", "udp6":
		return d.DialUDP(proto, nil, udpaddr(ip, port))
	default:
		return d.Dial(proto, addr(ip, port))
	}
}

func splitIpConnect(d *protect.RDial, proto string, ip netip.Addr, port int) (net.Conn, error) {
	switch proto {
	case "tcp", "tcp4", "tcp6":
		if conn, err := DialWithSplitRetry(d, tcpaddr(ip, port)); err == nil {
			log.D("redial: tcp: confirmed IP %s worked for %s", ip)
			return conn, nil
		}
	case "udp", "udp4", "udp6":
		if conn, err := d.DialUDP(proto, nil, udpaddr(ip, port)); err == nil {
			log.D("redial: udp: confirmed IP %s worked for %s", ip)
			return conn, nil
		}
	default:
		log.I("redial: unknown network %s", proto)
		return d.Dial(proto, addr(ip, port))
	}
	return nil, net.UnknownNetworkError(proto)
}

func commondial(d *protect.RDial, network, addr string, connect connectFunc) (net.Conn, error) {
	start := time.Now()

	log.D("redial: commondial: dialing %s", addr)
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
		log.D("redial: commondial: confirmed IP %s for %s failed with err %v", confirmed, addr, err)
	}

	allips := filter(ips.GetAll(), confirmed)
	if len(allips) <= 0 {
		log.D("redial: commondial: renew IPs for %s", addr)
		Renew(domain, ips.Seed())
		allips = filter(ips.GetAll(), confirmed)
	}
	log.D("redial: commondial: trying all IPs %d for %s", len(allips), addr)
	for _, ip := range allips {
		if conn, err = connect(d, network, ip, port); err == nil {
			ips.Confirm(ip)
			log.I("redial: commondial: found working IP %s for %s", ip, addr)
			return conn, nil
		}
	}

	dur := time.Since(start).Seconds()
	log.D("redial: commondial: duration: %ss; failed %s", dur, addr)
	// xxx: return nil, net.UnknownNetworkError(network)?
	return d.Dial(network, addr)
}

func SplitDial(d *protect.RDial, network, addr string) (net.Conn, error) {
	return commondial(d, network, addr, splitIpConnect)
}

func Dial(d *protect.RDial, network, addr string) (net.Conn, error) {
	return commondial(d, network, addr, ipConnect)
}
