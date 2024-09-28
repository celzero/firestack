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

const dialRetryTimeout = 1 * time.Minute

func maybeFilter(ips []netip.Addr, alwaysExclude netip.Addr) ([]netip.Addr, bool) {
	failingopen := true
	use4 := Use4()
	use6 := Use6()

	filtered := make([]netip.Addr, 0, len(ips))
	unfiltered := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if ip.Compare(alwaysExclude) == 0 || !ip.IsValid() {
			continue
		} else if use4 && ip.Is4() {
			filtered = append(filtered, ip)
		} else if use6 && ip.Is6() {
			filtered = append(filtered, ip)
		} else {
			unfiltered = append(unfiltered, ip)
		}
	}
	if len(filtered) <= 0 {
		// if all ips are filtered out, fail open and return unfiltered
		return unfiltered, failingopen
	}
	if len(unfiltered) > 0 {
		// sample one unfiltered ip in an ironic case that it works
		// but the filtered out ones don't. this can happen in scenarios
		// where tunnel's ipProto is IP4 but the underlying network is IP6:
		// that is, IP6 is filtered out even though it might have worked.
		filtered = append(filtered, unfiltered[0])
	}
	return filtered, !failingopen
}

// ipConnect dials into ip:port using the provided dialer and returns a net.Conn
// net.Conn is guaranteed to be either net.UDPConn or net.TCPConn
func ipConnect(d *protect.RDial, proto string, ip netip.Addr, port int) (net.Conn, error) {
	if d == nil {
		log.E("rdial: ipConnect: nil dialer")
		return nil, errNoDialer
	} else if !ipok(ip) {
		log.E("rdial: ipConnect: invalid ip", ip)
		return nil, errNoIps
	}

	switch proto {
	case "tcp", "tcp4", "tcp6":
		return d.DialTCP(proto, nil, tcpaddr(ip, port))
	case "udp", "udp4", "udp6":
		return d.DialUDP(proto, nil, udpaddr(ip, port))
	default:
		return d.Dial(proto, addrstr(ip, port))
	}
}

func doSplit(ip netip.Addr, port int) bool {
	// HTTPS or DoT
	return !ip.IsPrivate() && (port == 443 || port == 853)
}

func splitIpConnect(d *protect.RDial, proto string, ip netip.Addr, port int) (net.Conn, error) {
	if d == nil {
		log.E("rdial: splitIpConnect: nil dialer")
		return nil, errNoDialer
	} else if !ipok(ip) {
		log.E("rdial: splitIpConnect: invalid ip", ip)
		return nil, errNoIps
	}

	switch proto {
	case "tcp", "tcp4", "tcp6":
		if doSplit(ip, port) {
			return DialWithSplitRetry(d, tcpaddr(ip, port))
		}
		return d.DialTCP(proto, nil, tcpaddr(ip, port))
	case "udp", "udp4", "udp6":
		return d.DialUDP(proto, nil, udpaddr(ip, port))
	default:
		return d.Dial(proto, addrstr(ip, port))
	}
}

func commondial[C rconn](d *protect.RDial, network, addr string, connect mkrconn[C]) (C, error) {
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

	var conn C
	var errs error
	ips := ipm.Get(domain)
	dontretry := ips.OneIPOnly() // just one IP, no retries possible
	confirmed := ips.Confirmed() // may be zeroaddr
	confirmedIPOK := ipok(confirmed)

	defer func() {
		dur := time.Since(start)
		log.D("rdial: duration: %s; failed %s; confirmed? %s, sz: %d", dur, addr, confirmed, ips.Size())
	}()

	if confirmedIPOK {
		log.V("rdial: commondial: dialing confirmed ip %s for %s", confirmed, addr)
		conn, err = connect(d, network, confirmed, port)
		// nilaway: tx.socks5 returns nil conn even if err == nil
		if conn == nil && err == nil {
			err = errNoConn
		}
		if err == nil {
			log.V("rdial: commondial: ip %s works for %s", confirmed, addr)
			return conn, nil
		}
		errs = errors.Join(errs, err)
		ips.Disconfirm(confirmed)
		log.D("rdial: commondial: confirmed ip %s for %s failed with err %v", confirmed, addr, err)
	}

	if dontretry {
		if !confirmedIPOK {
			log.E("rdial: ip %s not ok for %s", confirmed, addr)
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
		log.D("rdial: renew ips for %s; ok? %t, failingopen? %t", addr, ok, failingopen)
	}
	log.D("rdial: commondial: trying all ips %d %v for %s, failingopen? %t",
		len(allips), allips, addr, failingopen)
	for _, ip := range allips {
		end := time.Since(start)
		if end > dialRetryTimeout {
			log.D("rdial: commondial: timeout %s for %s", end, addr)
			break
		}
		if ipok(ip) {
			conn, err = connect(d, network, ip, port)
			// nilaway: tx.socks5 returns nil conn even if err == nil
			if conn == nil && err == nil {
				err = errNoConn
			}
			if err == nil {
				log.V("rdial: commondial: dialing ip %s for %s", ip, addr)
				confirm(ips, ip)
				log.I("rdial: commondial: ip %s works for %s", ip, addr)
				return conn, nil
			}
			errs = errors.Join(errs, err)
			log.W("rdial: commondial: ip %s for %s failed with err %v", ip, addr, err)
		} else {
			log.W("rdial: commondial: ip %s not ok for %s", ip, addr)
		}
	}

	if len(ipset) <= 0 {
		errs = errNoIps
	}

	return nil, errs
}

// ListenPacket listens on for UDP connections on the local address using d.
// Returned net.Conn is guaranteed to be a *net.UDPConn.
func ListenPacket(d *protect.RDial, network, local string) (net.PacketConn, error) {
	if d == nil {
		log.E("rdial: ListenPacket: nil dialer")
		return nil, errNoListener
	}
	return d.AnnounceUDP(network, local)
}

// Listen listens on for TCP connections on the local address using d.
func Listen(d *protect.RDial, network, local string) (net.Listener, error) {
	if d == nil {
		log.E("rdial: Listen: nil dialer")
		return nil, errNoListener
	}
	return d.AcceptTCP(network, local)
}

// Probe sends and accepts ICMP packets on local addr using d over a net.PacketConn.
func Probe(d *protect.RDial, network, local string) (net.PacketConn, error) {
	// commondial does not handle unspecified ips well; see: ipmap.go & ipok()
	// return unPtr(commondial(d, network, addr, adaptp(icmpListen)))
	return d.ProbeICMP(network, local)
}

// Dial dials into addr using the provided dialer and returns a net.Conn,
// which is guaranteed to be either net.UDPConn or net.TCPConn
func Dial(d *protect.RDial, network, addr string) (net.Conn, error) {
	return unPtr(commondial(d, network, addr, adaptc(ipConnect)))
}

// DialWithTls dials into addr using the provided dialer and returns a tls.Conn
func DialWithTls(d *protect.RDial, cfg *tls.Config, addr string) (net.Conn, error) {
	return dialtls(d, cfg, addr, adaptc(ipConnect))
}

// SplitDial dials into addr splitting the first segment to two if the
// first connection is unsuccessful, using settings.DialStrategy.
// Returns a net.Conn, which may not be net.UDPConn or net.TCPConn.
func SplitDial(d *protect.RDial, network, addr string) (net.Conn, error) {
	return unPtr(commondial(d, network, addr, adaptc(splitIpConnect)))
}

// SplitDialWithTls dials into addr using the provided dialer and returns a tls.Conn
func SplitDialWithTls(d *protect.RDial, cfg *tls.Config, addr string) (net.Conn, error) {
	return dialtls(d, cfg, addr, adaptc(splitIpConnect))
}

func ipok(ip netip.Addr) bool {
	return ip.IsValid() && !ip.IsUnspecified()
}

func dialtls(d *protect.RDial, cfg *tls.Config, addr string, how mkrconn[*net.Conn]) (net.Conn, error) {
	c, err := unPtr(commondial(d, "tcp", addr, how))
	if err != nil {
		clos(c)
		return nil, err
	}
	tlsconn := tls.Client(c, cfg)
	err = tlsconn.Handshake()
	if eerr, ok := err.(*tls.ECHRejectionError); ok {
		clos(tlsconn)

		ech := eerr.RetryConfigList
		log.I("rdial: tls: ech rejected; new? %d, err: %v", len(ech), eerr)
		if len(ech) > 0 { // retry with new ech
			cfg.EncryptedClientHelloConfigList = ech
			c, err = unPtr(commondial(d, "tcp", addr, adaptc(ipConnect)))
			if err != nil {
				clos(c)
				return nil, err
			}
			tlsconn = tls.Client(c, cfg)
			err = tlsconn.Handshake()
		}
	}
	if err != nil {
		clos(tlsconn)
		tlsconn = nil
	}
	return tlsconn, err
}
