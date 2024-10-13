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

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	utls "github.com/refraction-networking/utls"
)

func netConnect2(d *protect.RDialer, proto string, ip netip.Addr, port int) (net.Conn, error) {
	if d == nil {
		log.E("rdial: netConnect: nil dialer")
		return nil, errNoDialer
	} else if !ipok(ip) {
		log.E("rdial: netConnect: invalid ip", ip)
		return nil, errNoIps
	}

	return (*d).Dial(proto, addrstr(ip, port))
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
	return unPtr(commondial(d, network, addr, adaptRDial(ipConnect)))
}

// SplitDial dials into addr splitting the first segment to two if the
// first connection is unsuccessful, using settings.DialStrategy.
// Returns a net.Conn, which may not be net.UDPConn or net.TCPConn.
func SplitDial(d *protect.RDial, network, addr string) (net.Conn, error) {
	return unPtr(commondial(d, network, addr, adaptRDial(splitIpConnect)))
}

// DialWithTls dials into addr using the provided dialer and returns a tls.Conn
func DialWithTls(d protect.RDialer, cfg *tls.Config, network, addr string) (net.Conn, error) {
	return dialtls(&d, cfg, network, addr, adaptRDialer(netConnect2))
}

func dialtls[D rdial](d D, cfg *tls.Config, network, addr string, how dialFn[D, *net.Conn]) (net.Conn, error) {
	c, err := unPtr(commondial(d, "tcp", addr, how))
	if err != nil {
		clos(c)
		return nil, err
	}

	tlsconn, err := tlsHello(c, cfg, addr)

	if eerr := new(tls.ECHRejectionError); errors.As(err, &eerr) {
		clos(tlsconn)

		ech := eerr.RetryConfigList
		log.I("rdial: tls: ech rejected; new? %d, err: %v", len(ech), eerr)
		if len(ech) > 0 { // retry with new ech
			cfg.EncryptedClientHelloConfigList = ech
			c, err = unPtr(commondial(d, network, addr, how))
			if err != nil {
				clos(c)
				return nil, err
			}
			tlsconn, err = tlsHello(c, cfg, addr)
		}
	}
	if err != nil {
		clos(tlsconn)
		tlsconn = nil
	}
	return tlsconn, err
}

// DialWithUTls dials a uTLS connection to addr and cfg.
func DialWithUTls(d *protect.RDial, cfg *utls.Config, network, addr string) (net.Conn, error) {
	c, err := unPtr(commondial(d, network, addr, adaptRDial(ipConnect)))
	if err != nil {
		clos(c)
		return nil, err
	}

	cfg = ensureSni2(cfg, addr)
	utlsConn, err := utlsHello(c, cfg, cfg.ServerName)
	if err != nil {
		clos(c)
		return nil, err
	}
	return utlsConn, nil
}

func tlsHello(c net.Conn, cfg *tls.Config, addr string) (*tls.Conn, error) {
	if c == nil || core.IsNil(c) {
		return nil, errNilConn
	}
	switch c := c.(type) {
	case *tls.Conn:
		return c, nil
	}

	tlsconn := tls.Client(c, ensureSni(cfg, addr))
	err := tlsconn.Handshake()

	if err != nil {
		clos(tlsconn)
	}
	return tlsconn, err
}

func ensureSni(cfg *tls.Config, addr string) *tls.Config {
	if cfg == nil {
		cfg = &tls.Config{
			ServerName: sni(addr),
			MinVersion: tls.VersionTLS12,
		}
	} else if len(cfg.ServerName) <= 0 {
		cfg.ServerName = sni(addr)
	}
	return cfg
}

func sni(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		log.W("rdial: sni %s, err: %v", addr, err)
		host = addr // may be ip
	}
	return host
}
