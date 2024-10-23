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

func netConnect2(d *protect.RDialer, proto string, laddr, raddr netip.AddrPort) (net.Conn, error) {
	if d == nil {
		log.E("rdial: netConnect: nil dialer")
		return nil, errNoDialer
	} else if !ipok(raddr.Addr()) {
		log.E("rdial: netConnect: invalid ip", raddr)
		return nil, errNoIps
	}

	if laddr.IsValid() {
		return (*d).DialBind(proto, laddr.String(), raddr.String())
	} else {
		return (*d).Dial(proto, raddr.String())
	}
}

// ipConnect dials into ip:port using the provided dialer and returns a net.Conn
// net.Conn is guaranteed to be either net.UDPConn or net.TCPConn
func ipConnect(d *protect.RDial, proto string, laddr, raddr netip.AddrPort) (net.Conn, error) {
	if d == nil {
		log.E("rdial: ipConnect: nil dialer")
		return nil, errNoDialer
	} else if !ipok(raddr.Addr()) {
		log.E("rdial: ipConnect: invalid ip", raddr)
		return nil, errNoIps
	}

	if laddr.IsValid() {
		switch proto {
		case "tcp", "tcp4", "tcp6":
			return d.DialTCP(proto, net.TCPAddrFromAddrPort(laddr), net.TCPAddrFromAddrPort(raddr))
		case "udp", "udp4", "udp6":
			return d.DialUDP(proto, net.UDPAddrFromAddrPort(laddr), net.UDPAddrFromAddrPort(raddr))
		default:
			return d.DialBind(proto, laddr.String(), raddr.String())
		}
	} else {
		switch proto {
		case "tcp", "tcp4", "tcp6":
			return d.DialTCP(proto, nil, net.TCPAddrFromAddrPort(raddr))
		case "udp", "udp4", "udp6":
			return d.DialUDP(proto, nil, net.UDPAddrFromAddrPort(raddr))
		default:
			return d.Dial(proto, raddr.String())
		}
	}
}

func doSplit(ipp netip.AddrPort) bool {
	ip := ipp.Addr()
	port := ipp.Port()
	// HTTPS or DoT
	return !ip.IsPrivate() && (port == 443 || port == 853)
}

func splitIpConnect(d *protect.RDial, proto string, laddr, raddr netip.AddrPort) (net.Conn, error) {
	if d == nil {
		log.E("rdial: splitIpConnect: nil dialer")
		return nil, errNoDialer
	} else if !ipok(raddr.Addr()) {
		log.E("rdial: splitIpConnect: invalid ip", raddr)
		return nil, errNoIps
	}

	if laddr.IsValid() {
		switch proto {
		case "tcp", "tcp4", "tcp6":
			remote := net.TCPAddrFromAddrPort(raddr)
			local := net.TCPAddrFromAddrPort(laddr)
			if doSplit(raddr) {
				return DialWithSplitRetry(d, local, remote)
			}
			return d.DialTCP(proto, local, remote)
		case "udp", "udp4", "udp6":
			remote := net.UDPAddrFromAddrPort(raddr)
			local := net.UDPAddrFromAddrPort(laddr)
			return d.DialUDP(proto, local, remote)
		default:
			return d.DialBind(proto, laddr.String(), raddr.String())
		}
	} else {
		switch proto {
		case "tcp", "tcp4", "tcp6":
			tcpaddr := net.TCPAddrFromAddrPort(raddr)
			if doSplit(raddr) {
				return DialWithSplitRetry(d, nil, tcpaddr)
			}
			return d.DialTCP(proto, nil, tcpaddr)
		case "udp", "udp4", "udp6":
			return d.DialUDP(proto, nil, net.UDPAddrFromAddrPort(raddr))
		default:
			return d.Dial(proto, raddr.String())
		}
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

func DialBind(d *protect.RDial, network, local, remote string) (net.Conn, error) {
	return unPtr(commondial2(d, network, local, remote, adaptRDial(ipConnect)))
}

func SplitDialBind(d *protect.RDial, network, local, remote string) (net.Conn, error) {
	return unPtr(commondial2(d, network, local, remote, adaptRDial(splitIpConnect)))
}

// DialWithTls dials into addr using the provided dialer and returns a tls.Conn
func DialWithTls(d protect.RDialer, cfg *tls.Config, network, addr string) (net.Conn, error) {
	return dialtls(&d, cfg, network, "", addr, adaptRDialer(netConnect2))
}

// DialWithTls dials into addr using the provided dialer and returns a tls.Conn
func DialBindWithTls(d protect.RDialer, cfg *tls.Config, network, local, remote string) (net.Conn, error) {
	return dialtls(&d, cfg, network, local, remote, adaptRDialer(netConnect2))
}

func dialtls[D rdials](d D, cfg *tls.Config, network, local, remote string, how dialFn[D, *net.Conn]) (net.Conn, error) {
	c, err := unPtr(commondial2(d, network, local, remote, how))
	if err != nil {
		clos(c)
		return nil, err
	}

	tlsconn, err := tlsHello(c, cfg, remote)

	if eerr := new(tls.ECHRejectionError); errors.As(err, &eerr) {
		clos(tlsconn)

		ech := eerr.RetryConfigList
		log.I("rdial: tls: ech rejected; new? %d, err: %v", len(ech), eerr)
		if len(ech) > 0 { // retry with new ech
			cfg.EncryptedClientHelloConfigList = ech
			c, err = unPtr(commondial2(d, network, local, remote, how))
			if err != nil {
				clos(c)
				return nil, err
			}
			tlsconn, err = tlsHello(c, cfg, remote)
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
