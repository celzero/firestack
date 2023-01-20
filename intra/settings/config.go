// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package settings

import (
	"errors"
	"net/netip"
	"strconv"

	"github.com/celzero/firestack/intra/log"
	"golang.org/x/net/proxy"
)

// TODO: These modes could be covered by bit-flags instead.

// DNSModeNone does not redirect DNS queries sent to the tunnel.
const DNSModeNone = 0

// DNSModeIP redirects DNS requests sent to the IP endpoint set by VPN.
const DNSModeIP int = 1

// DNSModePort redirects all DNS requests on port 53.
const DNSModePort int = 2

// BlockModeNone filters no packet.
const BlockModeNone int = 0

// BlockModeFilter filters packets on connection establishment.
const BlockModeFilter int = 1

// BlockModeSink blackholes all packets.
const BlockModeSink int = 2

// BlockModeFilterProc determines owner-uid of a tcp/udp connection
// from procfs before filtering
const BlockModeFilterProc int = 3

// ProxyModeNone forwards no packet.
const ProxyModeNone int = 0

// ProxyModeSOCKS5 forwards packets to a SOCKS5 endpoint.
const ProxyModeSOCKS5 int = 1

// ProxyModeHTTPS forwards packets to a HTTPS proxy.
const ProxyModeHTTPS int = 2

// PtModeAuto does not enforce (but may still use) 6to4 protocol translation.
const PtModeAuto int = 0

// PtModeForce64 enforces 6to4 protocol translation.
const PtModeForce64 int = 1

// Android implements 464Xlat out-of-the-box, so this zero userspace impl
const PtModeMaybe46 int = 2

// msb to lsb: ipv6, ipv4, lwip(1) or netstack(0)
const Ns4 = 0b010  // 2
const Ns46 = 0b110 // 6
const Ns6 = 0b100  // 4

const IP4 = "4"
const IP46 = "46"
const IP6 = "6"

const NICID = 0x01

func L3(w int) string {
	switch w {
	case Ns46:
		return IP46
	case Ns6:
		return IP6
	default:
		return IP4
	}
}

// TunMode specifies blocking and dns modes
type TunMode struct {
	// DNSMode specifies the kind of DNS traffic to be trapped and routed to DoH servers
	DNSMode int
	// BlockMode instructs change in firewall behaviour.
	BlockMode int
	// ProxyMode determines where the traffic is forwarded to.
	ProxyMode int
	// PtMode determines overrides 6to4 translation heuristics.
	PtMode int
}

// DNSOptions define https or socks5 proxy options
type DNSOptions struct {
	IPPort string
}

// ProxyOptions define https or socks5 proxy options
type ProxyOptions struct {
	Auth   *proxy.Auth
	IPPort string
}

// SetMode re-assigns d to DNSMode, b to BlockMode, and p to ProxyMode
func (t *TunMode) SetMode(d int, b int, p int, pt int) {
	t.DNSMode = d
	t.BlockMode = b
	t.ProxyMode = p
	t.PtMode = pt
}

// NewTunMode returns a new TunMode object.
// `d` sets dns-mode.
// `b` sets block-mode.
// `p` sets proxy-mode.
func NewTunMode(d int, b int, p int, pt int) *TunMode {
	return &TunMode{
		DNSMode:   d,
		BlockMode: b,
		ProxyMode: p,
		PtMode:    pt,
	}
}

// DefaultTunMode returns a new default TunMode with
// IP-only DNS capture and replay (not all DNS traffic but
// only the DNS traffic sent to [tcp/udp]handler.fakedns
// is captured and replayed to the remote DoH server)
// and with firewall disabled.
func DefaultTunMode() *TunMode {
	return &TunMode{
		DNSMode:   DNSModeIP,
		BlockMode: BlockModeNone,
		ProxyMode: ProxyModeNone,
		PtMode:    PtModeAuto,
	}
}

func addrport(ip string, port string) (*netip.AddrPort, error) {
	var ipaddr netip.Addr
	var p int
	var err error
	if ipaddr, err = netip.ParseAddr(ip); err == nil {
		if p, err = strconv.Atoi(port); err == nil {
			ipp := netip.AddrPortFrom(ipaddr, uint16(p))
			return &ipp, nil
		}
	}
	return nil, err
}

// NewDNSOptions returns a new DNSOpitons object.
func NewDNSOptions(ip string, port string) (*DNSOptions, error) {
	var ipp *netip.AddrPort
	var err error
	if ipp, err = addrport(ip, port); err == nil {
		return &DNSOptions{
			IPPort: ipp.String(),
		}, nil
	}
	log.Warnf("dnsopt(%s:%s); err(%v)", ip, port, err)
	return nil, err
}

func NewDNSOptionsFromNetIp(ipp netip.AddrPort) (*DNSOptions, error) {
	if !ipp.IsValid() {
		return nil, errors.New("dnsopt: empty ipport")
	}
	return &DNSOptions{
		IPPort: ipp.String(),
	}, nil
}

// NewAuthProxyOptions returns a new ProxyOptions object with authentication object.
func NewAuthProxyOptions(username string, password string, ip string, port string) *ProxyOptions {
	ipp, err := addrport(ip, port)
	if err != nil {
		log.Warnf("proxyopt(%s:%s); ipport invalid(%v)", ip, port, err)
		return nil
	}
	if len(username) <= 0 || len(password) <= 0 {
		username = ""
		password = ""
		log.Warnf("proxyopt; empty user(%s)/pwd(%d)", username, len(password))
	}
	auth := proxy.Auth{
		User:     username,
		Password: password,
	}
	return &ProxyOptions{
		Auth:   &auth,
		IPPort: ipp.String(),
	}
}

// NewProxyOptions returns a new ProxyOptions object.
func NewProxyOptions(ip string, port string) *ProxyOptions {
	return NewAuthProxyOptions("" /*user*/, "" /*password*/, ip, port)
}

func (d *DNSOptions) String() string {
	return d.IPPort
}

func (p *ProxyOptions) String() string {
	return p.Auth.User + "," + p.Auth.Password + "," + p.IPPort
}
