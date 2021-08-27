// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package settings

import (
	"net/url"
	"strings"

	"golang.org/x/net/proxy"
)

// TODO: These modes could be covered by bit-flags instead.

// DNSModeNone does no redirects of DNS queries sent to the tunnel.
const DNSModeNone = 0

// DNSModeIP redirects DNS requests sent to the IP endpoint set by VPN.
const DNSModeIP int = 1

// DNSModePort redirects all DNS requests on port 53.
const DNSModePort int = 2

// DNSModeCryptIP redirects DNS requests sent to the IP endpoint set by VPN to DNSCrypt
const DNSModeCryptIP int = 3

// DNSModeCryptPort redirects all DNS requests on port 53 to DNSCrypt.
const DNSModeCryptPort int = 4

// DNSModeProxyIP redirects DNS requests sent to the IP endpoint set by VPN to a DNS Proxy.
const DNSModeProxyIP int = 5

// DNSModeProxyPort redirects all DNS requests on port 53 to a DNS proxy.
const DNSModeProxyPort int = 6

// BlockModeNone filters no packet.
const BlockModeNone int = 0

// BlockModeFilter filters packets on connection establishment.
const BlockModeFilter int = 1

// BlockModeSink blackholes all packets.
const BlockModeSink int = 2

// BlockModeFilterProc determines owner-uid of a tcp/udp connection
// from procfs before filtering
const BlockModeFilterProc int = 3

// ProxyModeNone forwards nothing.
const ProxyTypeNone int = 0

// ProxyModeSOCKS5 forwards connections to a SOCKS5 endpoint.
const ProxyTypeSOCKS5 int = 1

// ProxyModeHTTPS forwards HTTP connections to a HTTP proxy.
const ProxyTypeHTTP int = 2

// TunMode specifies blocking and dns modes
type TunMode struct {
	// DNSMode specifies the kind of DNS traffic to be trapped and routed to DoH servers
	DNSMode int
	// BlockMode instructs change in firewall behaviour.
	BlockMode int
}

// DNSOptions define https or socks5 proxy options
type DNSOptions struct {
	IPPort string
}

// ProxyOptions define https or socks5 proxy options
type ProxyOptions struct {
	Id     string
	Typ    int
	Auth   *proxy.Auth
	IPPort string
}

// SetMode re-assigns d to DNSMode, b to BlockMode, and p to ProxyMode
func (t *TunMode) SetMode(d, b int) {
	t.DNSMode = d
	t.BlockMode = b
}

// NewTunMode returns a new TunMode object.
// `d` sets dns-mode.
// `b` sets block-mode.
func NewTunMode(d, b int) *TunMode {
	return &TunMode{
		DNSMode:   d,
		BlockMode: b,
	}
}

// DefaultTunMode returns a default TunMode object with
// IP-only DNS capture and replay (not all DNS traffic but
// only the DNS traffic sent to [tcp/udp]handler.fakedns
// is captured and replayed to the remote DoH server)
// and with firewall disabled.
func DefaultTunMode() *TunMode {
	return &TunMode{
		DNSMode:   DNSModeIP,
		BlockMode: BlockModeNone,
	}
}

// NewDNSOptions returns a new DNSOpitons object.
func NewDNSOptions(ip, port string) *DNSOptions {
	// TODO: validate IP and port, protocol
	return &DNSOptions{
		IPPort: ip + ":" + port,
	}
}

func (d *DNSOptions) String() string {
	ipport := strings.Split(d.IPPort, ":")
	return ipport[0] + "," + ipport[1]
}

// NewAuthProxyOptions returns a new ProxyOptions object with authentication object.
func NewAuthProxyOptions(typ int, id, username, password, ip, port string) *ProxyOptions {
	if len(username) <= 0 || len(password) <= 0 {
		return NewProxyOptions(typ, id, ip, port)
	}
	auth := proxy.Auth{
		User:     username,
		Password: password,
	}
	// TODO: validate typ, IP and port, protocol
	return &ProxyOptions{
		Id:     id,
		Typ:    typ,
		Auth:   &auth,
		IPPort: ip + ":" + port,
	}
}

// NewAuthProxyOptions returns a new ProxyOptions object with authentication object.
func NewEmptyAuthProxyOptions(id string) *ProxyOptions {
	// TODO: validate typ, IP and port, protocol
	return &ProxyOptions{
		Id:  id,
		Typ: ProxyTypeNone,
	}
}

// NewProxyOptions returns a new ProxyOptions object.
func NewProxyOptions(typ int, id, ip, port string) *ProxyOptions {
	// TODO: validate typ, IP and port, protocol
	return &ProxyOptions{
		Id:     id,
		Typ:    typ,
		Auth:   nil,
		IPPort: ip + ":" + port,
	}
}

func (p *ProxyOptions) IsSocks5() bool {
	return p.Typ == ProxyTypeSOCKS5
}

func (p *ProxyOptions) IsHttp() bool {
	return p.Typ == ProxyTypeHTTP
}

func (p *ProxyOptions) IsGrounded() bool {
	return len(p.IPPort) == 0 || p.Typ == ProxyTypeNone
}

func (p *ProxyOptions) Url() *url.URL {
	return &url.URL{
		Scheme: p.Scheme(),
		Opaque: "",
		User:   url.UserPassword(p.Auth.User, p.Auth.Password),
		Host:   p.IPPort,
	}
}

func (p *ProxyOptions) Scheme() string {
	switch p.Typ {
	case ProxyTypeSOCKS5:
		return "socks5"
	case ProxyTypeHTTP:
		return "http"
	case ProxyTypeNone:
		return "none"
	default:
		return ""
	}
}

func (p *ProxyOptions) String() string {
	return p.Url().String()
}
