// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package settings

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/celzero/firestack/intra/log"
	"golang.org/x/net/proxy"
)

var (
	errDnsOptArg = errors.New("dnsopt: invalid arg")
)

// TODO: These modes could be covered by bit-flags instead.

const (
	// DNSModeNone does not redirect DNS queries sent to the tunnel.
	DNSModeNone int32 = 0
	// DNSModeIP redirects DNS requests sent to the IP endpoint set by VPN.
	DNSModeIP int32 = 1
	// DNSModePort redirects all DNS requests on port 53.
	DNSModePort int32 = 2
)

const (
	// BlockModeNone filters no packet.
	BlockModeNone int32 = 0
	// BlockModeFilter filters packets on connection establishment.
	BlockModeFilter int32 = 1
	// BlockModeSink blackholes all packets.
	BlockModeSink int32 = 2
	// BlockModeFilterProc determines owner-uid of a tcp/udp connection
	// from procfs before filtering
	BlockModeFilterProc int32 = 3
)

const (
	// PtModeAuto does not enforce (but may still use) 6to4 protocol translation.
	PtModeAuto int32 = 0
	// PtModeForce64 enforces 6to4 protocol translation.
	PtModeForce64 int32 = 1
	// Android implements 464Xlat out-of-the-box, so this zero userspace impl
	PtModeNo46 int32 = 2
)

// msb to lsb: ipv6, ipv4, lwip(1) or netstack(0)
const (
	Ns4  = 0b010 // 2
	Ns46 = 0b110 // 6
	Ns6  = 0b100 // 4
)

// IP4, IP46, IP6 are string'd repr of Ns4, Ns46, Ns6
const (
	IP4  = "4"
	IP46 = "46"
	IP6  = "6"
)

// NICID is the default network interface card ID for the network stack.
const NICID = 0x01

// Debug is a global flag to enable debug behaviour.
var Debug bool = false

// Loopingback is a global flag to adjust netstack behaviour
// wrt preventing split dialing, closing tunfd without delay etc.
var Loopingback = atomic.Bool{}

// SingleThreaded is a global flag to run Netstack's packet forwarder
// in a single-threaded mode.
var SingleThreaded = atomic.Bool{}

// EndpointIndependentMapping is a global flag to enable endpoint-independent
// mapping for UDP as per RFC 4787.
var EndpointIndependentMapping = atomic.Bool{}

// EndpointIndependentFiltering is a global flag to enable endpoint-independent
// filtering for UDP as per RFC 4787.
var EndpointIndependentFiltering = atomic.Bool{}

// L3 returns the string'd repr of engine.
func L3(engine int) string {
	switch engine {
	case Ns46:
		return IP46
	case Ns6:
		return IP6
	default:
		return IP4
	}
}

// TunMode specifies dns, firewall, xlat, and ip modes
type TunMode struct {
	// DNSMode specifies the kind of DNS traffic to be trapped and routed to DoH servers
	DNSMode atomic.Int32
	// BlockMode instructs change in firewall behaviour.
	BlockMode atomic.Int32
	// PtMode determines 6to4 translation heuristics.
	PtMode atomic.Int32
}

// SetMode re-assigns d to DNSMode, b to BlockMode, pt to NatPtMode.
func (t *TunMode) SetMode(d, b, pt int32) {
	t.DNSMode.Store(d)
	t.BlockMode.Store(b)
	t.PtMode.Store(pt)
}

// NewTunMode returns a new TunMode object.
// `d` sets dns-mode.
// `b` sets block-mode.
// `pt` sets natpt-mode.
func NewTunMode(d, b, pt int32) *TunMode {
	tm := &TunMode{}
	tm.DNSMode.Store(d)
	tm.BlockMode.Store(b)
	tm.PtMode.Store(pt)
	return tm
}

// DefaultTunMode returns a new default TunMode with
// IP-only DNS capture and replay (not all DNS traffic but
// only the DNS traffic sent to [tcp/udp]handler.fakedns
// is captured and replayed to the remote DoH server)
// and with firewall disabled.
func DefaultTunMode() *TunMode {
	return NewTunMode(DNSModeIP, BlockModeNone, PtModeNo46)
}

// DNSOptions define https or socks5 proxy options
type DNSOptions struct {
	ipp      string
	hostport string
	hostips  string
}

func (d *DNSOptions) String() string {
	return d.AddrPort()
}

// AddrPort returns the ip:port or host:port.
func (d *DNSOptions) AddrPort() string {
	if len(d.ipp) > 0 {
		return d.ipp
	}
	if len(d.hostport) > 0 {
		return d.hostport
	}
	return ""
}

func (d *DNSOptions) ResolvedAddrs() string {
	return d.hostips // TODO: may be ip:port
}

// Parse ip and port; where ip can be either ip:port or ip
func addrport(ip string, port string) (ipp netip.AddrPort, err error) {
	var ipaddr netip.Addr
	var p int
	if ipaddr, err = netip.ParseAddr(ip); err == nil {
		if p, err = strconv.Atoi(port); err == nil {
			ipp = netip.AddrPortFrom(ipaddr.Unmap(), uint16(p))
			return ipp, nil
		}
	} else if ipp, err = netip.ParseAddrPort(ip); err == nil {
		return ipp, nil
	}
	return ipp, err
}

// NewDNSOptions returns a new DNSOpitons object.
func NewDNSOptions(ipport string) (*DNSOptions, error) {
	var ipp netip.AddrPort
	var err error
	ip, port, err := net.SplitHostPort(ipport)
	if err != nil {
		return nil, err
	}
	if ipp, err = addrport(ip, port); err == nil {
		return &DNSOptions{
			ipp: ipp.String(),
		}, nil
	}
	log.D("dnsopt(%s:%s); err(%v)", ip, port, err)
	return nil, err
}

func NewDNSOptionsFromNetIp(ipp netip.AddrPort) (*DNSOptions, error) {
	if !ipp.IsValid() {
		return nil, errors.New("dnsopt: empty ipport")
	}
	return &DNSOptions{
		ipp: ipp.String(),
	}, nil
}

func NewDNSOptionsFromHostname(hostOrHostPort, ipcsv string) (*DNSOptions, error) {
	if len(hostOrHostPort) <= 0 {
		return nil, errDnsOptArg
	}

	domain, port, _ := net.SplitHostPort(hostOrHostPort)
	if len(domain) <= 0 {
		domain = hostOrHostPort
	}
	if len(port) == 0 {
		port = "53"
	}

	return &DNSOptions{
		hostport: net.JoinHostPort(domain, port),
		hostips:  ipcsv, // may be empty, and may be ip:port
	}, nil
}

// ProxyOptions define https or socks5 proxy options
type ProxyOptions struct {
	Auth   *proxy.Auth
	IP     string   // just the ip
	Host   string   // just the hostname (no port)
	Port   string   // just the port number
	IPPort string   // may be a url or ip:port
	Scheme string   // http, https, socks5, pip
	Addrs  []string // list of ips if ipport is a url; may be nil
}

// NewAuthProxyOptions returns a new ProxyOptions object with authentication object.
func NewAuthProxyOptions(scheme, username, password, ip, port string, addrs []string) *ProxyOptions {
	var ippstr string
	var ipstr string
	var host string
	ip = strings.TrimSuffix(ip, "/")
	ipp, err := addrport(ip, port)
	if err != nil {
		log.I("proxyopt: scheme %s; ipport(%s:%s) is url?(%v)", scheme, ip, port, err)
		if len(ip) > 0 {
			// port is discarded, and expected to be in ip/url
			ippstr = ip
			host, port, _ = net.SplitHostPort(ip)
		} else if len(port) > 0 {
			// incoming ip,port is a wildcard address
			ippstr = ":" + port
		} else {
			return nil
		}
	} else {
		ippstr = ipp.String()
		ipstr = ipp.Addr().String()
	}
	if len(username) <= 0 || len(password) <= 0 {
		log.I("proxyopt: no user(%s) and/or pwd(%d)", username, len(password))
	}
	if len(scheme) <= 0 {
		scheme = "http"
	}
	// todo: query unescape username and password?
	auth := proxy.Auth{
		User:     username,
		Password: password,
	}
	return &ProxyOptions{
		Auth:   &auth,
		Host:   host,   // may be empty or hostname (without port)
		IP:     ipstr,  // may be empty or ipaddr
		Port:   port,   // port number
		IPPort: ippstr, // mmay be ip4:port, [ip::6]:port, host:port, or :port
		Scheme: scheme,
		Addrs:  addrs,
	}
}

// NewProxyOptions returns a new ProxyOptions object.
func NewProxyOptions(ip string, port string) *ProxyOptions {
	return NewAuthProxyOptions("" /*scheme*/, "" /*user*/, "" /*password*/, ip, port /*addrs*/, nil)
}

func (p *ProxyOptions) String() string {
	return p.Auth.User + "," + p.Auth.Password + "," + p.IPPort
}

// HasAuth returns true if p has auth params.
func (p *ProxyOptions) HasAuth() bool {
	return len(p.Auth.User) > 0 && len(p.Auth.Password) > 0
}

// FullUrl returns the full url with auth.
func (p *ProxyOptions) FullUrl() string {
	if p.HasAuth() {
		// superuser.com/a/532530
		usr := url.QueryEscape(p.Auth.User)
		pwd := url.QueryEscape(p.Auth.Password)
		return p.Scheme + "://" + usr + ":" + pwd + "@" + p.IPPort
	} else if len(p.Auth.User) > 0 {
		usr := url.QueryEscape(p.Auth.User)
		return p.Scheme + "://" + usr + "@" + p.IPPort
	}
	return p.Url()
}

// Url returns the url without auth.
func (p *ProxyOptions) Url() string {
	return p.Scheme + "://" + p.IPPort
}

// DialerOpts define dialer options.
type DialerOpts struct {
	// Strat is the dialing strategy.
	Strat int32
	// Retry is the retry strategy.
	Retry int32
	// LowerKeepAlive is the flag to enable low TCP keep-alive.
	// Currently, 180s for idle, 5s for interval, and 4 probes.
	LowerKeepAlive bool
}

func newDialerOpts() *DialerOpts {
	return &DialerOpts{}
}

func (d DialerOpts) String() string {
	s := func() string {
		switch d.Strat {
		case SplitAuto:
			return "SplitAuto"
		case SplitTCP:
			return "SplitTCP"
		case SplitTCPOrTLS:
			return "SplitTCPOrTLS"
		case SplitDesync:
			return "SplitDesync"
		case SplitNever:
			return "SplitNever"
		default:
			return "Unknown"
		}
	}()
	r := func() string {
		switch d.Retry {
		case RetryNever:
			return "RetryNever"
		case RetryWithSplit:
			return "RetryWithSplit"
		case RetryAfterSplit:
			return "RetryAfterSplit"
		default:
			return "Unknown"
		}
	}()
	ka := func() string {
		if d.LowerKeepAlive {
			return "LowerKeepAlive"
		}
		return ""
	}()

	return strings.Join([]string{s, r, ka}, ",")
}

// Dial strategies
const (
	SplitAuto int32 = iota
	SplitTCPOrTLS
	SplitTCP
	SplitDesync
	SplitNever
)

// Retry strategies
const (
	RetryAfterSplit int32 = iota
	RetryWithSplit
	RetryNever
)

var dialerOpts = newDialerOpts()

// SetDialerOpts sets the dialer options to use.
func SetDialerOpts(strat, retry int32, keepalive bool) bool {
	s := dialerOpts
	ok := true
	switch strat {
	case SplitTCP, SplitTCPOrTLS, SplitDesync, SplitAuto, SplitNever:
		s.Strat = strat
	default:
		s.Strat = SplitAuto
		ok = false
	}
	switch retry {
	case RetryNever, RetryWithSplit, RetryAfterSplit:
		s.Retry = retry
	default:
		s.Retry = RetryAfterSplit
		ok = false
	}
	s.LowerKeepAlive = keepalive
	return ok
}

// GetDialerOpts returns current dialer options.
func GetDialerOpts() DialerOpts {
	return *dialerOpts
}
