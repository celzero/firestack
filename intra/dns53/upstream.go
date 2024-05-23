// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dns53

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

const (
	Port       = "53"       // default DNS port
	PortU16    = uint16(53) // default DNS port as uint16
	DotPort    = "853"      // default DNS over TLS port
	timeout    = 5 * time.Second
	dottimeout = 8 * time.Second
)

var errQueryParse = errors.New("dns53: err parse query")

// TODO: Keep a context here so that queries can be canceled.
type transport struct {
	id       string
	addrport string // hostname, ip:port, protect.UidSelf, protect.System
	lastaddr string // last resolved addr
	status   int
	client   *dns.Client
	dialer   *protect.RDial
	proxies  ipn.Proxies // should never be nil
	relay    ipn.Proxy   // may be nil
	est      core.P2QuantileEstimator
}

var _ dnsx.Transport = (*transport)(nil)

// NewTransportFromHostname returns a DNS53 transport serving from hostname, ready for use.
func NewTransportFromHostname(id, hostname string, ipcsv string, px ipn.Proxies, ctl protect.Controller) (t *transport, err error) {
	// ipcsv may contain port, eg: 10.1.1.3:53
	do, err := settings.NewDNSOptionsFromHostname(hostname, ipcsv)
	if err != nil {
		return
	}
	return newTransport(id, do, px, ctl)
}

// NewTransport returns a DNS53 transport serving from ip & port, ready for use.
func NewTransport(id, ip, port string, px ipn.Proxies, ctl protect.Controller) (t *transport, err error) {
	ipport := net.JoinHostPort(ip, port)
	do, err := settings.NewDNSOptions(ipport)
	if err != nil {
		return
	}

	return newTransport(id, do, px, ctl)
}

func newTransport(id string, do *settings.DNSOptions, px ipn.Proxies, ctl protect.Controller) (*transport, error) {
	var relay ipn.Proxy
	// cannot be nil, see: ipn.Exit which the only proxy guaranteed to be connected to the internet;
	// ex: ipn.Base routed back within the tunnel (rethink's traffic routed back into rethink).
	if px == nil {
		return nil, dnsx.ErrNoProxyProvider
	}
	relay, _ = px.ProxyFor(id)
	d := protect.MakeNsRDial(id, ctl)
	tx := &transport{
		id:       id,
		addrport: do.AddrPort(), // may be hostname:port or ip:port
		status:   dnsx.Start,
		dialer:   d,
		proxies:  px,    // never nil; see above
		relay:    relay, // may be nil
		est:      core.NewP50Estimator(),
	}
	ipcsv := do.ResolvedAddrs()
	hasips := len(ipcsv) > 0
	ips := strings.Split(ipcsv, ",")               // may be nil or empty or ip:port
	ok := dnsx.RegisterAddrs(id, tx.addrport, ips) // addrport may be protect.UidSelf or protect.System
	log.I("dns53: (%s) pre-resolved %s to %s; ok? %t", id, tx.addrport, ipcsv, ok)
	tx.client = &dns.Client{
		Net:     "udp",   // default transport type
		Timeout: timeout, // default timeout
		// instead using custom dialer rdial
		// Dialer:  d,
		// TODO: set it to MTU? or no more than 512 bytes?
		// ref: github.com/miekg/dns/blob/b3dfea071/server.go#L207
		// UDPSize:        dns.DefaultMsgSize,
	}
	log.I("dns53: (%s) setup: %s; pre-ips? %t; relay? %t", id, tx.addrport, hasips, relay != nil)
	return tx, nil
}

// NewTransportFrom returns a DNS53 transport serving from ipp, ready for use.
func NewTransportFrom(id string, ipp netip.AddrPort, px ipn.Proxies, ctl protect.Controller) (t dnsx.Transport, err error) {
	do, err := settings.NewDNSOptionsFromNetIp(ipp)
	if err != nil {
		return
	}

	return newTransport(id, do, px, ctl)
}

func (t *transport) pxdial(network, pid string) (conn *dns.Conn, err error) {
	var px ipn.Proxy
	if t.relay != nil { // relay takes precedence
		px = t.relay
	} else if t.proxies != nil { // use proxy, if specified
		if px, err = t.proxies.ProxyFor(pid); err != nil {
			return
		}
	}
	if px == nil {
		return nil, dnsx.ErrNoProxyProvider
	}
	log.V("dns53: pxdial: (%s) using %s relay/proxy %s at %s", t.id, network, px.ID(), px.GetAddr())
	pxconn, err := px.Dialer().Dial(network, t.addrport)
	if err != nil {
		return
	} else if pxconn == nil {
		log.E("dns53: pxdial: (%s) no %s conn for relay/proxy %s at %s", t.id, network, px.ID(), px.GetAddr())
		err = errNoNet
		return
	}
	conn = &dns.Conn{Conn: pxconn}
	return
}

func (t *transport) dial(network string) (*dns.Conn, error) {
	// protect.dialers resolves t.addrport, if necessary
	// dialers.Dial fails to dial into tcp/udp conns w/ proxies like wgproxy
	// which only dial out to generic net.Conn for UDP and core.TCPConn for tcp
	c, err := dialers.Dial2(t.dialer, network, t.addrport)
	if err != nil {
		return nil, err
	} else if c == nil || core.IsNil(c) {
		return nil, errNoNet
	} else {
		return &dns.Conn{Conn: c}, nil
	}
}

// ref: github.com/celzero/midway/blob/77ede02c/midway/server.go#L179
func (t *transport) send(network, pid string, q *dns.Msg) (ans *dns.Msg, elapsed time.Duration, qerr *dnsx.QueryError) {
	var err error
	if q == nil || !xdns.HasAnyQuestion(q) {
		qerr = dnsx.NewBadQueryError(errQueryParse)
		return
	}

	var conn *dns.Conn

	useudp := network == dnsx.NetTypeUDP
	userelay := t.relay != nil
	useproxy := len(pid) != 0 // pid == dnsx.NetNoProxy => ipn.Base

	// if udp is unreachable, try tcp: github.com/celzero/rethink-app/issues/839
	// note that some proxies do not support udp (eg pipws, piph2)
	if userelay || useproxy {
		conn, err = t.pxdial(network, pid)
		if err != nil && useudp {
			log.E("dns53: send: udp %s pxdial(px? %t / relay? %t) failed %v", t.id, useproxy, userelay, err)
			network = dnsx.NetTypeTCP
			conn, err = t.pxdial(network, pid)
		}
	} else {
		conn, err = t.dial(network)
		if err != nil && useudp {
			log.E("dns53: send: udp %s dial failed %v", t.id, err)
			network = dnsx.NetTypeTCP
			conn, err = t.dial(network)
		}
	}

	log.V("dns53: send: (%s / %s) to %s using udp? %t / px? %t / relay? %t; err? %v", network, t.id, t.addrport, useudp, useproxy, userelay, err)

	if err != nil {
		qerr = dnsx.NewClientQueryError(err)
		return
	} // else: send query

	lastaddr := remoteAddrIfAny(conn) // may return empty string
	ans, elapsed, err = t.client.ExchangeWithConn(q, conn)
	clos(conn) // TODO: conn pooling w/ ExchangeWithConn

	if err != nil {
		log.V("dot: sendRequest: (%s) err: %v; disconfirm", t.id, err, lastaddr)
		dialers.Disconfirm2(t.addrport, lastaddr)
		qerr = dnsx.NewSendFailedQueryError(err)
	} else if ans == nil {
		qerr = dnsx.NewBadResponseQueryError(err)
	}

	t.lastaddr = lastaddr

	return
}

func (t *transport) Query(network string, q *dns.Msg, smm *x.DNSSummary) (ans *dns.Msg, err error) {
	proto, pid := xdns.Net2ProxyID(network)

	ans, elapsed, qerr := t.send(proto, pid, q)
	if qerr != nil { // only on send-request errors
		ans = xdns.Servfail(q)
	}

	status := dnsx.Complete
	if qerr != nil {
		err = qerr.Unwrap()
		status = qerr.Status()
		log.W("dns53: err(%v) / size(%d)", err, xdns.Len(ans))
	}
	t.status = status

	smm.Latency = elapsed.Seconds()
	smm.RData = xdns.GetInterestingRData(ans)
	smm.RCode = xdns.Rcode(ans)
	smm.RTtl = xdns.RTtl(ans)
	smm.Server = t.GetAddr()
	if t.relay != nil {
		smm.RelayServer = x.SummaryProxyLabel + t.relay.ID()
	} else if !dnsx.IsLocalProxy(pid) {
		smm.RelayServer = x.SummaryProxyLabel + pid
	}
	smm.Status = status
	t.est.Add(smm.Latency)

	log.V("dns53: len(res): %d, data: %s, via: %s, err? %v", xdns.Len(ans), smm.RData, smm.RelayServer, err)

	return ans, err
}

func (t *transport) ID() string {
	return t.id
}

func (t *transport) Type() string {
	return dnsx.DNS53
}

func (t *transport) P50() int64 {
	return t.est.Get()
}

func (t *transport) GetAddr() string {
	addr := t.lastaddr
	if len(addr) == 0 {
		// may be protect.UidSelf (for bootstrap/default) or protect.System
		addr = t.addrport
	}

	prefix := dnsx.PrefixFor(t.id)
	if len(prefix) > 0 {
		addr = prefix + addr
	}

	return addr
}

func (t *transport) Status() int {
	return t.status
}

func remoteAddrIfAny(conn *dns.Conn) string {
	if conn == nil || conn.Conn == nil {
		return ""
	} else if addr := conn.RemoteAddr(); addr == nil {
		return ""
	} else {
		return addr.String()
	}
}
