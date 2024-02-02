// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dns53

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

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
	Port       = "53"
	PortU16    = uint16(53)
	DotPort    = "853"
	timeout    = 5 * time.Second
	dottimeout = 8 * time.Second
)

var errQueryParse = errors.New("dns53: err parse query")

// TODO: Keep a context here so that queries can be canceled.
type transport struct {
	id       string
	addrport string
	status   int
	client   *dns.Client
	dialer   *protect.RDial
	proxies  ipn.Proxies // should never be nil
	relay    ipn.Proxy   // may be nil
	est      core.P2QuantileEstimator
}

var _ dnsx.Transport = (*transport)(nil)

func NewTransportFromHostname(id, hostname string, ipcsv string, px ipn.Proxies, ctl protect.Controller) (t dnsx.Transport, err error) {
	// ipcsv may contain port, eg: 10.1.1.3:53
	do, err := settings.NewDNSOptionsFromHostname(hostname, ipcsv)
	if err != nil {
		return
	}
	return newTransport(id, do, px, ctl)
}

// NewTransport returns a DNS transport, ready for use.
func NewTransport(id, ip, port string, px ipn.Proxies, ctl protect.Controller) (t dnsx.Transport, err error) {
	ipport := net.JoinHostPort(ip, port)
	do, err := settings.NewDNSOptions(ipport)
	if err != nil {
		return
	}

	return newTransport(id, do, px, ctl)
}

func newTransport(id string, do *settings.DNSOptions, px ipn.Proxies, ctl protect.Controller) (dnsx.Transport, error) {
	var relay ipn.Proxy
	// cannot be nil, see: ipn.Exit which the only proxy guaranteed to be connected to the internet;
	// ex: ipn.Base routed back within the tunnel (rethink's traffic routed back into rethink).
	if px == nil {
		return nil, dnsx.ErrNoProxyProvider
	}
	relay, _ = px.GetProxy(id)
	d := protect.MakeNsRDial(id, ctl)
	tx := &transport{
		id:       id,
		addrport: do.AddrPort(), // may be hostname:port or ip:port
		status:   dnsx.Start,
		dialer:   d,
		proxies:  px,    // may be nil; see above
		relay:    relay, // may be nil
		est:      core.NewP50Estimator(),
	}
	ipcsv := do.ResolvedAddrs()
	hasips := len(ipcsv) > 0
	ips := strings.Split(ipcsv, ",") // may be nil or empty
	ok := dialers.Renew(tx.addrport, ips)
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

// NewTransport returns a DNS transport, ready for use.
func NewTransportFrom(id string, ipp netip.AddrPort, px ipn.Proxies, ctl protect.Controller) (t dnsx.Transport, err error) {
	do, err := settings.NewDNSOptionsFromNetIp(ipp)
	if err != nil {
		return
	}

	return newTransport(id, do, px, ctl)
}

// Given a raw DNS query (including the query ID), this function sends the
// query.  If the query is successful, it returns the response and a nil qerr.  Otherwise,
// it returns a SERVFAIL response and a qerr with a status value indicating the cause.
func (t *transport) doQuery(network, pid string, q []byte) (response []byte, elapsed time.Duration, qerr *dnsx.QueryError) {
	if len(q) < 2 {
		qerr = dnsx.NewBadQueryError(fmt.Errorf("dns53: query length is %d", len(q)))
		return
	}

	response, elapsed, qerr = t.send(network, pid, q)

	if qerr != nil { // only on send-request errors
		response = xdns.Servfail(q)
	}

	return
}

func (t *transport) pxdial(network, pid string) (conn *dns.Conn, err error) {
	var px ipn.Proxy
	if t.relay != nil { // relay takes precedence
		px = t.relay
	} else if t.proxies != nil { // use proxy, if specified
		if px, err = t.proxies.GetProxy(pid); err != nil {
			return
		}
	}
	if px == nil {
		return nil, dnsx.ErrNoProxyProvider
	}
	log.V("dns53: pxdial: (%s) using %s relay/proxy %s at %s", t.id, network, px.ID(), px.GetAddr())
	pxconn, err := dialers.Dial2(px.Dialer(), network, t.addrport) // resolves t.addrport if necessary
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
	if c, err := dialers.Dial2(t.dialer, network, t.addrport); err == nil {
		return &dns.Conn{Conn: c}, nil
	} else {
		return nil, err
	}
}

// ref: github.com/celzero/midway/blob/77ede02c/midway/server.go#L179
func (t *transport) send(network, pid string, q []byte) (response []byte, elapsed time.Duration, qerr *dnsx.QueryError) {
	var ans *dns.Msg
	var err error
	msg := xdns.AsMsg(q)
	if msg == nil {
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

	if err == nil { // send query
		ans, elapsed, err = t.client.ExchangeWithConn(msg, conn)
		clos(conn) // TODO: conn pooling w/ ExchangeWithConn
		if err != nil {
			qerr = dnsx.NewSendFailedQueryError(err)
		} else if ans == nil {
			qerr = dnsx.NewBadResponseQueryError(err)
		} else {
			response, err = ans.Pack()
			if err != nil { // cannot dial or err packing
				qerr = dnsx.NewBadResponseQueryError(err)
			}
		}
		return
	} else {
		qerr = dnsx.NewClientQueryError(err)
		return
	}
}

func (t *transport) Query(network string, q []byte, smm *dnsx.Summary) (r []byte, err error) {
	proto, pid := xdns.Net2ProxyID(network)
	response, elapsed, qerr := t.doQuery(proto, pid, q)

	status := dnsx.Complete
	if qerr != nil {
		err = qerr.Unwrap()
		status = qerr.Status()
		log.W("dns53: err(%v) / size(%d)", err, len(response))
	}
	ans := xdns.AsMsg(response)
	t.status = status

	smm.Latency = elapsed.Seconds()
	smm.RData = xdns.GetInterestingRData(ans)
	smm.RCode = xdns.Rcode(ans)
	smm.RTtl = xdns.RTtl(ans)
	smm.Server = t.GetAddr()
	if t.relay != nil {
		smm.RelayServer = t.relay.GetAddr()
	} else if !dnsx.IsLocalProxy(pid) {
		smm.RelayServer = dnsx.SummaryProxyLabel + pid
	}
	smm.Status = status
	t.est.Add(smm.Latency)

	log.V("dns53: len(res): %d, data: %s, via: %s, err? %v", len(response), smm.RData, smm.RelayServer, err)

	return response, err
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
	return t.addrport
}

func (t *transport) Status() int {
	return t.status
}
