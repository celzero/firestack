// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dns53

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/celzero/firestack/intra/core"
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
	DotPort    = "853"
	timeout    = 5 * time.Second
	dottimeout = 8 * time.Second
)

var errQueryParse = errors.New("dns53: err parse query")

// TODO: Keep a context here so that queries can be canceled.
type transport struct {
	id      string
	addr    string
	status  int
	mcudp   *dns.Client
	mctcp   *dns.Client
	proxies ipn.Proxies // may be nil; esp for id == dnsx.System
	relay   ipn.Proxy   // may be nil
	est     core.P2QuantileEstimator
}

var _ dnsx.Transport = (*transport)(nil)

func NewTransportFromHostname(id, hostname string, px ipn.Proxies) (t dnsx.Transport, err error) {
	do, err := settings.NewDNSOptionsFromHostname(hostname)
	if err != nil {
		return
	}
	return newTransport(id, do, px)
}

// NewTransport returns a DNS transport, ready for use.
func NewTransport(id, ip, port string, px ipn.Proxies) (t dnsx.Transport, err error) {
	do, err := settings.NewDNSOptions(ip, port)
	if err != nil {
		return
	}

	return newTransport(id, do, px)
}

func newTransport(id string, do *settings.DNSOptions, px ipn.Proxies) (dnsx.Transport, error) {
	var relay ipn.Proxy
	if px != nil {
		relay, _ = px.GetProxy(id)
	}
	tx := &transport{
		id:      id,
		addr:    do.IPPort, // may be host:port or ip:port
		status:  dnsx.Start,
		proxies: px,    // may be nil; see above
		relay:   relay, // may be nil
		est:     core.NewP50Estimator(),
	}
	// todo: with controller
	d := protect.MakeNsDialer(id, nil)
	tx.mcudp = &dns.Client{
		Net:            "udp",
		Dialer:         d,
		Timeout:        timeout,
		SingleInflight: true,
		// TODO: set it to MTU? or no more than 512 bytes?
		// ref: github.com/miekg/dns/blob/b3dfea071/server.go#L207
		// UDPSize:        dns.DefaultMsgSize,
	}
	tx.mctcp = &dns.Client{
		Net:            "tcp",
		Dialer:         d,
		Timeout:        timeout,
		SingleInflight: true,
	}
	log.I("dns53: (%s) setup: %s; relay? %t", id, do.IPPort, relay != nil)
	return tx, nil
}

// NewTransport returns a DNS transport, ready for use.
func NewTransportFrom(id string, ipp netip.AddrPort, px ipn.Proxies) (t dnsx.Transport, err error) {
	do, err := settings.NewDNSOptionsFromNetIp(ipp)
	if err != nil {
		return
	}

	return newTransport(id, do, px)
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
		px, err = t.proxies.GetProxy(pid)
	} else {
		err = dnsx.ErrNoProxyProvider
	}
	if err != nil {
		return
	}
	log.V("dns53: pxdial: (%s) using %s relay/proxy %s at %s", t.id, network, px.ID(), px.GetAddr())
	pxconn, err := px.Dialer().Dial(network, t.addr)
	if err != nil {
		return
	}
	conn = &dns.Conn{Conn: pxconn}
	return
}

func (t *transport) dial(network string) (*dns.Conn, error) {
	if network == dnsx.NetTypeUDP {
		return t.mcudp.Dial(t.addr)
	} else {
		return t.mctcp.Dial(t.addr)
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
	useproxy := len(pid) != 0 && pid != dnsx.NetNoProxy

	// if udp is unreachable, try tcp: github.com/celzero/rethink-app/issues/839
	// note that some proxies do not support udp (eg pipws, piph2)
	if userelay || useproxy {
		conn, err = t.pxdial(network, pid)
		if err != nil && useudp {
			network = dnsx.NetTypeTCP
			conn, err = t.pxdial(network, pid)
		}
	} else {
		conn, err = t.dial(network)
		if err != nil && useudp {
			network = dnsx.NetTypeTCP
			conn, err = t.dial(network)
		}
	}
	if err == nil {
		// TODO: conn pooling w/ ExchangeWithConn
		if network == dnsx.NetTypeTCP {
			ans, elapsed, err = t.mctcp.ExchangeWithConn(msg, conn)
		} else {
			ans, elapsed, err = t.mcudp.ExchangeWithConn(msg, conn)
		}
		conn.Close()
	}

	if err != nil {
		qerr = dnsx.NewTransportQueryError(err)
		return
	}

	response, err = ans.Pack()
	if err != nil {
		qerr = dnsx.NewBadResponseQueryError(err)
		return
	}
	return
}

func (t *transport) Query(network string, q []byte, summary *dnsx.Summary) (r []byte, err error) {
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

	summary.Latency = elapsed.Seconds()
	summary.RData = xdns.GetInterestingRData(ans)
	summary.RCode = xdns.Rcode(ans)
	summary.RTtl = xdns.RTtl(ans)
	summary.Server = t.GetAddr()
	if t.relay != nil {
		summary.RelayServer = t.relay.GetAddr()
	} else if len(pid) > 0 && pid != dnsx.NetNoProxy {
		summary.RelayServer = dnsx.SummaryProxyLabel + pid
	}
	summary.Status = status
	t.est.Add(summary.Latency)

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
	return t.addr
}

func (t *transport) Status() int {
	return t.status
}
