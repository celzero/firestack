// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dns53

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
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
	"golang.org/x/net/context"
)

type dot struct {
	ctx     context.Context
	done    context.CancelFunc
	id      string // id of the transport
	url     string // full url
	addr    string // ip:port or hostname:port
	host    string // hostname from the url
	status  int
	c       *dns.Client
	rd      *protect.RDial
	proxies ipn.Proxies // may be nil
	relay   ipn.Proxy   // may be nil
	est     core.P2QuantileEstimator
}

var _ dnsx.Transport = (*dot)(nil)

// NewTLSTransport returns a DNS over TLS transport, ready for use.
func NewTLSTransport(id, rawurl string, addrs []string, px ipn.Proxies, ctl protect.Controller) (t *dot, err error) {
	tlscfg := &tls.Config{MinVersion: tls.VersionTLS12}
	// rawurl is either tls:host[:port] or tls://host[:port] or host[:port]
	parsedurl, err := url.Parse(rawurl)
	if err != nil {
		return
	}
	if parsedurl.Scheme != "tls" {
		log.I("dot: disabling tls verification for %s", rawurl)
		tlscfg.InsecureSkipVerify = true
	}
	var relay ipn.Proxy
	if px != nil {
		relay, _ = px.ProxyFor(id)
	}
	rd := protect.MakeNsRDial(id, ctl)
	hostname := parsedurl.Hostname()
	// addrs are pre-determined ip addresses for url / hostname
	ok := dnsx.RegisterAddrs(id, hostname, addrs)
	// add sni to tls config
	tlscfg.ServerName = hostname
	ctx, done := context.WithCancel(context.Background())
	tx := &dot{
		ctx:     ctx,
		done:    done,
		id:      id,
		url:     rawurl,
		host:    hostname,
		addr:    url2addr(rawurl), // may or may not be ipaddr
		status:  x.Start,
		proxies: px,
		rd:      rd,
		relay:   relay,
		est:     core.NewP50Estimator(ctx),
	}
	// local dialer: protect.MakeNsDialer(id, ctl)
	tx.c = &dns.Client{
		Net:            "tcp-tls",
		Dialer:         nil, // unused; dialers from px take precedence
		Timeout:        dottimeout,
		SingleInflight: true,
		TLSConfig:      tlscfg,
	}
	log.I("dot: (%s) setup: %s; relay? %t; resolved? %t", id, rawurl, relay != nil, ok)
	return tx, nil
}

func (t *dot) doQuery(pid string, q *dns.Msg) (response *dns.Msg, elapsed time.Duration, qerr *dnsx.QueryError) {
	if q == nil || !xdns.HasAnyQuestion(q) {
		qerr = dnsx.NewBadQueryError(fmt.Errorf("err len(query) %d", xdns.Len(q)))
		return
	}

	response, elapsed, qerr = t.sendRequest(pid, q)

	if qerr != nil { // only on send-request errors
		response = xdns.Servfail(q)
	}
	return
}

func (t *dot) tlsdial() (_ *dns.Conn, err error) {
	var c net.Conn
	if settings.Loopingback.Load() { // no splits in loopback (rinr) mode
		c, err = dialers.DialWithTls(t.rd, t.c.TLSConfig.Clone(), t.addr)
	} else {
		c, err = dialers.SplitDialWithTls(t.rd, t.c.TLSConfig.Clone(), t.addr)
	}
	if c != nil && core.IsNotNil(c) {
		_ = c.SetDeadline(time.Now().Add(dottimeout))
		return &dns.Conn{Conn: c, UDPSize: t.c.UDPSize}, err
	}
	return nil, err
}

func (t *dot) pxdial(pid string) (conn *dns.Conn, err error) {
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

	log.V("dot: pxdial: (%s) using relay/proxy %s at %s", t.id, px.ID(), px.GetAddr())
	// dot is always tcp; and t.addr may be ip or hostname
	pxconn, err := px.Dialer().Dial("tcp", t.addr)
	if err != nil {
		return
	}
	if pxconn == nil { // nilaway: tx.socks5 returns nil conn even if err == nil
		log.E("dot: pxdial: (%s) no conn for relay/proxy %s at %s", t.id, px.ID(), px.GetAddr())
		err = errNoNet
		return
	}
	// higher timeout for proxy
	_ = pxconn.SetDeadline(time.Now().Add(dottimeout * 3))
	pxconn, err = t.addtls(pxconn)
	if err != nil {
		clos(pxconn)
		return
	}
	conn = &dns.Conn{Conn: pxconn}
	return
}

func clos(c net.Conn) {
	core.CloseConn(c)
}

// perform tls handshake
func (t *dot) addtls(c net.Conn) (net.Conn, error) {
	tlsconn := tls.Client(c, t.c.TLSConfig)
	err := tlsconn.Handshake()
	return tlsconn, err
}

func (t *dot) sendRequest(pid string, q *dns.Msg) (ans *dns.Msg, elapsed time.Duration, qerr *dnsx.QueryError) {
	var err error

	if q == nil || !xdns.HasAnyQuestion(q) {
		qerr = dnsx.NewBadQueryError(errQueryParse)
		return
	}

	var conn *dns.Conn
	userelay := t.relay != nil
	useproxy := len(pid) != 0 // pid == dnsx.NetNoProxy => ipn.Base
	if useproxy || userelay {
		conn, err = t.pxdial(pid)
	} else {
		// ref dns.Client.Dial
		conn, err = t.tlsdial()
	}

	if err == nil {
		// FIXME: conn pooling using t.c.Dial + ExchangeWithConn
		ans, elapsed, err = t.c.ExchangeWithConn(q, conn)
		clos(conn)
	} // fallthrough

	raddr := remoteAddrIfAny(conn)
	if err != nil {
		ok := dialers.Disconfirm2(t.host, raddr)
		log.V("dot: sendRequest: (%s) err: %v; disconfirm? %t %s => %s", t.id, err, ok, t.host, raddr)
		qerr = dnsx.NewSendFailedQueryError(err)
	} else {
		dialers.Confirm2(t.host, raddr)
	}
	return
}

func (t *dot) Query(network string, q *dns.Msg, smm *x.DNSSummary) (ans *dns.Msg, err error) {
	var qerr *dnsx.QueryError
	var elapsed time.Duration

	_, pid := xdns.Net2ProxyID(network)

	ans, elapsed, qerr = t.doQuery(pid, q)

	status := dnsx.Complete
	if qerr != nil {
		err = qerr.Unwrap()
		status = qerr.Status()
		log.W("dot: err(%v) / size(%d)", err, xdns.Len(ans))
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
	if err != nil {
		smm.Msg = err.Error()
	}
	smm.Status = status
	t.est.Add(smm.Latency)

	log.V("dot: len(res): %d, data: %s, via: %s, err? %v", xdns.Len(ans), smm.RData, smm.RelayServer, err)

	return
}

func (t *dot) ID() string {
	return t.id
}

func (t *dot) Type() string {
	return dnsx.DOT
}

func (t *dot) P50() int64 {
	return t.est.Get()
}

func (t *dot) GetAddr() string {
	return t.addr
}

func (t *dot) Status() int {
	return t.status
}

func (t *dot) Stop() error {
	t.done()
	return nil
}

func url2addr(url string) string {
	// url is of type "tls://host:port" or "tls:host:port" or "host:port" or "host"
	if len(url) > 6 && url[:6] == "tls://" {
		url = url[6:]
	}
	if len(url) > 4 && url[:4] == "tls:" {
		url = url[4:]
	}
	// add port 853 if not present
	if _, _, err := net.SplitHostPort(url); err != nil {
		url = net.JoinHostPort(url, DotPort)
	}
	return url
}
