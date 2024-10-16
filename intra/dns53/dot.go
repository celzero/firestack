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
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

type dot struct {
	ctx           context.Context
	done          context.CancelFunc
	id            string // id of the transport
	url           string // full url
	addr          string // ip:port or hostname:port
	host          string // hostname from the url
	skipTLSVerify bool
	status        int
	c             *dns.Client
	c3            *dns.Client // with ech
	rd            *protect.RDial
	proxies       ipn.Proxies // may be nil
	relay         ipn.Proxy   // may be nil
	est           core.P2QuantileEstimator
}

var _ dnsx.Transport = (*dot)(nil)

// NewTLSTransport returns a DNS over TLS transport, ready for use.
func NewTLSTransport(ctx context.Context, id, rawurl string, addrs []string, px ipn.Proxies, ctl protect.Controller) (t *dot, err error) {
	tlscfg := &tls.Config{
		MinVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: false,
	}
	echcfg := &tls.Config{
		MinVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: false,
	}
	// rawurl is either tls:host[:port] or tls://host[:port] or host[:port]
	parsedurl, err := url.Parse(rawurl)
	if err != nil {
		return
	}
	skipTLSVerify := false
	if parsedurl.Scheme != "tls" {
		log.I("dot: disabling tls verification for %s", rawurl)
		tlscfg.InsecureSkipVerify = true
		// echcfg.InsecureSkipVerify = true
		skipTLSVerify = true
	}
	var relay ipn.Proxy
	if px != nil {
		relay, _ = px.ProxyFor(id)
	}
	rd := protect.MakeNsRDial(id, ctl)
	hostname := parsedurl.Hostname()
	if len(hostname) <= 0 {
		hostname = rawurl
	}
	// addrs are pre-determined ip addresses for url / hostname
	ok := dnsx.RegisterAddrs(id, hostname, addrs)
	// add sni to tls config
	tlscfg.ServerName = hostname
	tlscfg.ClientSessionCache = tls.NewLRUClientSessionCache(32)
	ctx, done := context.WithCancel(ctx)
	t = &dot{
		ctx:           ctx,
		done:          done,
		id:            id,
		url:           rawurl,
		host:          hostname,
		skipTLSVerify: skipTLSVerify,
		addr:          url2addr(rawurl), // may or may not be ipaddr
		status:        x.Start,
		proxies:       px,
		rd:            rd,
		relay:         relay,
		est:           core.NewP50Estimator(ctx),
	}
	ech := t.ech()
	if len(ech) > 0 {
		echcfg.ClientSessionCache = tls.NewLRUClientSessionCache(32)
		echcfg.EncryptedClientHelloConfigList = ech
		t.c3 = dnsclient(echcfg)
	}
	// local dialer: protect.MakeNsDialer(id, ctl)
	t.c = dnsclient(tlscfg)
	log.I("dot: (%s) setup: %s; relay? %t; resolved? %t, ech? %t",
		id, rawurl, relay != nil, ok, len(ech) > 0)
	return t, nil
}

func dnsclient(c *tls.Config) *dns.Client {
	return &dns.Client{
		Net:            "tcp-tls",
		Dialer:         nil, // unused; dialers from px take precedence
		Timeout:        dottimeout,
		SingleInflight: true, // coalsece queries
		TLSConfig:      c.Clone(),
	}
}

// todo: ech over user specified dns+proxy
func (t *dot) ech() []byte {
	if v, err := dialers.ECH(t.host); err == nil {
		log.V("dot: ech(%s): %d", t.host, len(v))
		return v
	}
	log.W("dot: ech(%s): not found", t.host)
	return nil
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

func (t *dot) tlsdial(rd protect.RDialer) (_ *dns.Conn, err error) {
	var c net.Conn = nil // dot is always tcp
	addr := t.addr       // t.addr may be ip or hostname
	if t.c3 != nil {     // may be nil if ech is not available
		cfg := t.c3.TLSConfig // don't clone; may be modified by dialers.DialWithTls
		c, err = dialers.DialWithTls(rd, cfg, "tcp", addr)
		log.W("dot: tlsdial: (%s) ech; err? %v", t.id, err)
	}
	if c == nil && core.IsNil(c) { // no ech or ech failed
		cfg := t.c.TLSConfig
		c, err = dialers.DialWithTls(rd, cfg, "tcp", addr)
	}
	if c != nil && core.IsNotNil(c) {
		_ = c.SetDeadline(time.Now().Add(dottimeout))
		// todo: higher timeout for if using proxy dialer
		// _ = c.SetDeadline(time.Now().Add(dottimeout * 2))
		return &dns.Conn{Conn: c, UDPSize: t.c.UDPSize}, err
	} else {
		if err == nil {
			log.W("dot: tlsdial: (%s) nil conn/err for %s", t.id, addr)
			err = errNoNet
		}
	}
	return nil, err
}

func (t *dot) pxdial(pid string) (*dns.Conn, error) {
	var px ipn.Proxy
	if t.relay != nil { // relay takes precedence
		px = t.relay
	} else if t.proxies != nil { // use proxy, if specified
		var err error
		if px, err = t.proxies.ProxyFor(pid); err != nil {
			return nil, err
		}
	}
	if px == nil {
		return nil, dnsx.ErrNoProxyProvider
	}
	log.V("dot: pxdial: (%s) using relay/proxy %s at %s",
		t.id, px.ID(), px.GetAddr())
	return t.tlsdial(px.Dialer())
}

func clos(c net.Conn) {
	core.CloseConn(c)
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
	} else { // ref dns.Client.Dial
		conn, err = t.tlsdial(t.rd)
	}

	if err == nil {
		// FIXME: conn pooling using t.c.Dial + ExchangeWithConn
		ans, elapsed, err = t.c.ExchangeWithConn(q, conn)
		clos(conn)
	} // fallthrough

	raddr := remoteAddrIfAny(conn)
	if err != nil {
		clos(conn)
		ok := dialers.Disconfirm2(t.host, raddr)
		log.V("dot: sendRequest: (%s) sz: %d, pad: %d, err: %v; disconfirm? %t %s => %s",
			t.id, xdns.Size(q), xdns.EDNS0PadLen(q), err, ok, t.host, raddr)
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
		log.W("dot: ans? %v err(%v) / ans(%d)", ans, err, xdns.Len(ans))
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

	log.V("dot: len(res): a:%d/sz:%d/pad:%d, data: %s, via: %s, err? %v",
		xdns.Len(ans), xdns.Size(ans), xdns.EDNS0PadLen(ans), smm.RData, smm.RelayServer, err)

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

func (t *dot) GetAddr() (addr string) {
	if t.c3 != nil {
		addr = dnsx.EchPrefix + t.addr
	} else if t.skipTLSVerify {
		addr = dnsx.NoPkiPrefix + t.addr
	} else {
		addr = t.addr
	}
	return addr
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
