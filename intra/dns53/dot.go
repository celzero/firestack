// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dns53

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

const usepool = true

const echRetryPeriod = 8 * time.Hour

type dot struct {
	ctx  context.Context
	done context.CancelFunc

	id string // id of the transport

	url      string // full url
	addrport string // ip:port or hostname:port
	port     uint16 // port number
	host     string // hostname from the url

	c             *dns.Client
	proxies       ipn.ProxyProvider        // may be nil
	relay         string                   // may be empty
	relayref      *core.WeakRef[ipn.Proxy] // preset ref to relay proxy, if any
	skipTLSVerify bool

	pool    *core.MultConnPool[uint64]
	usepool bool

	echconfig      atomic.Pointer[tls.Config] // echconfig for the endpoint; may be nil
	echlastattempt atomic.Int64               // last attempt fetching ech cfg; unix milli

	est    core.P2QuantileEstimator
	status *core.Volatile[int]
}

var _ dnsx.Transport = (*dot)(nil)

// NewTLSTransport returns a DNS over TLS transport, ready for use.
func NewTLSTransport(ctx context.Context, id, rawurl string, addrs []string, px ipn.ProxyProvider) (t *dot, err error) {
	tlscfg := &tls.Config{
		MinVersion:             tls.VersionTLS12,
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
		skipTLSVerify = true
	}
	var relay string
	var relayref *core.WeakRef[ipn.Proxy]
	if px != nil {
		if p, _ := px.ProxyFor(id); p != nil {
			relay = p.ID()
			if ref, err := px.ProxyRef("relay.dot."+id, relay); err == nil {
				relayref = ref
			}
		}
	}
	ctx, done := context.WithCancel(ctx)
	hostname := parsedurl.Hostname()
	if len(hostname) <= 0 {
		hostname = rawurl
	}
	// addrs are pre-determined ip addresses for url / hostname
	ok := dnsx.RegisterAddrs(id, hostname, addrs)
	// add sni to tls config
	tlscfg.ServerName = hostname
	tlscfg.ClientSessionCache = core.TlsSessionCache()
	addrport, port := url2addrport(rawurl)
	t = &dot{
		ctx:           ctx,
		done:          done,
		id:            id,
		url:           rawurl,
		host:          hostname,
		skipTLSVerify: skipTLSVerify,
		addrport:      addrport, // may or may not be ipaddr
		port:          port,
		status:        core.NewVolatile(x.Start),
		proxies:       px,
		relay:         relay,
		relayref:      relayref,
		pool:          core.NewMultConnPool[uint64](ctx),
		usepool:       usepool,
		est:           core.NewP50Estimator(ctx),
		// echconfig/echlastattempt: zero values (nil) are fine
	}
	echcfg := t.getOrCreateEchConfigIfNeeded()
	// local dialer: protect.MakeNsDialer(id, ctl)
	t.c = dnsclient(tlscfg)
	log.I("dot: (%s) setup: %s; relay? %t; resolved? %t, ech? %t",
		id, rawurl, len(relay) > 0, ok, echcfg != nil)
	return t, nil
}

func dnsclient(c *tls.Config) *dns.Client {
	return &dns.Client{
		Net:            "tcp-tls",
		Dialer:         nil, // unused; dialers from px take precedence
		Timeout:        dottimeout,
		SingleInflight: true,      // coalsece queries
		TLSConfig:      c.Clone(), // may be left unused
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

func (t *dot) echVerifyFn() func(tls.ConnectionState) error {
	if t.skipTLSVerify {
		return func(info tls.ConnectionState) error {
			log.V("doh: skip ech verify for %s via %s", t.addrport, info.ServerName)
			return nil // never reject
		}
	}
	return nil // delegate to stdlib
}

func (t *dot) doQuery(pid string, q *dns.Msg) (response *dns.Msg, rpid string, ech bool, elapsed time.Duration, qerr *dnsx.QueryError) {
	if q == nil || !xdns.HasAnyQuestion(q) {
		qerr = dnsx.NewBadQueryError(fmt.Errorf("err len(query) %d", xdns.Len(q)))
		return
	}

	if qerr = dnsx.WillErr(t); qerr != nil {
		return
	}

	response, rpid, ech, elapsed, qerr = t.sendRequest(pid, q)

	if qerr != nil { // only on send-request errors
		response = xdns.Servfail(q)
	}
	return
}

func (t *dot) tlsdial(p ipn.Proxy) (dc *dns.Conn, who uint64, usingech bool, err error) {
	who = p.Handle()

	defer func() {
		if dc != nil {
			// todo: higher timeout for if using proxy dialer
			// _ = c.SetDeadline(time.Now().Add(dottimeout * 2))
			if c := dc.Conn; c != nil {
				_ = c.SetDeadline(time.Now().Add(dottimeout))
			}
		}
	}()

	if dc = t.fromPool(who); dc != nil {
		return dc, who, false, nil // pooled connections don't track ECH state
	}

	var c net.Conn = nil // dot is always tcp
	addr := t.addrport   // t.addr may be ip or hostname

	// Try ECH first if available
	if echcfg := t.getOrCreateEchConfigIfNeeded(); echcfg != nil {
		// update ech config which may have been changed by DialWithTls
		defer t.echconfig.Store(echcfg)
		c, err = dialers.DialWithTls(p.Dialer(), echcfg, "tcp", addr)
	}

	if c == nil && core.IsNil(c) { // no ech or ech failed
		cfg := t.c.TLSConfig
		c, err = dialers.DialWithTls(p.Dialer(), cfg, "tcp", addr)
		usingech = false
	}
	if c != nil && core.IsNotNil(c) {
		if tlsConn, ok := c.(*tls.Conn); ok && usingech {
			usingech = tlsConn.ConnectionState().ECHAccepted
		}
		return &dns.Conn{Conn: c}, who, usingech, err
	} else {
		err = core.OneErr(err, errNoNet)
		log.W("dot: tlsdial: (%s) nil conn/err for %s, ech? %t; err? %v",
			t.id, addr, usingech, err)
	}
	return nil, who, false, err
}

func (t *dot) pxdial(pid string) (*dns.Conn, string, uint64, bool, error) {
	var px ipn.Proxy
	if len(t.relay) > 0 { // relay takes precedence
		pid = t.relay
	}
	if t.proxies != nil { // err if t.proxies is nil
		var err error
		if px, err = t.proxies.ProxyFor(pid); err != nil {
			return nil, "", core.Nobody, false, err
		}
	}
	if px == nil {
		return nil, "", core.Nobody, false, dnsx.ErrNoProxyProvider
	}
	pid = px.ID()
	rpid := ipn.ViaID(px)
	if settings.Debug {
		log.V("dot: pxdial: (%s) using relay/proxy %s (via: %s) at %s",
			t.id, pid, rpid, px.GetAddr())
	}

	c, who, ech, err := t.tlsdial(px)
	return c, rpid, who, ech, err
}

// toPool takes ownership of c.
func (t *dot) toPool(id uint64, c *dns.Conn) {
	if !t.usepool || id == core.Nobody {
		clos(c)
		return
	}
	ok := t.pool.Put(id, c)
	logwif(!ok)("dot: pool: (%s) put for %v; ok? %t", t.id, id, ok)
}

// fromPool returns a conn from the pool, if available.
func (t *dot) fromPool(id uint64) (c *dns.Conn) {
	if !t.usepool || id == core.Nobody {
		return
	}

	pooled := t.pool.Get(id)
	if pooled == nil || core.IsNil(pooled) {
		return
	}
	var ok bool
	if c, ok = pooled.(*dns.Conn); !ok { // unlikely
		return &dns.Conn{Conn: pooled}
	}
	if settings.Debug {
		log.V("dot: pool: (%s) got conn from %v", t.id, id)
	}
	return
}

func clos(c net.Conn) {
	core.CloseConn(c)
}

func (t *dot) sendRequest(pid string, q *dns.Msg) (ans *dns.Msg, rpid string, ech bool, elapsed time.Duration, qerr *dnsx.QueryError) {
	var err error

	if q == nil || !xdns.HasAnyQuestion(q) {
		qerr = dnsx.NewBadQueryError(errQueryParse)
		return
	}

	var conn *dns.Conn
	who := core.Nobody
	userelay := len(t.relay) > 0
	useproxy := len(pid) != 0 // pid == dnsx.NetNoProxy => ipn.Block
	if useproxy || userelay { // ref dns.Client.Dial
		conn, rpid, who, ech, err = t.pxdial(pid)
	} else {
		err = dnsx.ErrNoProxyProvider
	}

	if err == nil {
		// tls config is not used with this exchange as conn is pre-supplied
		ans, elapsed, err = t.c.ExchangeWithConnContext(t.ctx, q, conn)
	} // fallthrough

	raddr := remoteAddrIfAny(conn)
	if err != nil {
		clos(conn)
		ok := dialers.Disconfirm2(t.host, raddr)
		log.V("dot: sendRequest: (%s) sz: %d, pad: %d, err: %v; disconfirm? %t %s => %s",
			t.id, xdns.Size(q), xdns.EDNS0PadLen(q), err, ok, t.host, raddr)
		qerr = dnsx.NewSendFailedQueryError(err)
	} else if ans == nil {
		t.toPool(who, conn) // or close
		qerr = dnsx.NewBadResponseQueryError(errNoAns)
	} else {
		t.toPool(who, conn) // or close
		dialers.Confirm2(t.host, raddr)
	}
	return
}

func (t *dot) chooseProxy(pids ...string) string {
	// TODO: DoT could use DTLS which is udp?
	return dnsx.ChooseHealthyProxyHostPort("dot: "+t.id, dnsx.NetTypeTCP, t.addrport, t.port, pids, t.proxies)
}

func (t *dot) Query(network string, q *dns.Msg, smm *x.DNSSummary) (ans *dns.Msg, err error) {
	var qerr *dnsx.QueryError
	var elapsed time.Duration
	var pid, rpid string
	var ech bool

	if r := t.relay; len(r) > 0 {
		pid = t.chooseProxy(r)
	} else {
		_, pids := xdns.Net2ProxyID(network)
		pid = t.chooseProxy(pids...)
	}

	ans, rpid, ech, elapsed, qerr = t.doQuery(pid, q)

	status := dnsx.Complete
	if qerr != nil {
		err = qerr.Unwrap()
		status = qerr.Status()
		log.W("dot: ans? %v err(%v) / ans(%d)", ans, err, xdns.Len(ans))
	}
	t.status.Store(status)

	smm.Latency = elapsed.Seconds()
	smm.RData = xdns.GetInterestingRData(ans)
	smm.RCode = xdns.Rcode(ans)
	smm.RTtl = xdns.RTtl(ans)
	smm.Server = t.GetAddr()
	smm.ECH = ech
	smm.PID = pid   // may be local dnsx.IsLocalProxy
	smm.RPID = rpid // may be empty
	if err != nil {
		smm.Msg = err.Error()
	}
	smm.Status = status
	t.est.Add(smm.Latency)

	if settings.Debug {
		log.V("dot: %s (fid: %s) ech? %t; len(res): fro %s:%d a:%d/sz:%d/pad:%d, data: %s / status: %d, via: %s, err? %v",
			t.id, smm.FID, ech, smm.QName, smm.QType, xdns.Len(ans), xdns.Size(ans), xdns.EDNS0PadLen(ans), smm.RData, smm.Status, smm.PID, err)
	}

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

func (t *dot) GetRelay() x.Proxy {
	if t.relayref == nil {
		return nil
	}
	if p, valid := t.relayref.Get(); valid {
		return p
	}
	return nil
}

func (t *dot) Relaying() bool {
	return len(t.relay) > 0
}

func (t *dot) GetAddr() string {
	prefix0 := dnsx.CryptoPrefix(t.skipTLSVerify, t.echconfig.Load() != nil)
	prefix1 := dnsx.TransportPrefix(t.id)
	return prefix0 + prefix1 + t.addrport
}

func (t *dot) IPPorts() (ipps []netip.AddrPort) {
	for _, ip := range dialers.For(t.addrport) {
		ipps = append(ipps, netip.AddrPortFrom(ip, t.port))
	}
	return
}

func (t *dot) Status() int {
	if px := t.GetRelay(); px != nil {
		if y, to := dnsx.OverrideStatusFrom(px); y {
			return to
		}
	}
	s := t.status.Load()
	if s == dnsx.Paused {
		// paused status is a pseudo state dependent on underlying relay
		// or requested pid, not a permanent state of this transport.
		t.status.Cas(s, dnsx.Unpaused)
		return dnsx.Unpaused
	}
	return s
}

func (t *dot) Stop() error {
	t.status.Store(dnsx.DEnd)
	t.done()
	return nil
}

func url2addrport(url string) (string, uint16) {
	// url is of type "tls://host:port" or "tls:host:port" or "host:port" or "host"
	if len(url) > 6 && url[:6] == "tls://" {
		url = url[6:]
	}
	if len(url) > 4 && url[:4] == "tls:" {
		url = url[4:]
	}
	port := DotPortU16
	// add port 853 if not present
	if _, p, err := net.SplitHostPort(url); err != nil {
		url = net.JoinHostPort(url, DotPort)
	} else {
		v, err := strconv.Atoi(p)
		if err != nil && v > 0 {
			port = uint16(v)
		}
	}
	return url, port
}

func (t *dot) getOrCreateEchConfigIfNeeded() *tls.Config {
	echcfg := t.echconfig.Load()
	if echcfg != nil {
		return echcfg
	}

	prev := t.echlastattempt.Load()
	now := time.Now().UnixMilli()

	if prev > 0 && now-prev < echRetryPeriod.Milliseconds() {
		return nil
	}
	if !t.echlastattempt.CompareAndSwap(prev, now) {
		return nil
	}

	if ech := t.ech(); len(ech) > 0 {
		echcfg = &tls.Config{
			InsecureSkipVerify:                  t.skipTLSVerify,
			MinVersion:                          tls.VersionTLS13, // must be 1.3
			EncryptedClientHelloConfigList:      ech,
			SessionTicketsDisabled:              false,
			ClientSessionCache:                  core.TlsSessionCache(),
			EncryptedClientHelloRejectionVerify: t.echVerifyFn(),
		}
		t.echconfig.Store(echcfg)
	}

	ok := echcfg != nil
	logwif(!ok)("dot: %s fetch ech... ok? %t", t.id, ok)
	return echcfg
}
