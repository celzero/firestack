// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     Copyright 2019 The Outline Authors
//
//     Licensed under the Apache License, Version 2.0 (the "License");
//     you may not use this file except in compliance with the License.
//     You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
//     Unless required by applicable law or agreed to in writing, software
//     distributed under the License is distributed on an "AS IS" BASIS,
//     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//     See the License for the specific language governing permissions and
//     limitations under the License.

package doh

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
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
	"github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
)

const dohmimetype = "application/dns-message"

const maxEOFTries = uint8(2)

const purgethreshold = 1 * time.Minute

var errNoClient error = errors.New("no doh client")

type odohtransport struct {
	omu              sync.RWMutex // protects odohConfig
	odohproxyurl     string       // proxy url
	odohproxyname    string       // proxy hostname
	odohtargetname   string       // target hostname
	odohtargetpath   string       // target path
	odohConfig       *odoh.ObliviousDoHConfig
	odohConfigExpiry time.Time
	preferWK         bool // prefer .well-known over svcb/https probe
}

// TODO: Keep a context here so that queries can be canceled.
type transport struct {
	*odohtransport // stackoverflow.com/a/28505394
	ctx            context.Context
	done           context.CancelFunc
	id             string
	typ            string                     // dnsx.DOH / dnsx.ODOH
	url            string                     // endpoint URL
	hostname       string                     // endpoint hostname
	skipTLSVerify  bool                       // skips tls verification
	client         http.Client                // only for use with the endpoint
	client3        http.Client                // only for use with ech
	tlsconfig      *tls.Config                // preset tlsconfig for the endpoint
	echconfig      *tls.Config                // preset echconfig for the endpoint
	pxcmu          sync.RWMutex               // protects pxclients
	pxclients      map[string]*proxytransport // todo: use weak pointers for Proxy
	lastpurge      *core.Volatile[time.Time]  // last scrubbed time for stale pxclients
	dialer         *protect.RDial
	proxies        ipn.Proxies // proxy provider, may be nil
	relay          ipn.Proxy   // dial doh via relay, may be nil
	status         int
	est            core.P2QuantileEstimator
}

var _ dnsx.Transport = (*transport)(nil)

func (t *transport) dial(network, addr string) (net.Conn, error) {
	if settings.Loopingback.Load() { // no splits in loopback (rinr) mode
		return dialers.Dial(t.dialer, network, addr)
	} else {
		return dialers.SplitDial(t.dialer, network, addr)
	}
}

// NewTransport returns a POST-only DoH transport.
// `id` identifies this transport.
// `rawurl` is the DoH template in string form.
// `addrs` is a list of IP addresses to bootstrap dialers.
// `px` is the proxy provider, may be nil (eg for id == dnsx.Default)
func NewTransport(id, rawurl string, addrs []string, px ipn.Proxies, ctl protect.Controller) (*transport, error) {
	return newTransport(dnsx.DOH, id, rawurl, "", addrs, px, ctl)
}

// NewTransport returns a POST-only Oblivious DoH transport.
// `id` identifies this transport.
// `endpoint` is the ODoH proxy that liaisons with the target.
// `target` is the ODoH resolver.
// `addrs` is a list of IP addresses to bootstrap endpoint dialers.
// `px` is the proxy provider, never nil.
func NewOdohTransport(id, endpoint, target string, addrs []string, px ipn.Proxies, ctl protect.Controller) (*transport, error) {
	return newTransport(dnsx.ODOH, id, endpoint, target, addrs, px, ctl)
}

func newTransport(typ, id, rawurl, otargeturl string, addrs []string, px ipn.Proxies, ctl protect.Controller) (*transport, error) {
	isodoh := typ == dnsx.ODOH

	var renewed bool
	var relay ipn.Proxy
	if px != nil {
		relay, _ = px.ProxyFor(id)
	}

	ctx, done := context.WithCancel(context.Background())

	t := &transport{
		ctx:       ctx,
		done:      done,
		id:        id,
		typ:       typ,
		dialer:    protect.MakeNsRDial(id, ctl), // ctl may be nil
		proxies:   px,                           // may be nil
		relay:     relay,                        // may be nil
		status:    dnsx.Start,
		pxclients: make(map[string]*proxytransport),
		lastpurge: core.NewVolatile(time.Now()),
		est:       core.NewP50Estimator(ctx),
	}
	if !isodoh {
		parsedurl, err := url.Parse(rawurl)
		if err != nil {
			return nil, err
		}
		// use of "http" is an indication to turn-off TLS verification
		// for, odoh rawurl represents a proxy, which can operate on http
		if parsedurl.Scheme == "http" {
			log.I("doh: disabling tls verification for %s", rawurl)
			parsedurl.Scheme = "https"
			t.skipTLSVerify = true
		}
		if parsedurl.Scheme != "https" {
			return nil, fmt.Errorf("unsupported scheme %s", parsedurl.Scheme)
		}
		// for odoh, rawurl represents a proxy, which is optional
		if len(parsedurl.Hostname()) == 0 {
			return nil, fmt.Errorf("no hostname in %s", rawurl)
		}
		t.url = parsedurl.String()
		t.hostname = parsedurl.Hostname()
		// addrs are pre-determined ip addresses for url / hostname
		renewed = dnsx.RegisterAddrs(t.id, t.hostname, addrs)
	} else {
		t.odohtransport = &odohtransport{}

		proxy := rawurl // may be empty
		configurl, err := url.Parse(odohconfigdns)
		if err != nil || configurl == nil || configurl.Hostname() == "" {
			return nil, errors.Join(errNoOdohConfigUrl, err)
		}
		targeturl, err := url.Parse(otargeturl)
		if err != nil || targeturl == nil || targeturl.Hostname() == "" {
			return nil, errors.Join(errNoOdohTarget, err)
		}
		proxyurl, _ := url.Parse(proxy) // ignore err as proxy may be empty

		// addrs are proxy addresses if proxy is not empty, otherwise target addresses
		if proxyurl != nil && proxyurl.Hostname() != "" {
			renewed = dnsx.RegisterAddrs(id, proxyurl.Hostname(), addrs)
			if len(proxyurl.Path) <= 1 { // should not be "" or "/"
				proxyurl.Path = odohproxypath // default: "/proxy"
			}
			t.odohproxyurl = proxyurl.String()
			t.odohproxyname = proxyurl.Hostname()
		} else {
			renewed = dnsx.RegisterAddrs(id, targeturl.Hostname(), addrs)
		}

		t.url = configurl.String()        // odohconfigdns
		t.hostname = configurl.Hostname() // 1.1.1.1
		t.odohtargetname = targeturl.Hostname()
		if len(targeturl.Path) > 1 { // should not be "" or "/"
			t.odohtargetpath = targeturl.Path
		} else {
			t.odohtargetpath = odohtargetpath // default: "/dns-query"
		}
		log.I("doh: ODOH for %s -> %s", proxy, otargeturl)
	}

	ech := t.ech()
	// TODO: ClientAuth
	// Supply a client certificate during TLS handshakes.
	// if auth != nil {
	// 	signer := newClientAuthWrapper(auth)
	// 	t.tlsconfig = &tls.Config{
	// 		GetClientCertificate: signer.GetClientCertificate,
	// 		ServerName:           t.hostname,
	// 	}
	// }
	// TODO: ECH
	if len(ech) > 0 {
		t.echconfig = &tls.Config{
			// todo: InsecureSkipVerify:    t.skipTLSVerify,
			MinVersion:                     tls.VersionTLS13, // must be 1.3
			EncryptedClientHelloConfigList: ech,
		}
		t.client3.Transport = h2(t.dial, t.echconfig)
	}
	t.tlsconfig = &tls.Config{
		InsecureSkipVerify: t.skipTLSVerify,
		MinVersion:         tls.VersionTLS12,
		// SNI (hostname) must always be inferred from http-request
		// ServerName:         t.hostname,
	}
	// Override the dial function.
	t.client.Transport = h2(t.dial, t.tlsconfig)

	log.I("doh: new transport(%s): %s; relay? %t; addrs? %v; resolved? %t, ech? %t",
		t.typ, t.url, relay != nil, addrs, renewed, len(ech) > 0)
	return t, nil
}

type proxytransport struct {
	p  ipn.Proxy
	c  *http.Client
	c3 *http.Client
}

func (t *transport) ech() []byte {
	name := t.hostname
	if t.typ == dnsx.ODOH {
		name = t.odohproxyname
	}
	if len(name) <= 0 {
		return nil
	} else if v, err := dialers.ECH(name); err != nil {
		log.W("doh: ech(%s): %v", name, err)
		return nil
	} else {
		log.V("doh: ech(%s): sz %d", name, len(v))
		return v
	}
}

func h2(d protect.DialFn, c *tls.Config) *http.Transport {
	return &http.Transport{
		Dial:                d,
		ForceAttemptHTTP2:   true,
		IdleConnTimeout:     3 * time.Minute,
		TLSHandshakeTimeout: 7 * time.Second,
		// Android's DNS-over-TLS sets it to 30s
		ResponseHeaderTimeout: 20 * time.Second,
		// SNI (hostname) must always be inferred from http-request
		TLSClientConfig: c.Clone(),
	}
}

// always called from a go-routine
func (t *transport) purgeProxyClients() {
	lastpurge := t.lastpurge.Load()
	if time.Since(lastpurge) <= purgethreshold {
		return
	}
	if ok := t.lastpurge.Cas(lastpurge, time.Now()); !ok {
		log.I("doh: purge proxy clients: race...")
		return
	}
	t.pxcmu.Lock()
	defer t.pxcmu.Unlock()
	for id, pxtr := range t.pxclients {
		if pxtr == nil {
			continue
		} else if pxtr.p == nil {
			delete(t.pxclients, id)
			continue
		} else if orig, err := t.proxies.ProxyFor(id); err != nil {
			delete(t.pxclients, id)
			log.W("doh: purge proxy clients: %s %v", id, err)
			continue
		} else {
			diff := pxtr.p != orig
			note := log.V
			if diff {
				note = log.I
				delete(t.pxclients, id)
				continue
			}
			note("doh: purge proxy clients: remove? %t %s", diff, id)
		}
	}
}

func (t *transport) httpClientFor(p ipn.Proxy) (c3, c *http.Client, err error) {
	t.pxcmu.RLock()
	pxtr, ok := t.pxclients[p.ID()]
	t.pxcmu.RUnlock()

	same := pxtr != nil && pxtr.p == p
	if ok && same {
		return pxtr.c3, pxtr.c, nil
	}

	pdial := p.Dialer().Dial

	var client http.Client
	var client3 *http.Client
	client.Transport = h2(pdial, t.tlsconfig)
	if t.echconfig != nil {
		client3 = new(http.Client)
		client3.Transport = h2(pdial, t.echconfig)
	}

	// last writer wins
	t.pxcmu.Lock()
	t.pxclients[p.ID()] = &proxytransport{
		p:  p,
		c:  &client,
		c3: client3, // may be nil
	}
	t.pxcmu.Unlock()

	// check if other proxies need to be purged
	go t.purgeProxyClients()

	return client3, &client, nil
}

// Given a raw DNS query (including the query ID), this function sends the
// query.  If the query is successful, it returns the response and a nil qerr.  Otherwise,
// it returns a SERVFAIL response and a qerr with a status value indicating the cause.
// Independent of the query's success or failure, this function also returns the
// address of the server on a best-effort basis, or nil if the address could not
// be determined.
func (t *transport) doDoh(pid string, msg *dns.Msg) (response *dns.Msg, blocklists, region string, elapsed time.Duration, qerr *dnsx.QueryError) {
	start := time.Now()
	q, err := padQuery(msg)
	// fail on padding if debug
	if settings.Debug && (err != nil || q == nil) {
		elapsed = time.Since(start)
		qerr = dnsx.NewInternalQueryError(err) // err can be nil
		return
	}
	if q == nil { // padding error
		log.W("doh: failed to pad %s: %v", xdns.QName(msg), err)
		q = msg
	}

	// zero out the query id
	id := q.Id
	q.Id = 0

	req, err := t.asDohRequest(q)
	if err != nil {
		log.D("doh: failed to create request: %v", err)
		elapsed = time.Since(start)
		qerr = dnsx.NewInternalQueryError(err)
		return
	}

	response, blocklists, region, elapsed, qerr = t.send(pid, req)

	// restore dns query id
	q.Id = id
	if response != nil {
		response.Id = id
	} else { // override response with servfail
		response = xdns.Servfail(q)
	}
	return
}

func (t *transport) fetch(pid string, req *http.Request) (*http.Response, error) {
	ustr := req.URL.String()

	uerr := func(e error) *url.Error {
		if e == nil {
			return nil
		}
		if e, ok := e.(*url.Error); ok {
			return e
		}
		return &url.Error{
			Op:  req.Method,
			URL: ustr,
			Err: e,
		}
	}

	c3, c, err := t.prepare(pid) // c3 may be nil
	if err != nil {
		log.E("doh: prepare (%s) for %s, err: %v", pid, ustr, err)
		return nil, uerr(err)
	}
	if c == nil && c3 == nil { // should never happen as prepare() must never return nil without err
		return nil, uerr(errNoClient)
	}

	r, err := t.multifetch(req, c3, c)
	if err != nil {
		log.W("doh: fetch %s, err: %v", ustr, err)
		return r, uerr(err)
	}
	return r, nil
}

func (t *transport) multifetch(req *http.Request, clients ...*http.Client) (res *http.Response, err error) {
	term := false
	sent := false
	for _, c := range clients {
		if c == nil { // c may be nil (ex: if no ech)
			continue
		}
		for i := uint8(0); !term && i < maxEOFTries; i++ {
			sent = true
			if res, err = c.Do(req); err == nil {
				return res, nil // res is never nil here
			}
			if uerr, ok := err.(*url.Error); ok {
				term = uerr.Err != io.EOF || uerr.Err != io.ErrUnexpectedEOF // terminate if not EOF
			} else if eerr, ok := err.(*tls.ECHRejectionError); ok {
				ech := eerr.RetryConfigList
				useech := t.echconfig != nil
				if len(ech) > 0 && useech {
					t.echconfig.EncryptedClientHelloConfigList = ech
					t.client3.Transport = h2(t.dial, t.echconfig)
				}
				log.I("doh: fetch #%d: ech rejected; retry? %t ech? %t", i, len(ech) > 0, useech)
			}
			log.W("doh: fetch #%d (eof? %t); err: %v", i, !term, err)
		}
	}
	if !sent && err == nil { // should never happen
		return nil, errNoClient
	}
	return nil, err
}

func (t *transport) prepare(pid string) (c3, c *http.Client, err error) {
	userelay := t.relay != nil
	hasproxy := t.proxies != nil
	useproxy := len(pid) != 0 // if pid == dnsx.NetNoProxy, then px is ipn.Base
	useech := t.echconfig != nil

	c = &t.client
	if useech {
		c3 = &t.client3
	}
	if userelay || useproxy {
		var px ipn.Proxy
		if userelay { // relay takes precedence
			px = t.relay
		} else if hasproxy { // use proxy, if specified
			if px, err = t.proxies.ProxyFor(pid); err != nil {
				return
			}
		}
		if px == nil {
			return nil, nil, dnsx.ErrNoProxyProvider
		}
		c3, c, err = t.httpClientFor(px) // c3 may be nil
		useech = c3 != nil
		if err != nil {
			return
		}
		log.VV("doh: using proxy %s:%s ech? %t", px.ID(), px.GetAddr(), useech)
	} else {
		log.D("doh: no proxy %s ech? %t", pid, useech)
	}
	return
}

func (t *transport) do(pid string, req *http.Request) (ans []byte, blocklists, region string, elapsed time.Duration, qerr *dnsx.QueryError) {
	var server net.Addr
	var conn net.Conn
	start := time.Now()
	// either t.hostname or t.odohtargetname or t.odohproxy
	hostname := req.URL.Hostname()

	// Error cleanup function.  If the query fails, this function will close the
	// underlying socket and disconfirm the server IP.  Empirically, sockets often
	// become unresponsive after a network change, causing timeouts on all requests.
	defer func() {
		elapsed = time.Since(start)

		// server addr would be of relay / proxy (ex: 127.0.0.1:9050) if used
		usedrelay := t.relay != nil
		usedproxy := !dnsx.IsLocalProxy(pid) // pid == dnsx.NetNoProxy => ipn.Base
		hasserveraddr := server != nil && !usedrelay && !usedproxy

		if hasserveraddr {
			if qerr == nil {
				// record a working IP address for this server
				dialers.Confirm3(hostname, server)
				return
			} else {
				ok := dialers.Disconfirm3(hostname, server)
				log.D("doh: disconfirming %s, %s done? %t", hostname, server, ok)
			}
		}
		if qerr != nil {
			log.E("doh: query failed: %v", qerr)
			if conn != nil {
				log.I("doh: close failing doh conn to %s", hostname)
				core.CloseConn(conn)
			}
		}
	}()

	// Add a trace to the request in order to expose the server's IP address.
	// Only GotConn performs any action; the other methods just provide debug logs.
	// GotConn runs before client.Do() returns, so there is no data race when
	// reading the variables it has set.
	trace := httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			log.V("doh: got-conn(%v)", info)
			if info.Conn == nil {
				return
			}
			conn = info.Conn
			// info.Conn is a DuplexConn, so RemoteAddr is actually a TCPAddr.
			// if the conn is proxied, then RemoteAddr is that of the proxy
			server = conn.RemoteAddr()
		},
		ConnectStart: func(network, addr string) {
			start = time.Now() // re...start
			log.VV("doh: connect-start(%s, %s)", network, addr)
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			log.VV("doh: wrote-req(%v)", info)
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &trace))

	log.V("doh: sending query to: %s", t.hostname)

	httpResponse, err := t.fetch(pid, req)

	if err != nil || httpResponse == nil {
		qerr = dnsx.NewSendFailedQueryError(err)
		return
	}

	blocklists, region = t.rdnsHeaders(&httpResponse.Header)
	// todo: check if content-type is [doh|odoh] mime type

	ans, err = io.ReadAll(httpResponse.Body)
	if err != nil {
		qerr = dnsx.NewSendFailedQueryError(err)
		return
	}
	core.Close(httpResponse.Body)
	log.V("doh: closed response")

	// update the hostname, which could have changed due to a redirect
	hostname = httpResponse.Request.URL.Hostname()

	sc := httpResponse.StatusCode
	if sc != http.StatusOK { // 4xx
		if sc >= http.StatusBadRequest && sc < http.StatusInternalServerError {
			qerr = dnsx.NewClientQueryError(fmt.Errorf("http-status: %d", sc))
		} else {
			qerr = dnsx.NewTransportQueryError(fmt.Errorf("http-status: %d", sc))
		}
		return
	}

	return
}

func (t *transport) send(pid string, req *http.Request) (msg *dns.Msg, blocklists, region string, elapsed time.Duration, qerr *dnsx.QueryError) {
	var ans []byte
	var err error
	ans, blocklists, region, elapsed, qerr = t.do(pid, req)
	if qerr != nil {
		return
	}
	msg, err = xdns.AsMsg2(ans)
	if msg == nil {
		qerr = dnsx.NewBadResponseQueryError(fmt.Errorf("parse err: %v", err))
		return
	}
	return
}

func (t *transport) rdnsHeaders(h *http.Header) (blocklistStamp, region string) {
	if h == nil { // should not be nil
		return
	}
	blocklistStamp = h.Get(xdns.GetBlocklistStampHeaderKey())
	// X-Nile-Region:[sin]
	region = h.Get(xdns.GetRethinkDNSRegionHeaderKey1())
	if len(region) <= 0 {
		// Cf-Ray:[d1e2a3d4b5e6e7f8-SIN]
		if ck := h.Get(xdns.GetRethinkDNSRegionHeaderKey2()); len(ck) > 0 {
			_, region, _ = strings.Cut(ck, "-")
		}
	}
	log.VV("doh: header %s; region %s; stamp %v", h, region, blocklistStamp)
	return
}

func (t *transport) asDohRequest(msg *dns.Msg) (req *http.Request, err error) {
	var q []byte
	q, err = msg.Pack()
	if err != nil {
		return
	}
	req, err = http.NewRequest(http.MethodPost, t.url, bytes.NewBuffer(q))
	if err != nil {
		return
	}
	req.Header.Set("content-type", dohmimetype)
	req.Header.Set("accept", dohmimetype)
	req.Header.Set("user-agent", "")
	return
}

func (t *transport) ID() string {
	return t.id
}

func (t *transport) Type() string {
	return t.typ
}

func (t *transport) Query(network string, q *dns.Msg, smm *x.DNSSummary) (r *dns.Msg, err error) {
	var blocklists, region string
	var elapsed time.Duration
	var qerr *dnsx.QueryError

	_, pid := xdns.Net2ProxyID(network)
	if t.typ == dnsx.DOH {
		r, blocklists, region, elapsed, qerr = t.doDoh(pid, q)
		smm.Server = t.hostname
	} else {
		r, elapsed, qerr = t.doOdoh(pid, q)
		smm.Server = t.odohtargetname
		smm.RelayServer = t.odohproxyname
	}

	status := dnsx.Complete

	if qerr != nil {
		status = qerr.Status()
		err = qerr.Unwrap()
	}
	t.status = status

	t.est.Add(elapsed.Seconds())
	smm.Latency = elapsed.Seconds()
	smm.RData = xdns.GetInterestingRData(r)
	smm.RCode = xdns.Rcode(r)
	smm.RTtl = xdns.RTtl(r)
	smm.Status = status
	smm.Region = region
	smm.Blocklists = blocklists
	noOdohRelay := len(smm.RelayServer) <= 0
	if noOdohRelay {
		if t.relay != nil {
			smm.RelayServer = x.SummaryProxyLabel + t.relay.ID()
		} else if !dnsx.IsLocalProxy(pid) {
			smm.RelayServer = x.SummaryProxyLabel + pid
		}
	}
	if err != nil {
		smm.Msg = err.Error()
	}
	log.V("doh: (p/px %s/%s); len(res): %d, data: %s, via: %s, err? %v", network, pid, xdns.Len(r), smm.RData, smm.RelayServer, err)
	return r, err
}

func (t *transport) P50() int64 {
	return t.est.Get()
}

func (t *transport) GetAddr() string {
	addr := t.hostname
	if t.typ == dnsx.ODOH {
		addr = t.odohtargetname
	}

	if t.echconfig != nil {
		addr = dnsx.EchPrefix + addr
	}
	// doh transports could be "dnsx.Bootstrap"
	prefix := dnsx.PrefixFor(t.id)
	if len(prefix) > 0 {
		addr = prefix + addr
	}
	return addr
}

func (t *transport) Status() int {
	return t.status
}

func (t *transport) Stop() error {
	t.done()
	return nil
}
