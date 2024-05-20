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
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
)

const dohmimetype = "application/dns-message"

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
	id             string
	typ            string       // dnsx.DOH / dnsx.ODOH
	url            string       // endpoint URL
	hostname       string       // endpoint hostname
	client         http.Client  // only for use with the endpoint
	tlsconfig      *tls.Config  // preset tlsconfig for the endpoint
	pxcmu          sync.RWMutex // protects pxclients
	pxclients      map[string]*proxytransport
	dialer         *protect.RDial
	proxies        ipn.Proxies // proxy provider, may be nil
	relay          ipn.Proxy   // dial doh via relay, may be nil
	status         int
	est            core.P2QuantileEstimator
}

var _ dnsx.Transport = (*transport)(nil)

func (t *transport) dial(network, addr string) (net.Conn, error) {
	return dialers.SplitDial(t.dialer, network, addr)
}

// NewTransport returns a POST-only DoH transport.
// `id` identifies this transport.
// `rawurl` is the DoH template in string form.
// `addrs` is a list of IP addresses to bootstrap dialers.
// `px` is the proxy provider, may be nil (eg for id == dnsx.Default)
func NewTransport(id, rawurl string, addrs []string, px ipn.Proxies, ctl protect.Controller) (dnsx.Transport, error) {
	return newTransport(dnsx.DOH, id, rawurl, "", addrs, px, ctl)
}

// NewTransport returns a POST-only Oblivious DoH transport.
// `id` identifies this transport.
// `endpoint` is the ODoH proxy that liasons with the target.
// `target` is the ODoH resolver.
// `addrs` is a list of IP addresses to bootstrap endpoint dialers.
// `px` is the proxy provider, never nil.
func NewOdohTransport(id, endpoint, target string, addrs []string, px ipn.Proxies, ctl protect.Controller) (dnsx.Transport, error) {
	return newTransport(dnsx.ODOH, id, endpoint, target, addrs, px, ctl)
}

func newTransport(typ, id, rawurl, otargeturl string, addrs []string, px ipn.Proxies, ctl protect.Controller) (*transport, error) {
	skipTLSVerify := false
	isodoh := typ == dnsx.ODOH

	var renewed bool
	var relay ipn.Proxy
	if px != nil {
		relay, _ = px.ProxyFor(id)
	}

	t := &transport{
		id:        id,
		typ:       typ,
		dialer:    protect.MakeNsRDial(id, ctl), // ctl may be nil
		proxies:   px,                           // may be nil
		relay:     relay,                        // may be nil
		status:    dnsx.Start,
		pxclients: make(map[string]*proxytransport),
		est:       core.NewP50Estimator(),
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
			skipTLSVerify = true
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

	// TODO: ClientAuth
	// Supply a client certificate during TLS handshakes.
	// if auth != nil {
	// 	signer := newClientAuthWrapper(auth)
	// 	t.tlsconfig = &tls.Config{
	// 		GetClientCertificate: signer.GetClientCertificate,
	// 		ServerName:           t.hostname,
	// 	}
	// }
	t.tlsconfig = &tls.Config{
		InsecureSkipVerify: skipTLSVerify,
		MinVersion:         tls.VersionTLS12,
		// SNI (hostname) must always be inferred from http-request
		// ServerName:         t.hostname,
	}
	// Override the dial function.
	t.client.Transport = &http.Transport{
		Dial:                  t.dial,
		ForceAttemptHTTP2:     true,
		IdleConnTimeout:       2 * time.Minute,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second, // Same value as Android DNS-over-TLS
		TLSClientConfig:       t.tlsconfig.Clone(),
	}

	log.I("doh: new transport(%s): %s; relay? %t; addrs? %v; resolved? %t", t.typ, t.url, relay != nil, addrs, renewed)
	return t, nil
}

type proxytransport struct {
	p ipn.Proxy
	c *http.Client
}

func (t *transport) httpClientFor(p ipn.Proxy) (*http.Client, error) {
	t.pxcmu.RLock()
	pxtr, ok := t.pxclients[p.ID()]
	t.pxcmu.RUnlock()

	same := pxtr != nil && pxtr.p == p
	if ok && same {
		return pxtr.c, nil
	}

	client := &http.Client{
		// higher timeouts for proxies
		Transport: &http.Transport{
			Dial:                  p.Dialer().Dial,
			ForceAttemptHTTP2:     true,
			IdleConnTimeout:       5 * time.Minute,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			// SNI (hostname) must always be inferred from http-request
			TLSClientConfig: t.tlsconfig.Clone(),
		},
	}
	// last writer wins
	t.pxcmu.Lock()
	t.pxclients[p.ID()] = &proxytransport{p: p, c: client}
	t.pxcmu.Unlock()

	return client, nil
}

// Given a raw DNS query (including the query ID), this function sends the
// query.  If the query is successful, it returns the response and a nil qerr.  Otherwise,
// it returns a SERVFAIL response and a qerr with a status value indicating the cause.
// Independent of the query's success or failure, this function also returns the
// address of the server on a best-effort basis, or nil if the address could not
// be determined.
func (t *transport) doDoh(pid string, q *dns.Msg) (response *dns.Msg, blocklists string, elapsed time.Duration, qerr *dnsx.QueryError) {
	start := time.Now()
	q, err := AddEdnsPadding(q)
	if err != nil {
		log.D("doh: failed to add padding: %v", err)
		elapsed = time.Since(start)
		qerr = dnsx.NewInternalQueryError(err)
		return
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

	response, blocklists, elapsed, qerr = t.send(pid, req)

	// restore dns query id
	q.Id = id
	if response != nil {
		response.Id = id
	} else { // override response with servfail
		response = xdns.Servfail(q)
	}
	return
}

func (t *transport) fetch(pid string, req *http.Request) (res *http.Response, err error) {
	userelay := t.relay != nil
	hasproxy := t.proxies != nil
	useproxy := len(pid) != 0 // if pid == dnsx.NetNoProxy, then px is ipn.Base

	client := &t.client
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
			return nil, dnsx.ErrNoProxyProvider
		}
		// or: ipn.Fetch(px, req)
		client, err = t.httpClientFor(px)
		if err != nil {
			return
		}
		log.V("doh: using proxy %s:%s for %s", px.ID(), px.GetAddr(), req.URL)
	} else {
		log.V("doh: no proxy %s for %s", pid, req.URL)
	}
	return client.Do(req)
}

func (t *transport) do(pid string, req *http.Request) (ans []byte, blocklists string, elapsed time.Duration, qerr *dnsx.QueryError) {
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
				dialers.Confirm(hostname, server)
				return
			} else {
				log.D("doh: disconfirming %s, %s", hostname, server)
				dialers.Disconfirm3(hostname, server)
			}
		}
		if qerr != nil {
			log.E("doh: query failed: %v", qerr)
			if conn != nil {
				log.I("doh: close failing doh conn to %s", hostname)
				clos(conn)
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

	// todo: check if content-type is [doh|odoh] mime type
	log.V("doh: got response")
	ans, err = io.ReadAll(httpResponse.Body)

	if err != nil {
		qerr = dnsx.NewSendFailedQueryError(err)
		return
	}
	clos(httpResponse.Body)
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

	blocklists = t.rdnsBlockstamp(httpResponse)
	return
}

func (t *transport) send(pid string, req *http.Request) (msg *dns.Msg, blocklists string, elapsed time.Duration, qerr *dnsx.QueryError) {
	var ans []byte
	var err error
	ans, blocklists, elapsed, qerr = t.do(pid, req)
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

func (t *transport) rdnsBlockstamp(res *http.Response) (blocklistStamp string) {
	if res == nil { // should not be nil
		return
	}
	blocklistStamp = res.Header.Get(xdns.GetBlocklistStampHeaderKey())
	log.V("doh: stamp %s; header %v", res.Header, blocklistStamp)
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
	var blocklists string
	var elapsed time.Duration
	var qerr *dnsx.QueryError

	_, pid := xdns.Net2ProxyID(network)
	if t.typ == dnsx.DOH {
		r, blocklists, elapsed, qerr = t.doDoh(pid, q)
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
	smm.Blocklists = blocklists
	noOdohRelay := len(smm.RelayServer) <= 0
	if noOdohRelay {
		if t.relay != nil {
			smm.RelayServer = x.SummaryProxyLabel + t.relay.ID()
		} else if !dnsx.IsLocalProxy(pid) {
			smm.RelayServer = x.SummaryProxyLabel + pid
		}
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

func clos(c io.Closer) {
	core.Close(c)
}
