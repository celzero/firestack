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
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/cloudflare/odoh-go"
)

const dohmimetype = "application/dns-message"

type odohtransport struct {
	omu              sync.RWMutex // protects odohConfig
	odohproxy        string       // proxy url
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
	wkclient       http.Client  // to fetch well-known odoh configs
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

func newTransport(typ, id, rawurl, target string, addrs []string, px ipn.Proxies, ctl protect.Controller) (*transport, error) {
	// TODO: client auth
	var auth ClientAuth
	skipTLSVerify := false
	isodoh := typ == dnsx.ODOH

	var renewed bool
	var relay ipn.Proxy
	if px != nil {
		relay, _ = px.GetProxy(id)
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
		_, renewed = dialers.New(t.hostname, addrs)
	} else {
		t.odohtransport = &odohtransport{}

		proxy := rawurl         // may be empty
		rawurl := odohconfigdns // never empty

		parsedurl, err := url.Parse(rawurl)
		if err != nil {
			return nil, err
		}
		targeturl, err := url.Parse(target)
		if err != nil {
			return nil, err
		}
		proxyurl, _ := url.Parse(proxy)

		// addrs are proxy addresses if proxy is not empty, otherwise target addresses
		if proxyurl != nil && proxyurl.Hostname() != "" {
			_, renewed = dialers.New(proxyurl.Hostname(), addrs)
			if len(proxyurl.Path) <= 1 { // should not be "" or "/"
				proxyurl.Path = odohproxypath
			}
			t.odohproxy = proxyurl.String()
			t.odohproxyname = proxyurl.Hostname()
		} else if targeturl != nil && targeturl.Hostname() != "" {
			_, renewed = dialers.New(targeturl.Hostname(), addrs)
		}

		t.url = parsedurl.String()
		t.hostname = parsedurl.Hostname()
		t.odohtargetname = targeturl.Hostname()
		if len(targeturl.Path) > 1 { // should not be "" or "/"
			t.odohtargetpath = targeturl.Path
		} else {
			t.odohtargetpath = odohtargetpath // default: "/dns-query"
		}

		// setup a client to fetch well-known odoh configs
		// with tlsclientconfig set to nil, so the underlying
		// transport determines it from the url
		t.wkclient = http.Client{
			Transport: &http.Transport{
				Dial:                  t.dial,
				ForceAttemptHTTP2:     true,
				IdleConnTimeout:       2 * time.Minute,
				TLSHandshakeTimeout:   3 * time.Second,
				ResponseHeaderTimeout: 20 * time.Second,
			},
		}

		log.I("doh: ODOH for %s -> %s", proxy, target)
	}

	// Supply a client certificate during TLS handshakes.
	if auth != nil {
		signer := newClientAuthWrapper(auth)
		t.tlsconfig = &tls.Config{
			GetClientCertificate: signer.GetClientCertificate,
			// ServerName:           t.hostname,
		}
	} else {
		t.tlsconfig = &tls.Config{
			InsecureSkipVerify: skipTLSVerify,
			// ServerName:         t.hostname,
		}
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
			TLSClientConfig:       t.tlsconfig.Clone(),
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
func (t *transport) doDoh(pid string, q []byte) (response []byte, blocklists string, elapsed time.Duration, qerr *dnsx.QueryError) {
	start := time.Now()
	q, err := AddEdnsPadding(q)
	if err != nil {
		log.D("doh: failed to add padding: %v", err)
		elapsed = time.Since(start)
		qerr = dnsx.NewInternalQueryError(err)
		return
	}

	// zero out the query id
	id := binary.BigEndian.Uint16(q)
	binary.BigEndian.PutUint16(q, 0)

	req, err := t.asDohRequest(q)
	if err != nil {
		log.D("doh: failed to create request: %v", err)
		elapsed = time.Since(start)
		qerr = dnsx.NewInternalQueryError(err)
		return
	}

	response, blocklists, elapsed, qerr = t.send(pid, req)

	if qerr == nil { // restore dns query id
		zeroid := binary.BigEndian.Uint16(response)
		if zeroid != 0 {
			log.W("doh: ans qid not zero %d; origid: %d", zeroid, id)
		}
		binary.BigEndian.PutUint16(response, id)
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
			if px, err = t.proxies.GetProxy(pid); err != nil {
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

func (t *transport) send(pid string, req *http.Request) (ans []byte, blocklists string, elapsed time.Duration, qerr *dnsx.QueryError) {
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
		usedproxy := len(pid) > 0 // pid == dnsx.NetNoProxy => ipn.Base
		hasserveraddr := server != nil && !usedrelay && !usedproxy

		if hasserveraddr {
			if qerr == nil {
				// record a working IP address for this server
				dialers.Confirm(hostname, server)
				return
			} else {
				log.D("doh: disconfirming %s, %s", hostname, server)
				dialers.Disconfirm(hostname, server)
			}
		}
		if qerr != nil {
			log.E("doh: query failed: %v", qerr)
			if conn != nil {
				log.I("doh: close failing doh conn to %s", hostname)
				conn.Close()
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
			log.V("doh: connect-start(%s, %s)", network, addr)
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			log.V("doh: wrote-req(%v)", info)
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
	httpResponse.Body.Close()
	log.V("doh: closed response")

	// update the hostname, which could have changed due to a redirect
	hostname = httpResponse.Request.URL.Hostname()

	sc := httpResponse.StatusCode
	if sc != http.StatusOK {
		// 4xx
		if sc >= http.StatusBadRequest && sc < http.StatusInternalServerError {
			qerr = dnsx.NewClientQueryError(fmt.Errorf("http-status: %d", sc))
		} else {
			qerr = dnsx.NewTransportQueryError(fmt.Errorf("http-status: %d", sc))
		}
		return
	}
	if len(ans) < 2 {
		qerr = dnsx.NewBadResponseQueryError(fmt.Errorf("response length is %d", len(ans)))
		return
	}

	blocklists = t.rdnsBlockstamp(httpResponse)
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

func (t *transport) asDohRequest(q []byte) (req *http.Request, err error) {
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

func (t *transport) Query(network string, q []byte, smm *dnsx.Summary) (r []byte, err error) {
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
	ans := xdns.AsMsg(r)
	t.status = status

	t.est.Add(elapsed.Seconds())
	smm.Latency = elapsed.Seconds()
	smm.RData = xdns.GetInterestingRData(ans)
	smm.RCode = xdns.Rcode(ans)
	smm.RTtl = xdns.RTtl(ans)
	smm.Status = status
	smm.Blocklists = blocklists
	noOdohRelay := len(smm.RelayServer) <= 0
	if noOdohRelay {
		if t.relay != nil {
			smm.RelayServer = t.relay.GetAddr()
		} else if !dnsx.IsLocalProxy(pid) {
			smm.RelayServer = dnsx.SummaryProxyLabel + pid
		}
	}
	log.V("doh: (p/px %s/%s); len(res): %d, data: %s, via: %s, err? %v", network, pid, len(r), smm.RData, smm.RelayServer, err)
	return r, err
}

func (t *transport) P50() int64 {
	return t.est.Get()
}

func (t *transport) GetAddr() string {
	if t.typ == dnsx.DOH {
		return t.hostname
	}
	return t.odohtargetname
}

func (t *transport) Status() int {
	return t.status
}
