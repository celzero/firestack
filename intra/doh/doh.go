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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/core/ipmap"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/split"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/cloudflare/odoh-go"
)

// If the server sends an invalid reply, we start a "servfail hangover"
// of this duration, during which all queries are rejected.
// This rate-limits queries to misconfigured servers (e.g. wrong URL).
const hangoverDuration = 10 * time.Second
const dohmimetype = "application/dns-message"

var errInHangover = errors.New("forwarder is in servfail hangover")

type odohtransport struct {
	omu              sync.RWMutex // protects odohConfig
	odohproxy        string       // proxy url
	odohtargetname   string       // target hostname
	odohtargetpath   string       // target path
	odohConfig       *odoh.ObliviousDoHConfig
	odohConfigExpiry time.Time
	preferWK         bool // prefer .well-known over svcb/https probe
}

// TODO: Keep a context here so that queries can be canceled.
type transport struct {
	*odohtransport // stackoverflow.com/a/28505394
	dnsx.Transport
	id                 string
	typ                string // dnsx.DOH / dnsx.ODOH
	url                string // endpoint URL
	hostname           string // endpoint hostname
	ips                ipmap.IPMap
	client             http.Client
	dialer             *net.Dialer
	status             int
	est                core.P2QuantileEstimator
	hangoverLock       sync.RWMutex
	hangoverExpiration time.Time
}

func (t *transport) dial(network, addr string) (net.Conn, error) {
	log.D("doh: dialing %s", addr)
	domain, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}

	tcpaddr := func(ip net.IP) *net.TCPAddr {
		return &net.TCPAddr{IP: ip, Port: port}
	}

	// TODO: Improve IP fallback strategy with parallelism and Happy Eyeballs.
	var conn net.Conn
	ips := t.ips.Get(domain)
	confirmed := ips.Confirmed()
	if confirmed != nil {
		log.D("doh: trying IP %s for addr %s", confirmed.String(), addr)
		if conn, err = split.DialWithSplitRetry(t.dialer, tcpaddr(confirmed), nil); err == nil {
			log.I("doh: confirmed IP %s worked", confirmed.String())
			return conn, nil
		}
		log.D("doh: IP %s failed with err %v", confirmed.String(), err)
		ips.Disconfirm(confirmed)
	}

	log.D("doh: trying all IPs")
	for _, ip := range ips.GetAll() {
		if ip.Equal(confirmed) {
			continue // don't try this IP again
		}
		if conn, err = split.DialWithSplitRetry(t.dialer, tcpaddr(ip), nil); err == nil {
			log.I("doh: found working IP: %s", ip.String())
			return conn, nil
		}
	}
	return nil, err
}

// NewTransport returns a DoH DNSTransport, ready for use.
// This is a POST-only DoH implementation, so the DoH template should be a URL.
// `rawurl` is the DoH template in string form.
// `addrs` is a list of domains or IP addresses to use as fallback, if the hostname
//
//	lookup fails or returns non-working addresses.
//
// `dialer` is the dialer that the transport will use.  The transport will modify the dialer's
//
//	timeout but will not mutate it otherwise.
//
// `auth` will provide a client certificate if required by the TLS server.
// `listener` will receive the status of each DNS query when it is complete.
func NewTransport(id, rawurl string, addrs []string, dialer *net.Dialer) (dnsx.Transport, error) {
	return newTransport(dnsx.DOH, id, rawurl, "", addrs, dialer)
}

func NewOdohTransport(id, endpoint, target string, addrs []string, dailer *net.Dialer) (dnsx.Transport, error) {
	return newTransport(dnsx.ODOH, id, endpoint, target, addrs, dailer)
}

func newTransport(typ, id, rawurl, target string, addrs []string, dialer *net.Dialer) (*transport, error) {
	// TODO: client auth
	var auth ClientAuth
	skipTLSVerify := false
	isodoh := typ == dnsx.ODOH

	if dialer == nil {
		dialer = &net.Dialer{}
	}

	t := &transport{
		id:     id,
		typ:    typ,
		dialer: dialer,
		ips:    ipmap.NewIPMap(dialer.Resolver),
		status: dnsx.Start,
		est:    core.NewP50Estimator(),
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
		_ = t.ips.Of(t.hostname, addrs)
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
			_ = t.ips.Of(proxyurl.Hostname(), addrs)
			if len(proxyurl.Path) <= 1 { // should not be "" or "/"
				proxyurl.Path = odohproxypath
			}
			t.odohproxy = proxyurl.String()
		} else if targeturl != nil && targeturl.Hostname() != "" {
			_ = t.ips.Of(targeturl.Hostname(), addrs)
		}

		t.url = parsedurl.String()
		t.hostname = parsedurl.Hostname()
		t.odohtargetname = targeturl.Hostname()
		if len(targeturl.Path) > 1 { // should not be "" or "/"
			t.odohtargetpath = targeturl.Path
		} else {
			t.odohtargetpath = odohtargetpath // default: "/dns-query"
		}
		log.I("doh: ODOH for %s -> %s", proxy, target)
	}

	// Supply a client certificate during TLS handshakes.
	var tlsconfig *tls.Config
	if auth != nil {
		signer := newClientAuthWrapper(auth)
		tlsconfig = &tls.Config{
			GetClientCertificate: signer.GetClientCertificate,
		}
	} else {
		tlsconfig = &tls.Config{
			InsecureSkipVerify: skipTLSVerify,
		}
	}
	// Override the dial function.
	t.client.Transport = &http.Transport{
		Dial:                  t.dial,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second, // Same value as Android DNS-over-TLS
		TLSClientConfig:       tlsconfig,
	}

	log.I("doh: new transport(%s): %s", t.typ, t.url)
	return t, nil
}

// Given a raw DNS query (including the query ID), this function sends the
// query.  If the query is successful, it returns the response and a nil qerr.  Otherwise,
// it returns a SERVFAIL response and a qerr with a status value indicating the cause.
// Independent of the query's success or failure, this function also returns the
// address of the server on a best-effort basis, or nil if the address could not
// be determined.
func (t *transport) doDoh(q []byte) (response []byte, blocklists string, elapsed time.Duration, qerr *dnsx.QueryError) {
	start := time.Now()
	q, err := AddEdnsPadding(q)
	if err != nil {
		elapsed = time.Since(start)
		qerr = dnsx.NewInternalQueryError(err)
		return
	}

	// zero out the query id
	id := binary.BigEndian.Uint16(q)
	binary.BigEndian.PutUint16(q, 0)

	req, err := t.asDohRequest(q)
	if err != nil {
		elapsed = time.Since(start)
		qerr = dnsx.NewInternalQueryError(err)
		return
	}

	response, blocklists, elapsed, qerr = t.send(req)

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

func (t *transport) send(req *http.Request) (ans []byte, blocklists string, elapsed time.Duration, qerr *dnsx.QueryError) {
	t.hangoverLock.RLock()
	inHangover := time.Now().Before(t.hangoverExpiration)
	t.hangoverLock.RUnlock()
	if inHangover {
		qerr = dnsx.NewTransportQueryError(errInHangover)
		return
	}

	var server *net.TCPAddr
	var conn net.Conn
	start := time.Now()
	// either t.hostname or t.odohtargetname or t.odohproxy
	hostname := req.URL.Hostname()

	// Error cleanup function.  If the query fails, this function will close the
	// underlying socket and disconfirm the server IP.  Empirically, sockets often
	// become unresponsive after a network change, causing timeouts on all requests.
	defer func() {
		elapsed = time.Since(start)

		if qerr == nil && server != nil {
			// record a working IP address for this server
			t.ips.Get(hostname).Confirm(server.IP)
			return
		}
		if qerr != nil {
			if !qerr.SendFailed() { // hangover only on send-request errs
				t.hangoverLock.Lock()
				t.hangoverExpiration = time.Now().Add(hangoverDuration)
				t.hangoverLock.Unlock()
			}
			if server != nil {
				log.D("doh: disconfirming %s, %s", hostname, server.IP)
				t.ips.Get(hostname).Disconfirm(server.IP)
			}
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
			server = conn.RemoteAddr().(*net.TCPAddr)
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

	log.V("doh: sending query")
	httpResponse, err := t.client.Do(req)

	if err != nil {
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

func (t *transport) Query(_ string, q []byte, summary *dnsx.Summary) (r []byte, err error) {
	var blocklists string
	var elapsed time.Duration
	var qerr *dnsx.QueryError
	if t.typ == dnsx.DOH {
		r, blocklists, elapsed, qerr = t.doDoh(q)
		summary.Server = t.hostname
	} else {
		r, elapsed, qerr = t.doOdoh(q)
		summary.Server = t.odohtargetname
		summary.RelayServer = t.odohproxy
	}

	status := dnsx.Complete
	if qerr != nil {
		status = qerr.Status()
		err = qerr.Unwrap()
	}
	ans := xdns.AsMsg(r)
	t.status = status

	t.est.Add(elapsed.Seconds())
	summary.Latency = elapsed.Seconds()
	summary.RData = xdns.GetInterestingRData(ans)
	summary.RCode = xdns.Rcode(ans)
	summary.RTtl = xdns.RTtl(ans)
	summary.Status = status
	summary.Blocklists = blocklists

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
