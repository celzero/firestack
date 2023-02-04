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
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/doh/ipmap"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/split"
	"github.com/celzero/firestack/intra/xdns"
)

// If the server sends an invalid reply, we start a "servfail hangover"
// of this duration, during which all queries are rejected.
// This rate-limits queries to misconfigured servers (e.g. wrong URL).
const hangoverDuration = 10 * time.Second

// TODO: Keep a context here so that queries can be canceled.
type transport struct {
	dnsx.Transport
	id                 string
	url                string
	hostname           string
	port               int
	ips                ipmap.IPMap
	client             http.Client
	dialer             *net.Dialer
	status             int
	hangoverLock       sync.RWMutex
	hangoverExpiration time.Time
}

// Wait up to three seconds for the TCP handshake to complete.
const tcpTimeout time.Duration = 3 * time.Second

func (t *transport) dial(network, addr string) (net.Conn, error) {
	log.Debugf("Dialing %s", addr)
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
		log.Debugf("Trying confirmed IP %s for addr %s", confirmed.String(), addr)
		if conn, err = split.DialWithSplitRetry(t.dialer, tcpaddr(confirmed), nil); err == nil {
			log.Infof("Confirmed IP %s worked", confirmed.String())
			return conn, nil
		}
		log.Debugf("Confirmed IP %s failed with err %v", confirmed.String(), err)
		ips.Disconfirm(confirmed)
	}

	log.Debugf("Trying all IPs")
	for _, ip := range ips.GetAll() {
		if ip.Equal(confirmed) {
			// Don't try this IP twice.
			continue
		}
		if conn, err = split.DialWithSplitRetry(t.dialer, tcpaddr(ip), nil); err == nil {
			log.Infof("Found working IP: %s", ip.String())
			return conn, nil
		}
	}
	return nil, err
}

// NewTransport returns a DoH DNSTransport, ready for use.
// This is a POST-only DoH implementation, so the DoH template should be a URL.
// `rawurl` is the DoH template in string form.
// `addrs` is a list of domains or IP addresses to use as fallback, if the hostname
//   lookup fails or returns non-working addresses.
// `dialer` is the dialer that the transport will use.  The transport will modify the dialer's
//   timeout but will not mutate it otherwise.
// `auth` will provide a client certificate if required by the TLS server.
// `listener` will receive the status of each DNS query when it is complete.
func NewTransport(id, rawurl string, addrs []string, dialer *net.Dialer, auth ClientAuth) (dnsx.Transport, error) {
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	parsedurl, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	if parsedurl.Scheme != "https" {
		return nil, fmt.Errorf("bad scheme: %s", parsedurl.Scheme)
	}
	// Resolve the hostname and put those addresses first.
	portStr := parsedurl.Port()
	var port int
	if len(portStr) > 0 {
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return nil, err
		}
	} else {
		port = 443
	}
	t := &transport{
		id:       id,
		url:      rawurl,
		hostname: parsedurl.Hostname(),
		port:     port,
		dialer:   dialer,
		ips:      ipmap.NewIPMap(dialer.Resolver),
		status:   dnsx.Start,
	}

	ipset := t.ips.Of(t.hostname, addrs)
	if ipset.Empty() {
		// IPs instead resolved just-in-time with ipmap.Get in transport.dial
		log.Warnf("zero bootstrap ips %s", t.hostname)
	}

	// Supply a client certificate during TLS handshakes.
	var tlsconfig *tls.Config
	if auth != nil {
		signer := newClientAuthWrapper(auth)
		tlsconfig = &tls.Config{
			GetClientCertificate: signer.GetClientCertificate,
		}
	}

	// Override the dial function.
	t.client.Transport = &http.Transport{
		Dial:                  t.dial,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   tcpTimeout,
		ResponseHeaderTimeout: 20 * time.Second, // Same value as Android DNS-over-TLS
		TLSClientConfig:       tlsconfig,
	}
	return t, nil
}

// Given a raw DNS query (including the query ID), this function sends the
// query.  If the query is successful, it returns the response and a nil qerr.  Otherwise,
// it returns a SERVFAIL response and a qerr with a status value indicating the cause.
// Independent of the query's success or failure, this function also returns the
// address of the server on a best-effort basis, or nil if the address could not
// be determined.
func (t *transport) doQuery(q []byte) (response []byte, blocklists string, server *net.TCPAddr, elapsed time.Duration, qerr *dnsx.QueryError) {

	start := time.Now()
	t.hangoverLock.RLock()
	inHangover := time.Now().Before(t.hangoverExpiration)
	t.hangoverLock.RUnlock()
	if inHangover {
		response = xdns.Servfail(q)
		qerr = dnsx.NewTransportQueryError(errors.New("forwarder is in servfail hangover"))
		elapsed = time.Since(start)
		return
	}

	// Add padding to the raw query
	q, err := AddEdnsPadding(q)
	if err != nil {
		elapsed = time.Since(start)
		qerr = dnsx.NewInternalQueryError(err)
		return
	}

	// zero out the query ID.
	id := binary.BigEndian.Uint16(q)
	binary.BigEndian.PutUint16(q, 0)

	var hostname string
	response, hostname, server, blocklists, elapsed, qerr = t.sendRequest(id, q)

	// restore dns query id
	binary.BigEndian.PutUint16(q, id)

	if qerr != nil { // only on send-request errors
		if !qerr.SendFailed() {
			t.hangoverLock.Lock()
			t.hangoverExpiration = time.Now().Add(hangoverDuration)
			t.hangoverLock.Unlock()
		}
		response = xdns.Servfail(q)
	} else if server != nil {
		// Record a working IP address for this server
		t.ips.Get(hostname).Confirm(server.IP)
	}

	return
}

func (t *transport) sendRequest(id uint16, q []byte) (response []byte, hostname string, server *net.TCPAddr, blocklists string, elapsed time.Duration, qerr *dnsx.QueryError) {
	hostname = t.hostname

	// The connection used for this request.  If the request fails, we will close
	// this socket, in case it is no longer functioning.
	var conn net.Conn
	start := time.Now()

	// Error cleanup function.  If the query fails, this function will close the
	// underlying socket and disconfirm the server IP.  Empirically, sockets often
	// become unresponsive after a network change, causing timeouts on all requests.
	defer func() {
		if qerr == nil {
			return
		}
		log.Infof("%d Query failed: %v", id, qerr)
		if server != nil {
			log.Debugf("%d Disconfirming %s", id, server.IP.String())
			t.ips.Get(hostname).Disconfirm(server.IP)
		}
		if conn != nil {
			log.Infof("%d Closing failing DoH socket", id)
			conn.Close()
		}
	}()

	req, err := http.NewRequest(http.MethodPost, t.url, bytes.NewBuffer(q))
	if err != nil {
		elapsed = time.Since(start)
		qerr = dnsx.NewInternalQueryError(err)
		return
	}

	// Add a trace to the request in order to expose the server's IP address.
	// Only GotConn performs any action; the other methods just provide debug logs.
	// GotConn runs before client.Do() returns, so there is no data race when
	// reading the variables it has set.
	trace := httptrace.ClientTrace{
		GetConn: func(hostPort string) {
			log.Debugf("%d GetConn(%s)", id, hostPort)
		},
		GotConn: func(info httptrace.GotConnInfo) {
			log.Debugf("%d GotConn(%v)", id, info)
			if info.Conn == nil {
				return
			}
			conn = info.Conn
			// info.Conn is a DuplexConn, so RemoteAddr is actually a TCPAddr.
			server = conn.RemoteAddr().(*net.TCPAddr)
		},
		PutIdleConn: func(err error) {
			log.Debugf("%d PutIdleConn(%v)", id, err)
		},
		GotFirstResponseByte: func() {
			log.Debugf("%d GotFirstResponseByte()", id)
		},
		Got100Continue: func() {
			log.Debugf("%d Got100Continue()", id)
		},
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			log.Debugf("%d Got1xxResponse(%d, %v)", id, code, header)
			return nil
		},
		DNSStart: func(info httptrace.DNSStartInfo) {
			log.Debugf("%d DNSStart(%v)", id, info)
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			log.Debugf("%d, DNSDone(%v)", id, info)
		},
		ConnectStart: func(network, addr string) {
			start = time.Now() // re...start
			log.Debugf("%d ConnectStart(%s, %s)", id, network, addr)
		},
		ConnectDone: func(network, addr string, err error) {
			log.Debugf("%d ConnectDone(%s, %s, %v)", id, network, addr, err)
		},
		TLSHandshakeStart: func() {
			log.Debugf("%d TLSHandshakeStart()", id)
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			log.Debugf("%d TLSHandshakeDone(%v, %v)", id, state, err)
		},
		WroteHeaders: func() {
			log.Debugf("%d WroteHeaders()", id)
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			log.Debugf("%d WroteRequest(%v)", id, info)
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &trace))

	const mimetype = "application/dns-message"
	req.Header.Set("Content-Type", mimetype)
	req.Header.Set("Accept", mimetype)
	req.Header.Set("User-Agent", "")

	log.Debugf("%d Sending query", id)
	httpResponse, err := t.client.Do(req)

	if err != nil {
		elapsed = time.Since(start)
		qerr = dnsx.NewSendFailedQueryError(err)
		return
	}

	log.Debugf("%d Got response", id)
	response, err = ioutil.ReadAll(httpResponse.Body)
	elapsed = time.Since(start)

	if err != nil {
		qerr = dnsx.NewBadResponseQueryError(err)
		return
	}
	httpResponse.Body.Close()
	log.Debugf("%d Closed response", id)

	// Update the hostname, which could have changed due to a redirect.
	hostname = httpResponse.Request.URL.Hostname()

	if httpResponse.StatusCode != http.StatusOK {
		reqBuf := new(bytes.Buffer)
		req.Write(reqBuf)
		respBuf := new(bytes.Buffer)
		httpResponse.Write(respBuf)
		log.Debugf("%d request: %s\nresponse: %s", id, reqBuf.String(), respBuf.String())

		qerr = dnsx.NewTransportQueryError(fmt.Errorf("http-status: %d", httpResponse.StatusCode))
		return
	}

	if len(response) >= 2 {
		if binary.BigEndian.Uint16(response) == 0 {
			binary.BigEndian.PutUint16(response, id)
			blocklists = t.rdnsBlockstamp(httpResponse)
		} else {
			qerr = dnsx.NewBadResponseQueryError(errors.New("nonzero response ID"))
		}
	} else {
		qerr = dnsx.NewBadResponseQueryError(fmt.Errorf("response length is %d", len(response)))
	}

	return
}

func (t *transport) rdnsBlockstamp(res *http.Response) (blocklistStamp string) {
	blocklistStamp = res.Header.Get(xdns.GetBlocklistStampHeaderKey())
	log.Debugf("header", res.Header, "st", blocklistStamp)
	return
}

func (t *transport) ID() string {
	return t.id
}

func (t *transport) Type() string {
	return dnsx.DOH
}

func (t *transport) Query(_ string, q []byte, summary *dnsx.Summary) (r []byte, err error) {

	response, blocklists, _, elapsed, qerr := t.doQuery(q)

	status := dnsx.Complete
	if qerr != nil {
		status = qerr.Status()
		err = qerr.Unwrap()
	}
	ans := xdns.AsMsg(response)
	t.status = status
	summary.Latency = elapsed.Seconds()
	summary.RData = xdns.GetInterestingRData(ans)
	summary.RCode = xdns.Rcode(ans)
	summary.RTtl = xdns.RTtl(ans)
	summary.Server = t.GetAddr()
	summary.Status = status
	summary.Blocklists = blocklists

	return response, err
}

func (t *transport) GetAddr() string {
	return t.hostname
}

func (t *transport) Status() int {
	return t.status
}
