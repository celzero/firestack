// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     Copyright 2016 Michal Witkowski. All Rights Reserved.

package h1

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/log"
)

// code adopted from github.com/mwitkow/go-http-dialer/blob/378f744fb2/dialer.go#L1

type Opt func(*HttpTunnel)

func New(proxyUrl *url.URL, opts ...Opt) *HttpTunnel {
	t := &HttpTunnel{
		parentDialer: &net.Dialer{},
	}
	t.parseProxyUrl(proxyUrl)
	for _, opt := range opts {
		opt(t)
	}
	_, ok := dialers.New(t.hostname, nil)
	log.I("http: new dialer for %s; resolved? %t", t.hostname, ok)
	return t
}

// WithTls sets the tls.Config to be used (e.g. CA certs) when connecting to an HTTP proxy over TLS.
func WithTls(tlsConfig *tls.Config) Opt {
	return func(t *HttpTunnel) {
		t.tlsConfig = tlsConfig
	}
}

// WithDialer allows the customization of the underlying net.Dialer used for establishing TCP connections to the proxy.
func WithDialer(dialer *net.Dialer) Opt {
	return func(t *HttpTunnel) {
		t.parentDialer = dialer
	}
}

// WithConnectionTimeout customizes the underlying net.Dialer.Timeout.
func WithConnectionTimeout(timeout time.Duration) Opt {
	return func(t *HttpTunnel) {
		t.parentDialer.Timeout = timeout
	}
}

// WithProxyAuth allows you to add ProxyAuthorization to calls.
func WithProxyAuth(auth ProxyAuthorization) Opt {
	return func(t *HttpTunnel) {
		t.auth = auth
	}
}

// HttpTunnel represents a configured HTTP Connect Tunnel dialer.
type HttpTunnel struct {
	parentDialer *net.Dialer
	isTls        bool
	hostname     string
	proxyAddr    string
	tlsConfig    *tls.Config
	auth         ProxyAuthorization
}

func (t *HttpTunnel) parseProxyUrl(proxyUrl *url.URL) {
	t.hostname = proxyUrl.Hostname()
	t.proxyAddr = proxyUrl.Host
	if strings.ToLower(proxyUrl.Scheme) == "https" {
		if !strings.Contains(t.proxyAddr, ":") {
			t.proxyAddr = t.proxyAddr + ":443"
		}
		t.isTls = true
	} else {
		if !strings.Contains(t.proxyAddr, ":") {
			t.proxyAddr = t.proxyAddr + ":8080"
		}
		t.isTls = false
	}
}

func (t *HttpTunnel) dialProxy() (net.Conn, error) {
	if !t.isTls {
		return dialers.ProxyDial(t.parentDialer, "tcp", t.proxyAddr)
	}
	td := &tls.Dialer{
		NetDialer: t.parentDialer,
		Config:    t.tlsConfig.Clone(),
	}
	return dialers.TlsDial(td, "tcp", t.proxyAddr)
}

// Dial is an implementation of net.Dialer, and returns a TCP connection handle to the host that HTTP CONNECT reached.
func (t *HttpTunnel) Dial(network string, address string) (net.Conn, error) {
	if !strings.Contains(network, "tcp") { // tcp4, tcp6, tcp
		return nil, fmt.Errorf("http1: tunnel: network type '%v' unsupported (only 'tcp')", network)
	}
	conn, err := t.dialProxy()
	if err != nil {
		return nil, fmt.Errorf("http1: tunnel: failed dialing to proxy: %v", err)
	}
	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: address},
		Host:   address, // This is weird
		Header: make(http.Header),
	}
	if t.auth != nil && t.auth.InitialResponse() != "" {
		req.Header.Set(hdrProxyAuthResp, t.auth.Type()+" "+t.auth.InitialResponse())
	}
	resp, err := t.doRoundtrip(conn, req)
	if err != nil {
		clos(conn)
		return nil, err
	}
	// Retry request with auth, if available.
	if resp.StatusCode == http.StatusProxyAuthRequired && t.auth != nil {
		responseHdr, err := t.performAuthChallengeResponse(resp)
		if err != nil {
			clos(conn)
			return nil, err
		}
		req.Header.Set(hdrProxyAuthResp, t.auth.Type()+" "+responseHdr)
		resp, err = t.doRoundtrip(conn, req)
		if err != nil {
			clos(conn)
			return nil, err
		}
	}

	if resp.StatusCode != 200 {
		clos(conn)
		return nil, fmt.Errorf("http1: tunnel: failed proxying %d: %s", resp.StatusCode, resp.Status)
	}
	return conn, nil
}

func clos(c net.Conn) {
	core.CloseConn(c)
}

func (t *HttpTunnel) doRoundtrip(conn net.Conn, req *http.Request) (*http.Response, error) {
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("http1: tunnel: failed writing request: %v", err)
	}
	// Doesn't matter, discard this bufio.
	br := bufio.NewReader(conn)
	return http.ReadResponse(br, req)

}

func (t *HttpTunnel) performAuthChallengeResponse(resp *http.Response) (string, error) {
	respAuthHdr := resp.Header.Get(hdrProxyAuthReq)
	if !strings.Contains(respAuthHdr, t.auth.Type()+" ") {
		return "", fmt.Errorf("http1: tunnel: expected '%v' Proxy authentication, got: '%v'", t.auth.Type(), respAuthHdr)
	}
	splits := strings.SplitN(respAuthHdr, " ", 2)
	if len(splits) <= 1 {
		return "", fmt.Errorf("http1: tunnel: malformed Proxy-Authenticate header: '%v'", respAuthHdr)
	}
	challenge := splits[1]
	return t.auth.ChallengeResponse(challenge), nil
}
