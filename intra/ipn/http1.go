// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"crypto/tls"
	"net/http"
	"net/url"

	"github.com/celzero/firestack/intra/dialers"
	tx "github.com/celzero/firestack/intra/ipn/h1"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	"golang.org/x/net/proxy"
)

type http1 struct {
	hc          *http.Client   // exported http client
	rd          *protect.RDial // exported rdial
	proxydialer proxy.Dialer
	id          string
	opts        *settings.ProxyOptions
	status      int
}

func NewHTTPProxy(id string, c protect.Controller, po *settings.ProxyOptions) (Proxy, error) {
	var err error
	if po == nil {
		log.W("proxy: err setting up http1 w(%v): %v", po, err)
		return nil, errMissingProxyOpt
	}

	u, err := url.Parse(po.Url())
	if err != nil {
		log.W("proxy: http1: err proxy opts(%v): %v", po, err)
		return nil, errProxyScheme
	}

	d := protect.MakeNsDialer(id, c)

	opts := make([]tx.Opt, 0)
	optdialer := tx.WithDialer(d)
	opts = append(opts, optdialer)
	if po.Scheme == "https" && len(po.Host) > 0 {
		opttls := tx.WithTls(&tls.Config{
			ServerName: po.Host,
		})
		opts = append(opts, opttls)
	}
	if po.HasAuth() {
		optauth := tx.WithProxyAuth(tx.AuthBasic(po.Auth.User, po.Auth.Password))
		opts = append(opts, optauth)
	}

	hp := tx.New(u, opts...)

	if err != nil {
		log.W("proxy: http1: err creating w(%v): %v", po, err)
		return nil, err
	}

	h := &http1{
		proxydialer: hp,
		id:          id,
		opts:        po,
	}
	h.rd = newRDial(h)
	h.hc = newHTTPClient(h.rd)

	log.D("proxy: http1: created %s with opts(%s)", h.ID(), po)

	return h, nil
}

func (h *http1) Dial(network, addr string) (c protect.Conn, err error) {
	if h.status == END {
		return nil, errProxyStopped
	}

	// dialers.ProxyDial not needed, because
	// tx.HttpTunnel.Dial() supports dialing into hostnames
	if c, err = dialers.ProxyDial(h.proxydialer, network, addr); err != nil {
		h.status = TKO
	} else {
		h.status = TOK
	}
	log.I("proxy: http1: dial(%s) from %s to %s; err? %v", network, h.GetAddr(), addr, err)
	return
}

func (h *http1) fetch(req *http.Request) (*http.Response, error) {
	stopped := h.status == END
	log.V("proxy: http1: %d; fetch(%s) from %s; ok? %t", h.id, req.URL, !stopped)
	if stopped {
		return nil, errProxyStopped
	}
	return h.hc.Do(req)
}

func (h *http1) Dialer() *protect.RDial {
	return h.rd
}

func (h *http1) DNS() string {
	return NoDNS
}

func (h *http1) ID() string {
	return h.id
}

func (h *http1) Type() string {
	return HTTP1
}

func (h *http1) GetAddr() string {
	return h.opts.IPPort
}

func (h *http1) Status() int {
	return h.status
}

func (h *http1) Stop() error {
	h.status = END
	log.I("proxy: http1: stopped %s", h.id)
	return nil
}

func (h *http1) Refresh() error { return nil }
