// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"net/url"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	tx "github.com/mwitkow/go-http-dialer"
	"golang.org/x/net/proxy"
)

type http1 struct {
	Proxy
	dialer proxy.Dialer
	id     string
	opts   *settings.ProxyOptions
	status int
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

	var hp *tx.HttpTunnel
	optdialer := tx.WithDialer(protect.MakeNsDialer(c))
	if po.HasAuth() {
		optauth := tx.WithProxyAuth(tx.AuthBasic(po.Auth.User, po.Auth.Password))
		hp = tx.New(u, optdialer, optauth)
	} else {
		hp = tx.New(u, optdialer)
	}

	if err != nil {
		log.W("proxy: http1: err creating w(%v): %v", po, err)
		return nil, err
	}

	h := &http1{
		dialer: hp,
		id:     id,
		opts:   po,
	}

	log.D("proxy: http1: created %s with opts(%s)", h.ID(), po)

	return h, nil
}

func (h *http1) Dial(network, addr string) (c Conn, err error) {
	if h.status == END {
		return nil, errProxyStopped
	}

	if c, err = h.dialer.Dial(network, addr); err != nil {
		h.status = TKO
	} else {
		h.status = TOK
	}
	log.I("proxy: http1: dial(%s) from %s to %s; err? %v", network, h.GetAddr(), addr, err)
	return
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
