// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"crypto/tls"
	"net/url"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	tx "github.com/celzero/firestack/intra/ipn/h1"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	"golang.org/x/net/proxy"
)

type http1 struct {
	nofwd       // no forwarding/listening
	skiprefresh // no refresh
	outbound    proxy.Dialer
	id          string
	opts        *settings.ProxyOptions
	lastdial    time.Time
	status      *core.Volatile[int]
}

func NewHTTPProxy(id string, c protect.Controller, po *settings.ProxyOptions) (*http1, error) {
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
			MinVersion: tls.VersionTLS12,
		})
		opts = append(opts, opttls)
	}
	if po.HasAuth() {
		optauth := tx.WithProxyAuth(tx.AuthBasic(po.Auth.User, po.Auth.Password))
		opts = append(opts, optauth)
	}

	hp := tx.New(u, opts...)

	h := &http1{
		outbound: hp, // does not support udp
		id:       id,
		opts:     po,
	}

	log.D("proxy: http1: created %s with opts(%s)", h.ID(), po)

	return h, nil
}

// Dial implements Proxy.
func (h *http1) Dial(network, addr string) (c protect.Conn, err error) {
	if h.status.Load() == END {
		return nil, errProxyStopped
	}

	h.lastdial = time.Now()
	// dialers.ProxyDial not needed, because
	// tx.HttpTunnel.Dial() supports dialing into hostnames
	if c, err = dialers.ProxyDial(h.outbound, network, addr); err != nil {
		h.status.Store(TKO)
	} else {
		h.status.Store(TOK)
	}
	log.I("proxy: http1: dial(%s) from %s to %s; err? %v", network, h.GetAddr(), addr, err)
	return
}

func (h *http1) Dialer() protect.RDialer {
	return h
}

func (h *http1) DNS() string {
	return nodns
}

func (h *http1) ID() string {
	return h.id
}

func (h *http1) Type() string {
	return HTTP1
}

func (*http1) Router() x.Router {
	return PROXYGATEWAY
}

func (h *http1) GetAddr() string {
	return h.opts.IPPort
}

func (h *http1) Status() int {
	s := h.status.Load()
	if s != END && idling(h.lastdial) {
		return TZZ
	}
	return s
}

func (h *http1) Stop() error {
	h.status.Store(END)
	log.I("proxy: http1: stopped %s", h.id)
	return nil
}

func (h *http1) onProtoChange() (string, bool) {
	return h.opts.FullUrl(), true
}
