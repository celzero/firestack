// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"net"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	tx "github.com/elazarl/goproxy"
)

type http1 struct {
	Proxy
	dialfn func(network, addr string) (net.Conn, error)
	id     string
	opts   *settings.ProxyOptions
	status int
}

func NewHTTPProxy(id string, b protect.Blocker, po *settings.ProxyOptions) (Proxy, error) {
	var err error
	if po == nil {
		log.W("proxy: err setting up http1(%v): %v", po, err)
		return nil, errMissingProxyOpt
	}

	hp := tx.NewProxyHttpServer()
	hp.Tr.Dial = protect.MakeNsDialer(b).Dial
	hp.Verbose = settings.Debug
	dialfn := hp.NewConnectDialToProxy(po.AsUrl())

	if err != nil {
		log.W("proxy: err creating up http1(%v): %v", po, err)
		return nil, err
	}

	h := &http1{
		dialfn: dialfn,
		id:     id,
	}

	return h, nil
}

func (h *http1) Dial(network, addr string) (c net.Conn, err error) {
	if c, err = h.dialfn(network, addr); err != nil {
		log.W("proxy: http1 dial %s -> %s; err %v", h.GetAddr(), addr, err)
		h.status = TKO
	}
	h.status = TOK
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
	return nil
}
