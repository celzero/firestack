// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"net"
	"net/http"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
)

type base struct {
	rd     *protect.RDial
	hc     *http.Client
	dialer *net.Dialer
	addr   string
	status int
}

func NewBaseProxy(c protect.Controller) Proxy {
	d := protect.MakeNsDialer(c)
	h := &base{
		addr:   "127.3.4.5:6890",
		dialer: d,
		status: TOK,
	}
	h.rd = newRDial(h)
	h.hc = newHTTPClient(h.rd)
	return h
}

func (h *base) Dial(network, addr string) (c protect.Conn, err error) {
	if h.status == END {
		return nil, errProxyStopped
	}

	if c, err = h.dialer.Dial(network, addr); err != nil {
		h.status = TKO
	} else {
		h.status = TOK
	}
	log.I("proxy: base: dial(%s) to %s; err? %v", network, addr, err)
	return
}

func (h *base) asRDial() *protect.RDial {
	return h.rd
}

func (h *base) Fetch(req *http.Request) (*http.Response, error) {
	stopped := h.status == END
	log.V("proxy: base: fetch(%s); ok? %t", req.URL, !stopped)
	if stopped {
		return nil, errProxyStopped
	}
	return h.hc.Do(req)
}

func (h *base) ID() string {
	return Base
}

func (h *base) Type() string {
	return NOOP
}

func (h *base) GetAddr() string {
	return h.addr
}

func (h *base) Status() int {
	return h.status
}

func (h *base) Stop() error {
	h.status = END
	log.I("proxy: base: stopped")
	return nil
}

func (h *base) Refresh() error { return nil }
