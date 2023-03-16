// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"net"

	"github.com/celzero/firestack/intra/protect"
)

type base struct {
	Proxy
	dialer *net.Dialer
	addr   string
	status int
}

func NewBaseProxy(c protect.Controller) Proxy {
	h := &base{
		addr:   "127.3.4.5:6890",
		dialer: protect.MakeNsDialer(c),
		status: TOK,
	}
	return h
}

func (h *base) Dial(network, addr string) (c Conn, err error) {
	if c, err = h.dialer.Dial(network, addr); err != nil {
		h.status = TKO
	}
	h.status = TOK
	return
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
	return nil
}
