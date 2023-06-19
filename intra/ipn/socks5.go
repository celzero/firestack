// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	tx "github.com/txthinking/socks5"
	"golang.org/x/net/proxy"
)

type socks5 struct {
	Proxy
	dailer proxy.Dialer
	id     string
	opts   *settings.ProxyOptions
	status int
}

func NewSocks5Proxy(id string, ctl protect.Controller, po *settings.ProxyOptions) (Proxy, error) {
	var fproxy proxy.Dialer
	var err error
	if po == nil {
		log.W("proxy: err setting up socks5(%v): %v", po, err)
		return nil, errMissingProxyOpt
	}

	// replace with a network namespace aware dialer
	tx.Dial = protect.MakeNsXDial(ctl)

	// x.net.proxy doesn't yet support udp
	// github.com/golang/net/blob/62affa334/internal/socks/socks.go#L233
	// if po.Auth.User and po.Auth.Password are empty strings, the upstream
	// socks5 server may throw err when dialing with golang/net/x/proxy;
	// although, txthinking/socks5 deals gracefully with empty auth strings
	// fproxy, err = proxy.SOCKS5("udp", po.IPPort, po.Auth, proxy.Direct)
	fproxy, err = tx.NewClient(po.IPPort, po.Auth.User, po.Auth.Password, tcptimeoutsec, udptimeoutsec)

	if err != nil {
		log.W("proxy: err creating socks5(%v): %v", po, err)
		return nil, err
	}

	h := &socks5{
		dailer: fproxy,
		id:     id,
		opts:   po,
	}

	log.D("proxy: socks5: created %s with opts(%s)", h.ID(), po)

	return h, nil
}

func (h *socks5) Dial(network, addr string) (c Conn, err error) {
	if h.status == END {
		return nil, errProxyStopped
	}

	if c, err = h.dailer.Dial(network, addr); err == nil {
		// in txthinking/socks5, an underlying-conn is actually a net.TCPConn
		// github.com/txthinking/socks5/blob/39268fae/client.go#L15
		if uc, ok := c.(*tx.Client); ok {
			if uc.TCPConn != nil {
				c = uc.TCPConn
			} else if uc.UDPConn != nil {
				c = uc.UDPConn
			} else {
				log.W("proxy: socks5 conn not tcp nor udp %s -> %s", h.GetAddr(), addr)
				c = nil
				err = errNoProxyConn
			}
		} else {
			log.W("proxy: socks5 conn not a tx.Client(%s) %s -> %s", network, h.GetAddr(), addr)
			c = nil
			err = errNoProxyConn
		}
	} else {
		log.W("proxy: socks5 dial(%s) failed %s -> %s: %v", network, h.GetAddr(), addr, err)
	}
	if err == nil {
		log.I("proxy: socks5: dial(%s) from %s -> %s", network, h.GetAddr(), addr)
		h.status = TOK
	} else {
		h.status = TKO
	}
	return
}

func (h *socks5) ID() string {
	return h.id
}

func (h *socks5) Type() string {
	return SOCKS5
}

func (h *socks5) GetAddr() string {
	return h.opts.IPPort
}

func (h *socks5) Status() int {
	return h.status
}

func (h *socks5) Stop() error {
	h.status = END
	log.I("proxy: socks5: stopped %s", h.id)
	return nil
}
