// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"net"
	"net/http"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	tx "github.com/txthinking/socks5"
)

type socks5 struct {
	proxydialer *tx.Client
	id          string
	opts        *settings.ProxyOptions
	rd          *protect.RDial
	hc          *http.Client
	status      int
}

type socks5tcpconn struct {
	*tx.Client
}

type socks5udpconn struct {
	*tx.Client
}

var _ core.TCPConn = (*socks5tcpconn)(nil)
var _ core.UDPConn = (*socks5udpconn)(nil)

func (c *socks5tcpconn) CloseRead() error {
	return c.Close()
}

func (c *socks5tcpconn) CloseWrite() error {
	return c.Close()
}

func (c *socks5udpconn) Ready() bool {
	return c.Client != nil && c.Client.UDPConn != nil
}

// WriteFrom writes b to TUN using addr as the source.
func (c *socks5udpconn) WriteFrom(b []byte, addr *net.UDPAddr) (int, error) {
	// no-op; intra/udp.go does not require outbound udp to implement TUN specific methods
	return 0, nil
}

// ReceiveTo is incoming TUN packet b to be sent to addr.
func (c *socks5udpconn) ReceiveTo(b []byte, addr *net.UDPAddr) error {
	// no-op; intra/udp.go does not require outbound udp to implement TUN specific methods
	return nil
}

func NewSocks5Proxy(id string, ctl protect.Controller, po *settings.ProxyOptions) (Proxy, error) {
	var err error
	if po == nil {
		log.W("proxy: err setting up socks5(%v): %v", po, err)
		return nil, errMissingProxyOpt
	}

	// replace with a network namespace aware dialer
	tx.Dial = protect.MakeNsRDial(id, ctl)
	// x.net.proxy doesn't yet support udp
	// github.com/golang/net/blob/62affa334/internal/socks/socks.go#L233
	// if po.Auth.User and po.Auth.Password are empty strings, the upstream
	// socks5 server may throw err when dialing with golang/net/x/proxy;
	// although, txthinking/socks5 deals gracefully with empty auth strings
	// fproxy, err = proxy.SOCKS5("udp", po.IPPort, po.Auth, proxy.Direct)
	fproxy, err := tx.NewClient(po.IPPort, po.Auth.User, po.Auth.Password, tcptimeoutsec, udptimeoutsec)

	if err != nil {
		log.W("proxy: err creating socks5(%v): %v", po, err)
		return nil, err
	}

	h := &socks5{
		proxydialer: fproxy,
		id:          id,
		opts:        po,
	}
	h.rd = newRDial(h)
	h.hc = newHTTP1Client(h.rd)

	log.D("proxy: socks5: created %s with opts(%s)", h.ID(), po)

	return h, nil
}

func (h *socks5) Dial(network, addr string) (c protect.Conn, err error) {
	if h.status == END {
		return nil, errProxyStopped
	}

	log.D("proxy: socks5: %d dial(%s) from %s -> %s", h.ID(), network, h.GetAddr(), addr)
	// tx.Client.Dial does not support dialing hostnames
	if c, err = dialers.ProxyDial(h.proxydialer, network, addr); err == nil {
		// in txthinking/socks5, an underlying-conn is actually a net.TCPConn
		// github.com/txthinking/socks5/blob/39268fae/client.go#L15
		if uc, ok := c.(*tx.Client); ok {
			if uc.TCPConn != nil {
				c = &socks5tcpconn{uc}
			} else if uc.UDPConn != nil {
				c = &socks5udpconn{uc}
			} else {
				log.W("proxy: socks5: %s conn not tcp nor udp %s -> %s", h.ID(), h.GetAddr(), addr)
				c = nil
				err = errNoProxyConn
			}
		} else {
			log.W("proxy: socks5: %s conn not a tx.Client(%s) %s -> %s", h.ID(), network, h.GetAddr(), addr)
			c = nil
			err = errNoProxyConn
		}
	} else {
		log.W("proxy: socks5: %s dial(%s) failed %s -> %s: %v", h.ID(), network, h.GetAddr(), addr, err)
	}
	if err == nil {
		log.I("proxy: socks5: %s dial(%s) from %s -> %s", h.ID(), network, h.GetAddr(), addr)
		h.status = TOK
	} else {
		h.status = TKO
	}
	return
}

func (h *socks5) Dialer() *protect.RDial {
	return h.rd
}

func (h *socks5) DNS() string {
	return NoDNS
}

func (h *socks5) fetch(req *http.Request) (*http.Response, error) {
	stopped := h.status == END
	log.V("proxy: socks5: %s; fetch(%s); ended? %t", h.id, req.URL, stopped)
	if stopped {
		return nil, errProxyStopped
	}
	return h.hc.Do(req)
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

func (h *socks5) Refresh() error { return nil }
