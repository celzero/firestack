// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"net"
	"net/http"

	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
)

type exit struct {
	rd        *protect.RDial    // this proxy as a RDial
	hc        *http.Client      // this proxy as a http.Client
	outbound  *net.Dialer       // outbound dialer
	listencfg *net.ListenConfig // outbound listener
	addr      string
	status    int
}

func NewExitProxy(c protect.Controller) Proxy {
	if c == nil {
		log.W("proxy: exit: missing ctl; probably not what you want")
	}
	d := protect.MakeNsDialer(Exit, c)
	l := protect.MakeNsListenConfig(Exit, c)
	h := &exit{
		addr:      "127.0.0.127:1337",
		outbound:  d,
		listencfg: l,
		status:    TUP,
	}
	h.rd = newRDial(h)
	h.hc = newHTTPClient(h.rd)
	return h
}

// Dial implements Proxy.
func (h *exit) Dial(network, addr string) (c protect.Conn, err error) {
	if h.status == END {
		return nil, errProxyStopped
	}

	if c, err = dialers.NetDial(h.outbound, network, addr); err != nil {
		h.status = TKO
	} else {
		h.status = TOK
	}
	log.I("proxy: exit: dial(%s) to %s; err? %v", network, addr, err)
	return
}

// Announce implements Proxy.
func (h *exit) Announce(network, local string) (protect.PacketConn, error) {
	if h.status == END {
		return nil, errProxyStopped
	}
	return dialers.NetListen(h.listencfg, network, local)
}

func (h *exit) Dialer() *protect.RDial {
	return h.rd
}

// todo: return system DNS
func (h *exit) DNS() string {
	return nodns
}

func (h *exit) fetch(req *http.Request) (*http.Response, error) {
	stopped := h.status == END
	log.V("proxy: base: fetch(%s); ok? %t", req.URL, !stopped)
	if stopped {
		return nil, errProxyStopped
	}
	return h.hc.Do(req)
}

func (h *exit) ID() string {
	return Exit
}

func (h *exit) Type() string {
	return INTERNET
}

func (h *exit) GetAddr() string {
	return h.addr
}

func (h *exit) Status() int {
	return h.status
}

func (h *exit) Stop() error {
	h.status = END
	log.I("proxy: exit: stopped")
	return nil
}

func (h *exit) Refresh() error { return nil }
