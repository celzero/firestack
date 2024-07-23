// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"net/http"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
)

// exit is a proxy that always dials out to the internet.
type exit struct {
	protoagnostic
	skiprefresh
	rd       *protect.RDial // this proxy as a RDial
	hc       *http.Client   // this proxy as a http.Client
	outbound *protect.RDial // outbound dialer
	addr     string
	status   int
}

// NewExitProxy returns a new exit proxy.
func NewExitProxy(c protect.Controller) *exit {
	d := protect.MakeNsRDial(Exit, c)
	h := &exit{
		addr:     "127.0.0.127:1337",
		outbound: d,
		status:   TUP,
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

	// exit always splits
	if c, err = dialStrat(h.outbound, network, addr); err != nil {
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
	return dialers.ListenPacket(h.outbound, network, local)
}

// Accept implements Proxy.
func (h *exit) Accept(network, local string) (protect.Listener, error) {
	if h.status == END {
		return nil, errProxyStopped
	}
	return dialers.Listen(h.outbound, network, local)
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

func (*exit) Router() x.Router {
	return PROXYGATEWAY
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
