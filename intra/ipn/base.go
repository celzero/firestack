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

var currentStrategy func(*protect.RDial, string, string) (protect.Conn, error) = dialers.SplitDial
const (
	retrierStrategy int32 = 0
	desyncStrategy int32 = 1
)
func SwitchStrategy(s int32){
	switch s {
	case retrierStrategy:
		currentStrategy = dialers.SplitDial
	case desyncStrategy:
		currentStrategy = dialers.SplitDial3
	}
}

// base is no-op proxy that dials into the underlying network,
// which typically is wifi or mobile but may also be a tun device.
type base struct {
	protoagnostic                // Dial is proto aware
	skiprefresh                  // no rebinding necessary on refresh
	rd            *protect.RDial // this proxy as a RDial
	hc            *http.Client   // this proxy as a http.Client
	outbound      *protect.RDial // outbound dialer
	addr          string
	status        int
}

// Base returns a base proxy.
func NewBaseProxy(c protect.Controller) *base {
	d := protect.MakeNsRDial(Base, c)
	h := &base{
		addr:     "127.8.4.5:3690",
		outbound: d,
		status:   TUP,
	}
	h.rd = newRDial(h)
	h.hc = newHTTPClient(h.rd)
	return h
}

// Dial implements the Proxy interface.
func (h *base) Dial(network, addr string) (c protect.Conn, err error) {
	if h.status == END {
		return nil, errProxyStopped
	}

	if c, err = currentStrategy(h.outbound, network, addr); err != nil {
		h.status = TKO
	} else {
		h.status = TOK
	}
	log.I("proxy: base: dial(%s) to %s; err? %v", network, addr, err)
	return
}

// Announce implements Proxy.
func (h *base) Announce(network, local string) (protect.PacketConn, error) {
	if h.status == END {
		return nil, errProxyStopped
	}
	return dialers.ListenPacket(h.outbound, network, local)
}

// Accept implements Proxy.
func (h *base) Accept(network, local string) (protect.Listener, error) {
	if h.status == END {
		return nil, errProxyStopped
	}
	return dialers.Listen(h.outbound, network, local)
}

func (h *base) Dialer() *protect.RDial {
	return h.rd
}

func (h *base) DNS() string {
	return nodns
}

func (h *base) fetch(req *http.Request) (*http.Response, error) {
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

func (*base) Router() x.Router {
	return PROXYGATEWAY
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
