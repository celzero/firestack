// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
)

// base is no-op proxy that dials into the underlying network,
// which typically is wifi or mobile but may also be a tun device.
type base struct {
	protoagnostic                // Dial is proto aware
	skiprefresh                  // no rebinding necessary on refresh
	outbound      *protect.RDial // outbound dialer
	addr          string
	status        *core.Volatile[int]
}

// Base returns a base proxy.
func NewBaseProxy(c protect.Controller) *base {
	d := protect.MakeNsRDial(Base, c)
	h := &base{
		addr:     "127.8.4.5:3690",
		outbound: d,
		status:   core.NewVolatile(TUP),
	}
	return h
}

// Dial implements the Proxy interface.
func (h *base) Dial(network, addr string) (c protect.Conn, err error) {
	if h.status.Load() == END {
		return nil, errProxyStopped
	}

	if settings.Loopingback.Load() { // loopback (rinr) mode
		c, err = dialers.Dial(h.outbound, network, addr)
	} else {
		c, err = localDialStrat(h.outbound, network, addr)
	}
	defer localDialStatus(h.status, err)

	//Adjust TCP keepalive config if c is a TCPConn
	protect.SetKeepAliveConfigSockOpt(c)

	log.I("proxy: base: dial(%s) to %s; err? %v", network, addr, err)
	return
}

// Announce implements Proxy.
func (h *base) Announce(network, local string) (protect.PacketConn, error) {
	if h.status.Load() == END {
		return nil, errProxyStopped
	}
	c, err := dialers.ListenPacket(h.outbound, network, local)
	defer localDialStatus(h.status, err)
	log.I("proxy: base: announce(%s) on %s; err? %v", network, local, err)
	return c, err
}

// Accept implements Proxy.
func (h *base) Accept(network, local string) (protect.Listener, error) {
	if h.status.Load() == END {
		return nil, errProxyStopped
	}
	return dialers.Listen(h.outbound, network, local)
}

// Probe implements Proxy.
func (h *base) Probe(network, local string) (protect.PacketConn, error) {
	if h.status.Load() == END {
		return nil, errProxyStopped
	}
	c, err := dialers.Probe(h.outbound, network, local)
	defer localDialStatus(h.status, err)
	log.I("proxy: base: probe(%s) on %s; err? %v", network, local, err)
	return c, err
}

func (h *base) Dialer() protect.RDialer {
	return h
}

func (h *base) DNS() string {
	return nodns
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
	return h.status.Load()
}

func (h *base) Stop() error {
	h.status.Store(END)
	log.I("proxy: base: stopped")
	return nil
}
