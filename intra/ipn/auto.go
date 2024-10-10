// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
)

// exit is a proxy that always dials out to the internet.
type auto struct {
	protoagnostic
	skiprefresh
	pxr    Proxies
	rd     *protect.RDial // this proxy as a RDial
	addr   string
	status *core.Volatile[int]
}

// NewExitProxy returns a new exit proxy.
func NewAutoProxy(pxr Proxies) *auto {
	h := &auto{
		pxr:    pxr,
		addr:   "127.5.51.52:5321",
		status: core.NewVolatile(TUP),
	}
	h.rd = newRDial(h)
	return h
}

// Dial implements Proxy.
func (h *auto) Dial(network, addr string) (protect.Conn, error) {
	if h.status.Load() == END {
		return nil, errProxyStopped
	}

	exit, exerr := h.pxr.ProxyFor(Exit)
	warp, waerr := h.pxr.ProxyFor(RpnWg)

	// auto always splits
	c, who, err := core.Race(
		network+".dial-auto."+addr,
		tlsHandshakeTimeout,
		func() (protect.Conn, error) {
			if exit == nil {
				return nil, exerr
			}
			return exit.Dialer().Dial(network, addr)
		}, func() (protect.Conn, error) {
			if warp == nil {
				return nil, waerr
			}
			return warp.Dialer().Dial(network, addr)
		},
	)

	if err != nil {
		h.status.Store(TKO)
	} else {
		h.status.Store(TOK)
	}
	// adjust TCP keepalive config if c is a TCPConn
	protect.SetKeepAliveConfigSockOpt(c)
	log.I("proxy: auto: w(%d) dial(%s) to %s; err? %v", who, network, addr, err)
	return c, err
}

// Announce implements Proxy.
func (h *auto) Announce(network, local string) (protect.PacketConn, error) {
	if h.status.Load() == END {
		return nil, errProxyStopped
	}
	exit, exerr := h.pxr.ProxyFor(Exit)
	warp, waerr := h.pxr.ProxyFor(RpnWg)

	// auto always splits
	c, who, err := core.Race(
		network+".announce-auto."+local,
		tlsHandshakeTimeout,
		func() (protect.PacketConn, error) {
			if exit == nil {
				return nil, exerr
			}
			return exit.Dialer().Announce(network, local)
		}, func() (protect.PacketConn, error) {
			if warp == nil {
				return nil, waerr
			}
			return warp.Dialer().Announce(network, local)
		},
	)

	if err != nil {
		h.status.Store(TKO)
	} else {
		h.status.Store(TOK)
	}
	log.I("proxy: auto: w(%d) listen(%s) to %s; err? %v", who, network, local, err)
	return c, err
}

// Accept implements Proxy.
func (h *auto) Accept(network, local string) (protect.Listener, error) {
	if h.status.Load() == END {
		return nil, errProxyStopped
	}
	if exit, err := h.pxr.ProxyFor(Exit); err == nil {
		return exit.Dialer().Accept(network, local)
	} else {
		return nil, err
	}
}

// Probe implements Proxy.
func (h *auto) Probe(network, local string) (protect.PacketConn, error) {
	if h.status.Load() == END {
		return nil, errProxyStopped
	}
	// todo: rpnwg
	if exit, err := h.pxr.ProxyFor(Exit); err == nil {
		return exit.Dialer().Probe(network, local)
	} else {
		return nil, err
	}
}

func (h *auto) Dialer() *protect.RDial {
	return h.rd
}

// todo: return system DNS
func (h *auto) DNS() string {
	return nodns
}

func (h *auto) ID() string {
	return Auto
}

func (h *auto) Type() string {
	return RPN
}

func (*auto) Router() x.Router {
	return PROXYGATEWAY
}

func (h *auto) GetAddr() string {
	return h.addr
}

func (h *auto) Status() int {
	return h.status.Load()
}

func (h *auto) Stop() error {
	h.status.Store(END)
	log.I("proxy: auto: stopped")
	return nil
}
