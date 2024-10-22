// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"context"
	"net"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
)

var ttl30s = 30 * time.Second
var shortdelay = 200 * time.Millisecond

// exit is a proxy that always dials out to the internet.
type auto struct {
	protoagnostic
	skiprefresh
	gw
	pxr    Proxies
	addr   string
	exp    *core.ExpMap[string, int]
	status *core.Volatile[int]
}

// NewExitProxy returns a new exit proxy.
func NewAutoProxy(ctx context.Context, pxr Proxies) *auto {
	h := &auto{
		pxr:    pxr,
		addr:   "127.5.51.52:5321",
		exp:    core.NewExpiringMap2[string, int](ctx),
		ba:     core.NewBarrier[bool](ttl30s),
		status: core.NewVolatile(TUP),
	}
	return h
}

// Handle implements Proxy.
func (h *auto) Handle() uintptr {
	return core.Loc(h)
}

// Dial implements Proxy.
func (h *auto) Dial(network, addr string) (protect.Conn, error) {
	if h.status.Load() == END {
		return nil, errProxyStopped
	}

	exit, exerr := h.pxr.ProxyFor(Exit)
	warp, waerr := h.pxr.ProxyFor(RpnWg)
	exit64, ex64err := h.pxr.ProxyFor(Rpn64)

	previdx, recent := h.exp.V(addr)

	c, who, err := core.Race(
		network+".dial-auto."+addr,
		tlsHandshakeTimeout,
		func(ctx context.Context) (protect.Conn, error) {
			const myidx = 0
			if exit == nil {
				return nil, exerr
			}
			if recent && previdx != myidx {
				return nil, errNotPinned
			}
			return exit.Dialer().Dial(network, addr)
		}, func(ctx context.Context) (protect.Conn, error) {
			const myidx = 1
			if warp == nil {
				return nil, waerr
			}
			if recent && previdx != myidx {
				return nil, errNotPinned
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(shortdelay):
			}
			return warp.Dialer().Dial(network, addr)
		}, func(ctx context.Context) (protect.Conn, error) {
			const myidx = 2
			if exit64 == nil {
				return nil, ex64err
			}
			if recent && previdx != myidx {
				return nil, errNotPinned
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(shortdelay):
			}
			return exit64.Dialer().Dial(network, addr)
		},
	)

	defer localDialStatus(h.status, err)
	if err != nil {
		h.exp.Delete(addr)
	} else {
		h.exp.K(addr, who, ttl30s)
	}
	maybeKeepAlive(c)
	log.I("proxy: auto: w(%d) pin(%t/%d), dial(%s) %s; err? %v",
		who, recent, previdx, network, addr, err)
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
		func(ctx context.Context) (protect.PacketConn, error) {
			if exit == nil {
				return nil, exerr
			}
			return exit.Dialer().Announce(network, local)
		}, func(ctx context.Context) (protect.PacketConn, error) {
			if warp == nil {
				return nil, waerr
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(shortdelay):
			}
			return warp.Dialer().Announce(network, local)
		},
	)
	defer localDialStatus(h.status, err)

	log.I("proxy: auto: w(%d) listen(%s) to %s; err? %v", who, network, local, err)
	return c, err
}

// Accept implements Proxy.
func (h *auto) Accept(network, local string) (l protect.Listener, err error) {
	if h.status.Load() == END {
		return nil, errProxyStopped
	}
	if exit, err := h.pxr.ProxyFor(Exit); err == nil {
		l, err = exit.Dialer().Accept(network, local)
	}
	defer localDialStatus(h.status, err)

	log.I("proxy: auto: accept(%s) on %s; err? %v", network, local, err)
	return l, err
}

// Probe implements Proxy.
func (h *auto) Probe(network, local string) (pc protect.PacketConn, err error) {
	if h.status.Load() == END {
		return nil, errProxyStopped
	}
	// todo: rpnwg
	if exit, err := h.pxr.ProxyFor(Exit); err == nil {
		pc, err = exit.Dialer().Probe(network, local)
	}
	defer localDialStatus(h.status, err)

	log.I("proxy: auto: probe(%s) on %s; err? %v", network, local, err)
	return pc, err
}

func (h *auto) Dialer() protect.RDialer {
	return h
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

func (h *auto) Router() x.Router {
	return h
}

// Reaches implements x.Router.
func (h *auto) Reaches(hostportOrIPPortCsv string) bool {
	return Reaches(h, hostportOrIPPortCsv)
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

func maybeKeepAlive(c net.Conn) {
	if settings.GetDialerOpts().LowerKeepAlive {
		// adjust TCP keepalive config if c is a TCPConn
		core.SetKeepAliveConfigSockOpt(c)
	}
}

func (h *auto) dialAfterTest(p Proxy, network, local, remote string) (net.Conn, error) {
	ipp, _ := netip.ParseAddrPort(remote)
	if reachable, err := h.ba.DoIt(baID(p, remote), icmpReachesWork(p, ipp)); err != nil {
		return nil, err
	} else if !reachable {
		return nil, errUnreachable
	}
	return dialProxy(p, network, local, remote)
}

func baID(p Proxy, ipp string) string {
	return strconv.Itoa(int(p.Handle())) + ipp
}
