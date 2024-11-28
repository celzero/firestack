// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"context"
	"fmt"
	"net"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
)

const ttl30s = 30 * time.Second
const shortdelay = 100 * time.Millisecond

// exit is a proxy that always dials out to the internet.
type auto struct {
	NoDNS
	ProtoAgnostic
	SkipRefresh
	GW
	pxr  Proxies
	addr string

	via *core.Volatile[Proxy] // via dialer

	exp    *core.Sieve[string, int]
	ba     *core.Barrier[bool, string]
	status *core.Volatile[int]
}

// NewAutoProxy returns a new exit proxy.
func NewAutoProxy(ctx context.Context, pxr Proxies) *auto {
	h := &auto{
		pxr:    pxr,
		via:    core.NewZeroVolatile[Proxy](),
		addr:   "127.5.51.52:5321",
		exp:    core.NewSieve[string, int](ctx, ttl30s),
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
	return h.dial(network, "", addr)
}

// DialBind implements Proxy.
func (h *auto) DialBind(network, local, remote string) (protect.Conn, error) {
	return h.dial(network, local, remote)
}

func (h *auto) dial(network, local, remote string) (protect.Conn, error) {
	if h.status.Load() == END {
		return nil, errProxyStopped
	}

	exit, exerr := h.pxr.ProxyFor(Exit)
	exit64, ex64err := h.pxr.ProxyFor(Rpn64)
	warp, waerr := h.pxr.ProxyFor(RpnWg)
	sep, seerr := h.pxr.ProxyFor(RpnSE)

	if v := h.via.Load(); v != nil {
		if v.Status() == END {
			h.Hop(nil) // stale; unset
			log.W("proxy: auto: via(%s) removed", idhandle(v))
		}
	}

	previdx, recent := h.exp.Get(remote)

	c, who, err := core.Race(
		network+".dial-auto."+remote,
		tlsHandshakeTimeout,
		func(ctx context.Context) (protect.Conn, error) {
			const myidx = 0
			if exit == nil { // exit must always be present
				return nil, exerr
			}
			if recent {
				if previdx != myidx {
					return nil, errNotPinned
				}
				// ip pinned to this proxy
				h.dialIfHealthy(exit, network, local, remote)
			}
			return h.dialIfReachable(exit, network, local, remote)
		}, func(ctx context.Context) (protect.Conn, error) {
			const myidx = 1
			if warp == nil {
				return nil, waerr
			}
			if recent {
				if previdx != myidx {
					return nil, errNotPinned
				}
				// ip pinned to this proxy
				return h.dialIfHealthy(warp, network, local, remote)
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(shortdelay): // 100ms
			}
			return h.dialIfHealthy(warp, network, local, remote)
		}, func(ctx context.Context) (protect.Conn, error) {
			const myidx = 2
			if exit64 == nil {
				return nil, ex64err
			}
			if recent {
				if previdx != myidx {
					return nil, errNotPinned
				}
				// ip pinned to this proxy
				return h.dialIfHealthy(exit64, network, local, remote)
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(shortdelay * 2): // 200ms
			}
			return h.dialIfHealthy(exit64, network, local, remote)
		}, func(ctx context.Context) (protect.Conn, error) {
			const myidx = 3
			if sep == nil {
				return nil, seerr
			}
			if recent {
				if previdx != myidx {
					return nil, errNotPinned
				}
				// ip pinned to this proxy
				return h.dialIfHealthy(sep, network, local, remote)
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(shortdelay * 3): // 300ms
			}
			return h.dialIfHealthy(sep, network, local, remote)
		},
	)

	defer localDialStatus(h.status, err)
	if err != nil {
		h.exp.Del(remote)
	} else {
		h.exp.Put(remote, who)
	}
	maybeKeepAlive(c)
	logeif(err != nil)("proxy: auto: w(%d) pin(%t/%d), dial(%s) %s; err? %v",
		who, recent, previdx, network, remote, err)
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
		}, // seasy-proxy does not support udp?
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
	exit, err := h.pxr.ProxyFor(Exit)
	if err == nil {
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
	// todo: rpnwg, rpnamz
	exit, err := h.pxr.ProxyFor(Exit)
	if err == nil {
		pc, err = exit.Dialer().Probe(network, local)
	}
	defer localDialStatus(h.status, err)

	log.I("proxy: auto: probe(%s) on %s; err? %v", network, local, err)
	return pc, err
}

// Dialer implements Proxy.
func (h *auto) Dialer() protect.RDialer {
	return h
}

// ID implements x.Proxy.
func (h *auto) ID() string {
	return Auto
}

// Type implements x.Proxy.
func (h *auto) Type() string {
	return RPN
}

// Router implements x.Proxy.
func (h *auto) Router() x.Router {
	return h
}

// Reaches implements x.Router.
func (h *auto) Reaches(hostportOrIPPortCsv string) bool {
	return Reaches(h, hostportOrIPPortCsv)
}

func (h *auto) Hop(p Proxy) error {
	if p == nil {
		old := h.via.Tango(nil)
		log.I("proxy: auto: hop(%s) removed", idhandle(old))
		return nil
	}
	if p.Status() == END {
		return errProxyStopped
	}

	var warp, sep Proxy
	var waerr, seerr error
	old := h.via.Tango(p)
	if warp, waerr = h.pxr.ProxyFor(RpnWg); warp != nil {
		warp.Hop(p)
	}
	if sep, seerr = h.pxr.ProxyFor(RpnSE); sep != nil {
		sep.Hop(p)
	}

	log.I("proxy: auto: hop(%s) => %s; errs? %v %v", idhandle(old), idhandle(p), waerr, seerr)
	return nil
}

func (h *auto) Via() (x.Proxy, error) {
	if v := h.via.Load(); v != nil {
		return v, nil
	}
	return nil, errNoHop
}

// GetAddr implements x.Proxy.
func (h *auto) GetAddr() string {
	return h.addr
}

// Status implements x.Proxy.
func (h *auto) Status() int {
	return h.status.Load()
}

// Stop implements x.Proxy.
func (h *auto) Stop() error {
	h.status.Store(END)
	h.exp.Clear()
	log.I("proxy: auto: stopped")
	return nil
}

func (h *auto) dialIfReachable(p Proxy, network, local, remote string) (net.Conn, error) {
	if !hasroute(p, remote) {
		return nil, fmt.Errorf("auto; %s: %v", p.ID(), errNoRouteToHost)
	}
	// some IPs never respond to ping; ex: 34.245.245.138:443, 63.32.2.144:80
	// even if they respond over tcp/udp on the same ip:port.
	// ipp, _ := netip.ParseAddrPort(remote)
	// if reachable, err := h.ba.DoIt(p.ID()+remote, remote), icmpReachesWork(p, ipp)); err != nil {
	// 	return nil, fmt.Errorf("auto; %s ping %s: %v", p.ID(), remote, err)
	// } else if !reachable {
	//	return nil, fmt.Errorf("auto; %s: %v: %s", p.ID(), errNoRouteToHost, remote)
	// }
	return h.dialIfHealthy(p, network, local, remote)
}

func (*auto) dialIfHealthy(p Proxy, network, local, remote string) (net.Conn, error) {
	if err := healthy(p); err != nil {
		return nil, fmt.Errorf("auto; %s not ok; %v: %s", p.ID(), err, remote)
	}
	if len(local) > 0 {
		return p.Dialer().DialBind(network, local, remote)
	}
	return p.Dialer().Dial(network, remote)
}

func maybeKeepAlive(c net.Conn) {
	if settings.GetDialerOpts().LowerKeepAlive {
		// adjust TCP keepalive config if c is a TCPConn
		core.SetKeepAliveConfigSockOpt(c)
	}
}
