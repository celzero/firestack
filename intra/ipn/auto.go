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

const (
	ttl30s                   = 30 * time.Second
	shortdelay               = 100 * time.Millisecond
	delayForUnhealthyProxies = 2 * time.Second
)

// exit is a proxy that always dials out to the internet.
type auto struct {
	NoDNS
	ProtoAgnostic
	SkipRefresh
	GW
	pxr  ProxyProvider
	addr string

	via   *core.WeakRef[Proxy]   // via dialer
	viaID *core.Volatile[string] // via ID

	exp    *core.Sieve[string, int]
	ba     *core.Barrier[bool, string]
	status *core.Volatile[int]
}

// NewAutoProxy returns a new exit proxy.
func NewAutoProxy(ctx context.Context, pxr Proxies) *auto {
	var err error

	h := &auto{
		pxr:    pxr,
		viaID:  core.NewZeroVolatile[string](),
		addr:   "127.5.51.52:5321",
		exp:    core.NewSieve[string, int](ctx, ttl30s),
		ba:     core.NewBarrier[bool](ttl30s),
		status: core.NewVolatile(TUP),
	}
	h.via, err = core.NewWeakRef(h.viafor, viaok)
	if err != nil {
		panic(err) // unlikely
	}
	return h
}

func (h *auto) viafor() *Proxy {
	return viafor(h.ID(), h.viaID.Load(), h.pxr)
}

func (h *auto) swapVia(new Proxy) Proxy {
	return swapVia(h.ID(), new, h.viaID, h.via)
}

// Handle implements Proxy.
func (h *auto) Handle() uintptr {
	return core.Loc(h)
}

// DialerHandle implements Proxy.
func (h *auto) DialerHandle() (mix uintptr) {
	remoteOnly := settings.AutoAlwaysRemote()
	if !remoteOnly {
		if exit, _ := h.pxr.ProxyFor(Exit); exit != nil {
			mix ^= exit.DialerHandle()
		}
		if exit64, _ := h.pxr.ProxyFor(Rpn64); exit64 != nil {
			mix ^= exit64.DialerHandle()
		}
	}
	if warp, _ := h.pxr.mainRpnProxyOf(RpnWg); warp != nil {
		mix ^= warp.DialerHandle()
	}
	if pro, _ := h.pxr.mainRpnProxyOf(RpnPro); pro != nil {
		mix ^= pro.DialerHandle()
	}
	if amz, _ := h.pxr.mainRpnProxyOf(RpnAmz); amz != nil {
		mix ^= amz.DialerHandle()
	}
	if sep, _ := h.pxr.mainRpnProxyOf(RpnSE); sep != nil {
		mix ^= sep.DialerHandle()
	}

	return mix
}

// Dial implements Proxy.
func (h *auto) Dial(network, addr string) (protect.Conn, error) {
	return h.dial(network, "", addr)
}

// DialBind implements Proxy.
func (h *auto) DialBind(network, local, remote string) (protect.Conn, error) {
	return h.dial(network, local, remote)
}

func (h *auto) dial(network, laddr, raddr string) (protect.Conn, error) {
	if h.status.Load() == END {
		return nil, errProxyStopped
	}

	exit, exerr := h.pxr.ProxyFor(Exit)
	exit64, ex64err := h.pxr.ProxyFor(Rpn64)
	warp, waerr := h.pxr.mainRpnProxyOf(RpnWg)
	pro, proerr := h.pxr.mainRpnProxyOf(RpnPro)
	amz, amzerr := h.pxr.mainRpnProxyOf(RpnAmz)
	sep, seerr := h.pxr.mainRpnProxyOf(RpnSE)

	if usevia(h.viaID) {
		if v, vok := h.via.Get(); !vok {
			if removeViaOnErrors {
				h.Hop(nil, false /*dryrun*/) // stale; unset
			}
			log.W("proxy: auto: via(%s) failing...", idhandle(v))
		}
	}

	remoteOnly := settings.AutoAlwaysRemote()
	parallelDial := settings.AutoDialsParallel.Load()

	if !parallelDial {
		rpns := []Proxy{pro, warp, amz, sep}
		healthy := core.Map(
			core.FilterLeft(
				rpns,
				func(p Proxy) bool {
					if p == nil || core.IsNil(p) {
						return false // nil proxies out
					}
					if remoteOnly && local(p.ID()) {
						return false // local proxies out
					}
					if err := healthy(p); err != nil {
						log.D("auto: dial; %s %s not ok; %v: %s", p.ID(), network, err, raddr)
						return false // not healthy out
					}
					return true // ok
				}),
			func(p Proxy) protect.RDialer {
				return p.Dialer()
			})
		// TODO: pinning IPs
		if len(healthy) <= 0 {
			// no healthy proxies; fail open
			all := core.Map(rpns, func(p Proxy) protect.RDialer {
				return p.Dialer()
			})
			return dialAny(core.WithoutNils(all), network, laddr, raddr)
		}
		return dialAny(healthy, network, laddr, raddr)
	}

	previdx, recent := h.exp.Get(raddr)

	c, who, err := core.Race(
		network+".dial-auto."+raddr,
		tlsHandshakeTimeout,
		func(ctx context.Context) (protect.Conn, error) {
			const myidx = 0
			if exit == nil { // exit must always be present
				return nil, exerr
			}
			if !remoteOnly {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				default: // dial ahead
				}
			} else {
				return nil, errNotRemote
			}
			if recent {
				if previdx != myidx {
					return nil, errNotPinned
				}
				// ip pinned to this proxy
				return h.dialAlways(exit, network, laddr, raddr)
			}
			return h.dialIfReachable(exit, network, laddr, raddr)
		}, func(ctx context.Context) (protect.Conn, error) {
			const myidx = 1
			if pro == nil {
				return nil, proerr
			}
			if recent {
				if previdx != myidx {
					return nil, errNotPinned
				}
				// ip pinned to this proxy
				return h.dialAlways(pro, network, laddr, raddr)
			}

			// wait only if exit was used
			if !remoteOnly {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(shortdelay * myidx): // 100ms
				}
			}
			return h.dialIfHealthy(pro, network, laddr, raddr)
		}, func(ctx context.Context) (protect.Conn, error) {
			const myidx = 2
			if warp == nil {
				return nil, waerr
			}
			if recent {
				if previdx != myidx {
					return nil, errNotPinned
				}
				// ip pinned to this proxy
				return h.dialAlways(warp, network, laddr, raddr)
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(shortdelay * myidx): // 200ms
			}
			return h.dialIfHealthy(warp, network, laddr, raddr)
		}, func(ctx context.Context) (protect.Conn, error) {
			const myidx = 3
			if exit64 == nil {
				return nil, ex64err
			}
			if remoteOnly {
				return nil, errNotRemote
			}
			if recent {
				if previdx != myidx {
					return nil, errNotPinned
				}
				// ip pinned to this proxy
				return h.dialAlways(exit64, network, laddr, raddr)
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(shortdelay * myidx): // 300ms
			}
			return h.dialIfHealthy(exit64, network, laddr, raddr)
		}, func(ctx context.Context) (protect.Conn, error) {
			const myidx = 4
			if amz == nil {
				return nil, amzerr
			}
			if recent {
				if previdx != myidx {
					return nil, errNotPinned
				}
				// ip pinned to this proxy
				return h.dialAlways(amz, network, laddr, raddr)
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(shortdelay * myidx): // 400ms
			}
			return h.dialIfHealthy(amz, network, laddr, raddr)
		}, func(ctx context.Context) (protect.Conn, error) {
			const myidx = 5
			if sep == nil {
				return nil, seerr
			}
			if recent {
				if previdx != myidx {
					return nil, errNotPinned
				}
				// ip pinned to this proxy
				return h.dialAlways(sep, network, laddr, raddr)
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(shortdelay * myidx): // 500ms
			}
			return h.dialIfHealthy(sep, network, laddr, raddr)
		},
	)

	defer localDialStatus(h.status, err)
	if err != nil {
		h.exp.Del(raddr)
	} else {
		h.exp.Put(raddr, who)
	}
	kaenabled := maybeKeepAlive(c)
	logei(err)("proxy: auto: w(%d) pin(%t/%d), dial(%s) %s, ka? %t; err? %v",
		who, recent, previdx, network, raddr, kaenabled, err)
	return c, err
}

// Announce implements Proxy.
func (h *auto) Announce(network, local string) (protect.PacketConn, error) {
	if h.status.Load() == END {
		return nil, errProxyStopped
	}

	exit, exerr := h.pxr.ProxyFor(Exit)
	warp, waerr := h.pxr.mainRpnProxyOf(RpnWg)
	pro, proerr := h.pxr.mainRpnProxyOf(RpnPro)
	amz, amzerr := h.pxr.mainRpnProxyOf(RpnAmz)

	previdx, recent := h.exp.Get(local)

	// TODO: announceIfHealthy
	c, who, err := core.Race(
		network+".announce-auto."+local,
		tlsHandshakeTimeout,
		func(ctx context.Context) (protect.PacketConn, error) {
			const myidx = 0
			if exit == nil {
				return nil, exerr
			}
			if recent {
				if previdx != myidx {
					return nil, errNotPinned
				}
				// ip pinned to this proxy
				return h.announceIfHealthy(exit, network, local)
			}
			return h.announceIfHealthy(exit, network, local)
		}, func(ctx context.Context) (protect.PacketConn, error) {
			const myidx = 1
			if pro == nil {
				return nil, proerr
			}
			if recent {
				if previdx != myidx {
					return nil, errNotPinned
				}
				// ip pinned to this proxy
				return h.announceIfHealthy(pro, network, local)
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(shortdelay * myidx): // 100ms
			}
			return h.announceIfHealthy(pro, network, local)
		}, func(ctx context.Context) (protect.PacketConn, error) {
			const myidx = 2
			if warp == nil {
				return nil, waerr
			}
			if recent {
				if previdx != myidx {
					return nil, errNotPinned
				}
				// ip pinned to this proxy
				return h.announceIfHealthy(warp, network, local)
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(shortdelay * myidx): // 200ms
			}
			return h.announceIfHealthy(warp, network, local)
		}, func(ctx context.Context) (protect.PacketConn, error) {
			const myidx = 3
			if amz == nil {
				return nil, amzerr
			}
			if recent {
				if previdx != myidx {
					return nil, errNotPinned
				}
				// ip pinned to this proxy
				return h.announceIfHealthy(amz, network, local)
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(shortdelay * myidx): // 300ms
			}
			return h.announceIfHealthy(amz, network, local)
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
	if settings.AutoAlwaysRemote() {
		log.E("proxy: auto: accept(%s) on %s remote-dial unimplemented", network, local)
		return nil, errNotRemote
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
	if settings.AutoAlwaysRemote() {
		log.E("proxy: auto: probe(%s) on %s remote-dial unimplemented", network, local)
		return nil, errNotRemote
	}
	// todo: rpnwg, rpnamz, rpnpro
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

// Hop implements Proxy.
func (h *auto) Hop(p Proxy, dryrun bool) error {
	if p == nil {
		if !dryrun {
			old := h.swapVia(nil)
			log.I("proxy: auto: hop(%s) removed", idhandle(old))
		}
		return nil
	}
	if p.Status() == END {
		return errProxyStopped
	}

	var warp, sep, amz, pro Proxy
	var waerr, seerr, amzerr, proerr error
	old := h.swapVia(p)
	if warp, waerr = h.pxr.mainRpnProxyOf(RpnWg); warp != nil {
		waerr = warp.Hop(p, dryrun)
	}
	if pro, proerr = h.pxr.mainRpnProxyOf(RpnPro); pro != nil {
		proerr = pro.Hop(p, dryrun)
	}
	if amz, amzerr = h.pxr.mainRpnProxyOf(RpnAmz); amz != nil {
		amzerr = amz.Hop(p, dryrun)
	}
	if sep, seerr = h.pxr.mainRpnProxyOf(RpnSE); sep != nil {
		seerr = sep.Hop(p, dryrun)
	}

	errs := core.JoinErr(waerr, seerr, amzerr, proerr) // may be nil

	logei(errs)("proxy: auto: hop(%s) => %s; errs? %v",
		idhandle(old), idhandle(p), errs)

	return errs
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

// dialIfReachable currently aliases dialIfHealthy.
func (h *auto) dialIfReachable(p Proxy, network, local, remote string) (net.Conn, error) {
	// remote is oftimes a hostname; in which case hasroute would error out (as it
	// works with ip addresses only). The alternative is to get the ipmap from dialers pkg
	// but that would be redundant to what the individual proxy implementations already do.
	// if !hasroute(p, remote) {
	//	return nil, fmt.Errorf("auto; %s: %v", p.ID(), errNoRouteToHost)
	// }
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

func (*auto) dialAlways(p Proxy, network, local, remote string) (net.Conn, error) {
	err := healthy(p)
	if err != nil {
		log.E("auto dial; %s %s not ok; to %s; err: %v", idstr(p), network, remote, err)
	}
	if len(local) > 0 {
		return p.Dialer().DialBind(network, local, remote)
	}
	return p.Dialer().Dial(network, remote)
}

func (a *auto) dialIfHealthy(p Proxy, network, local, remote string) (net.Conn, error) {
	if err := healthy(p); err != nil {
		log.E("auto dial; %s %s not ok; %v: %s", p.ID(), network, err, remote)
		time.Sleep(delayForUnhealthyProxies)
	}
	if len(local) > 0 {
		return p.Dialer().DialBind(network, local, remote)
	}
	return p.Dialer().Dial(network, remote)
}

func (*auto) announceIfHealthy(p Proxy, network, local string) (net.PacketConn, error) {
	if err := healthy(p); err != nil {
		return nil, fmt.Errorf("auto announce; %s %s not ok; %v: %s", p.ID(), network, err, local)
	}
	return p.Dialer().Announce(network, local)
}

func maybeKeepAlive(c net.Conn) (keepingalive bool) {
	keepingalive, _ = maybeKeepAlive2(c)
	return
}

func maybeKeepAlive2(c net.Conn) (keepingalive, ok bool) {
	if settings.GetDialerOpts().LowerKeepAlive {
		// adjust socket's keepalive config
		lowered := core.SetKeepAliveConfigSockOpt(c)
		keepingalive = lowered
		ok = lowered
		return
	}
	// disable socket keepalive
	disabled := core.DisableKeepAlive(c)
	keepingalive = !disabled
	ok = disabled
	return
}
