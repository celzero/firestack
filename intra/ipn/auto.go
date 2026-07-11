// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"context"
	"net"
	"sync/atomic"
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

// auto is a proxy that dials multiple, preset outbounds.
type auto struct {
	NoDNS
	ProtoAgnostic
	SkipRefresh
	CantPause
	GW
	pxr  ProxyProvider
	addr string
	hdl  uint64

	via atomic.Pointer[core.WeakRef[Proxy]] // via dialer

	exp    *core.Sieve[string, int]
	ba     *core.Barrier[bool, string]
	status atomic.Int32
}

// NewAutoProxy returns a new exit proxy.
func NewAutoProxy(ctx context.Context, pxr Proxies) *auto {
	h := &auto{
		pxr:  pxr,
		addr: "127.5.51.52:5321",
		exp:  core.NewSieve[string, int](ctx, "ipn.a.exp", ttl30s),
		ba:   core.NewBarrier[bool](ctx, "ipn.a.bar", ttl30s),
	}
	h.status.Store(TUP)
	h.since.Store(now())
	h.hdl = core.Loc(h)
	return h
}

// Handle implements Proxy.
func (h *auto) Handle() uint64 {
	return h.hdl
}

// DialerHandle implements Proxy.
func (h *auto) DialerHandle() (mix uint64) {
	remoteOnly := settings.AutoAlwaysRemote()
	if !remoteOnly {
		if exit, _ := h.pxr.ProxyFor(Exit); exit != nil {
			mix ^= exit.DialerHandle()
		}
		if exit64, _ := h.pxr.ProxyFor(Rpn64); exit64 != nil {
			mix ^= exit64.DialerHandle()
		}
	}
	if win, _ := h.pxr.mainRpnProxyOf(RpnWin); win != nil {
		mix ^= win.DialerHandle()
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
	if err := candial(&h.status); err != nil {
		return nil, err
	}

	exit, exerr := h.pxr.ProxyFor(Exit)
	exit64, ex64err := h.pxr.ProxyFor(Rpn64)
	win, winerr := h.pxr.mainRpnProxyOf(RpnWin)

	pxrerrs := core.JoinErr(exerr, winerr, ex64err)

	if ref := h.via.Load(); ref != nil {
		if v, vok := ref.Get(); !vok {
			if removeViaOnErrors {
				h.Hop(nil, false /*dryrun*/) // stale; unset
			}
			log.W("proxy: auto: via(%s) failing...", idhandle(v))
		}
	}

	remoteOnly := settings.AutoAlwaysRemote()
	parallelDial := settings.AutoDialsParallel.Load()

	var c protect.Conn
	var err error

	// non-parallel dial states
	who := -1
	previdx, recent := h.exp.Get(raddr)
	delpin := false

	// parallel dial states
	tothealthy := -1
	totdials := -1

	if !parallelDial {
		rpns := []Proxy{exit, exit64, win}
		healthy := core.Map(
			core.FilterLeft(
				rpns,
				func(p Proxy) bool {
					if p == nil || core.IsNil(p) {
						return false // nil proxies out
					}
					if remoteOnly && local(idstr(p)) {
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

		tothealthy = len(healthy)
		if len(healthy) > 0 {
			// dial healthy proxies
			c, err = dialAny(healthy, network, laddr, raddr)
			totdials = len(healthy)
		} else {
			// no healthy proxies; fail open
			d := core.Map(rpns, func(p Proxy) protect.RDialer {
				if p == nil || core.IsNil(p) {
					return nil // nil proxies out
				}
				if remoteOnly && local(idstr(p)) {
					return nil // local proxies out
				}
				return p.Dialer()
			})
			totdials = len(d)
			if len(d) > 0 {
				// dialAny delegates to dialers.DialAny which pins IPs
				// to proxies (against their IDs) for 30s.
				c, err = dialAny(core.WithoutNils(d), network, laddr, raddr)
			} else {
				c, err = nil, core.OneErr(pxrerrs, errNoProxyHealthy)
			}
		}
	} else {
		c, who, err = core.Race(
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
				const myidx = 3
				if win == nil {
					return nil, winerr
				}
				if recent {
					if previdx != myidx {
						return nil, errNotPinned
					}
					// ip pinned to this proxy
					return h.dialAlways(win, network, laddr, raddr)
				}

				// wait only if exit was used
				if !remoteOnly {
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-time.After(shortdelay * myidx): // 500ms
					}
				}
				return h.dialIfHealthy(win, network, laddr, raddr)
			},
		)

		if err != nil || c == nil || core.IsNil(c) {
			h.exp.Del(raddr)
			c = nil
			delpin = true // remove pin
		} else {
			h.exp.Put(raddr, who)
		}
	}

	defer localDialStatus(&h.status, err)

	kaenabled := maybeKeepAlive(c)
	n, berr := changeBufferSizes(c)
	logei(err)("proxy: auto: w(%d) pin(%t+%t/%d), dial(%s) %s, ka? %t / parallel? %t / remote? %t; tot(healthy %d / dials %d); errs? %v+%v; sz? %d (%v)",
		who, recent, !delpin, previdx, network, raddr, kaenabled, parallelDial, remoteOnly, tothealthy, totdials, err, pxrerrs, n, berr)

	return c, err
}

// Announce implements Proxy.
func (h *auto) Announce(network, local string) (protect.PacketConn, error) {
	if err := candial(&h.status); err != nil {
		return nil, err
	}

	// TODO: settings.AutoDialsParallel
	remoteOnly := settings.AutoAlwaysRemote()

	exit, exerr := h.pxr.ProxyFor(Exit)
	win, winerr := h.pxr.mainRpnProxyOf(RpnWin)

	previdx, recent := h.exp.Get(local)

	c, who, err := core.Race(
		network+".announce-auto."+local,
		tlsHandshakeTimeout,
		func(ctx context.Context) (protect.PacketConn, error) {
			const myidx = 0
			if exit == nil {
				return nil, exerr
			}
			if remoteOnly {
				return nil, errNotRemote
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
			if win == nil {
				return nil, winerr
			}
			if recent {
				if previdx != myidx {
					return nil, errNotPinned
				}
				// ip pinned to this proxy
				return h.announceIfHealthy(win, network, local)
			}
			// delay if not dialing remote exclusively
			if !remoteOnly {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(shortdelay * myidx): // 100ms
				}
			}
			return h.announceIfHealthy(win, network, local)
		},
	)
	defer localDialStatus(&h.status, err)

	n, berr := changeBufferSizes(c)
	log.I("proxy: auto: w(%d) listen(%s) to %s; err? %v; sz? %d (%v)", who, network, local, err, n, berr)
	return c, err
}

// Accept implements Proxy.
func (h *auto) Accept(network, local string) (protect.Listener, error) {
	if err := candial(&h.status); err != nil {
		return nil, err
	}

	// TODO: settings.AutoDialsParallel
	remoteOnly := settings.AutoAlwaysRemote()

	exit, exerr := h.pxr.ProxyFor(Exit)
	win, winerr := h.pxr.mainRpnProxyOf(RpnWin)

	previdx, recent := h.exp.Get(local)

	l, who, err := core.Race(
		network+".accept-auto."+local,
		tlsHandshakeTimeout,
		func(ctx context.Context) (protect.Listener, error) {
			const myidx = 0
			if exit == nil {
				return nil, exerr
			}
			if remoteOnly {
				return nil, errNotRemote
			}
			if recent {
				if previdx != myidx {
					return nil, errNotPinned
				}
				return h.acceptIfHealthy(exit, network, local)
			}
			return h.acceptIfHealthy(exit, network, local)
		}, func(ctx context.Context) (protect.Listener, error) {
			const myidx = 1
			if win == nil {
				return nil, winerr
			}
			if recent {
				if previdx != myidx {
					return nil, errNotPinned
				}
				return h.acceptIfHealthy(win, network, local)
			}
			// delay if not dialing remote exclusively
			if !remoteOnly {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(shortdelay * myidx): // 100ms
				}
			}
			return h.acceptIfHealthy(win, network, local)
		},
	)
	defer localDialStatus(&h.status, err)

	log.I("proxy: auto: w(%d) accept(%s) on %s; err? %v", who, network, local, err)
	return l, err
}

// Probe implements Proxy.
func (h *auto) Probe(network, local string) (protect.PacketConn, error) {
	if err := candial(&h.status); err != nil {
		return nil, err
	}

	exit, exerr := h.pxr.ProxyFor(Exit)
	win, winerr := h.pxr.mainRpnProxyOf(RpnWin)

	previdx, recent := h.exp.Get(local)

	pc, who, err := core.Race(
		network+".probe-auto."+local,
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
				return h.probeIfHealthy(exit, network, local)
			}
			return h.probeIfHealthy(exit, network, local)
		}, func(ctx context.Context) (protect.PacketConn, error) {
			const myidx = 1
			if win == nil {
				return nil, winerr
			}
			if recent {
				if previdx != myidx {
					return nil, errNotPinned
				}
				return h.probeIfHealthy(win, network, local)
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(shortdelay * myidx): // 100ms
			}
			return h.probeIfHealthy(win, network, local)
		},
	)
	defer localDialStatus(&h.status, err)

	log.I("proxy: auto: w(%d) probe(%s) on %s; err? %v", who, network, local, err)
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

// Self implements x.Router.
func (h *auto) Self(ip string) bool {
	if len(ip) <= 0 {
		return false
	}
	if settings.AutoAlwaysRemote() {
		if win, _ := h.pxr.mainRpnProxyOf(RpnWin); win != nil {
			if iscircular(win, ip) {
				return true
			}
		}
		if exit64, _ := h.pxr.ProxyFor(Rpn64); exit64 != nil {
			if iscircular(exit64, ip) {
				return true
			}
		}
		return false
	}
	if exit, _ := h.pxr.ProxyFor(Exit); exit != nil {
		return iscircular(exit, ip)
	}
	return false
}

// Hop implements Proxy.
func (h *auto) Hop(via *core.WeakRef[Proxy], dryrun bool) error {
	var winerr error
	if !dryrun {
		old := h.via.Swap(via)
		log.I("proxy: auto: hop %s => %s", refhandle(old), refhandle(via))
	}
	if win, _ := h.pxr.mainRpnProxyOf(RpnWin); win != nil {
		winerr = win.Hop(via, dryrun)
	}

	logei(winerr)("proxy: auto: hop set; win err? %v", winerr)

	return winerr
}

func (h *auto) Via() (x.Proxy, error) {
	if ref := h.via.Load(); ref != nil {
		if v, ok := ref.Get(); ok && v != nil {
			return v, nil
		}
	}
	return nil, errNoHop
}

// GetAddr implements x.Proxy.
func (h *auto) GetAddr() string {
	return h.addr
}

// Status implements x.Proxy.
func (h *auto) Status() int32 {
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
		log.E("auto announce; %s %s not ok; %v: %s", p.ID(), network, err, local)
		time.Sleep(delayForUnhealthyProxies)
	}
	return p.Dialer().Announce(network, local)
}

func (*auto) acceptIfHealthy(p Proxy, network, local string) (net.Listener, error) {
	if err := healthy(p); err != nil {
		log.E("auto accept; %s %s not ok; %v: %s", p.ID(), network, err, local)
		time.Sleep(delayForUnhealthyProxies)
	}
	return p.Dialer().Accept(network, local)
}

func (*auto) probeIfHealthy(p Proxy, network, local string) (net.PacketConn, error) {
	if err := healthy(p); err != nil {
		log.E("auto probe; %s %s not ok; %v: %s", p.ID(), network, err, local)
		time.Sleep(delayForUnhealthyProxies)
	}
	return p.Dialer().Probe(network, local)
}

func changeBufferSizes(c core.MinConn) (int, error) {
	opts := settings.GetDialerOpts()
	rsz := int(opts.ReadBufferSize)
	wsz := int(opts.WriteBufferSize)
	return core.ChangeBufferSizes(c, rsz, wsz)
}

// laddr returns the local address of conn c as a string, or false if c is nil.
func laddr(c net.Conn) (string, bool) {
	if c == nil || core.IsNil(c) {
		return "", false
	}
	if addr := c.LocalAddr(); addr != nil {
		return addr.String(), true
	}
	return "", false
}

func maybeKeepAlive(c net.Conn) (keepingalive bool) {
	keepingalive, _ = maybeKeepAlive2(c)
	return
}

func maybeKeepAlive2(c net.Conn) (keepingalive, ok bool) {
	if c == nil || core.IsNil(c) {
		return
	}

	if opts := settings.GetDialerOpts(); opts.LowerKeepAlive {
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
