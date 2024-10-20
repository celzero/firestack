// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"context"
	"math/rand"
	"net"
	"net/netip"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
)

var (
	// preset 6to4 NATs
	// from: nat64.xyz
	net6to4 = []netip.Prefix{
		netip.MustParsePrefix("2a00:1098:2b::/96"),          // kasper
		netip.MustParsePrefix("2a00:1098:2c:1::/96"),        // kasper
		netip.MustParsePrefix("2a01:4f8:c2c:123f:64::/96"),  // kasper
		netip.MustParsePrefix("2a01:4f9:c010:3f02:64::/96"), // kasper
		netip.MustParsePrefix("2001:67c:2960:6464::/96"),    // level66
		netip.MustParsePrefix("2001:67c:2b0:db32:0:1::/96"), // trex
	}
)

var ttl30s = 30 * time.Second

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

	previdx, recent := h.exp.V(addr)

	c, who, err := core.Race(
		network+".dial-auto."+addr,
		tlsHandshakeTimeout,
		func() (protect.Conn, error) {
			const myidx = 0
			if exit == nil {
				return nil, exerr
			}
			if recent && previdx != myidx {
				return nil, errNotPinned
			}
			return exit.Dialer().Dial(network, addr)
		}, func() (protect.Conn, error) {
			const myidx = 1
			if warp == nil {
				return nil, waerr
			}
			if recent && previdx != myidx {
				return nil, errNotPinned
			}
			return warp.Dialer().Dial(network, addr)
		}, func() (protect.Conn, error) {
			const myidx = 2
			if exit == nil {
				return nil, exerr
			}
			if recent && previdx != myidx {
				return nil, errNotPinned
			}
			if addr64 := addr4to6(addr); len(addr64) > 0 {
				return exit.Dialer().Dial(network, addr64)
			}
			return nil, errNoAuto464XLAT
		},
	)

	if err != nil {
		h.exp.Delete(addr)
		h.status.Store(TKO)
	} else {
		h.exp.K(addr, who, ttl30s)
		h.status.Store(TOK)
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

// go.dev/play/p/GtLCDAXeeLJ
func addr4to6(addr string) string {
	// check if addr is an IPv4 address
	ipport, err := netip.ParseAddrPort(addr)
	if err != nil {
		// todo: query? dialers.Resolve(addr)
		log.W("proxy: auto: addr64: invalid addr(%s); err(%v)", addr, err)
		return ""
	}
	ip4 := ipport.Addr()
	if !ip4.Is4() {
		log.VV("proxy: auto: addr64: not IPv4(%s)", addr)
		return ""
	}
	// convert IPv4 to IPv6
	ippre := net6to4[rand.Intn(len(net6to4))]
	ip6 := ip4to6(ippre, ip4)
	if !ip6.IsValid() {
		log.W("proxy: auto: addr64: failed to convert(%s) to IPv6", ip4)
		return ""
	}
	return netip.AddrPortFrom(ip6, ipport.Port()).String()
}

func ip4to6(prefix96 netip.Prefix, ip4 netip.Addr) netip.Addr {
	if !prefix96.IsValid() || !ip4.IsValid() {
		return netip.Addr{}
	}
	startingAddress := prefix96.Masked().Addr()
	addrLen := startingAddress.BitLen() / 8 // == 128 / 8 == 16
	prefixLen := prefix96.Bits() / 8        // == 96 / 8 == 12
	hostLen := (addrLen - prefixLen)        // == 16 - 12 == 4
	s6 := startingAddress.As16()
	s4 := ip4.As4()
	n := copy(s6[prefixLen:], s4[:hostLen])
	if n != hostLen {
		log.W("proxy: auto: ip4to6(%v, %v) failed; pre:%d host:%d for net:%v ip4:%v",
			s6, s4, prefixLen, hostLen, prefix96, ip4)
		return netip.Addr{}
	}
	return netip.AddrFrom16(s6)
}

func maybeKeepAlive(c net.Conn) {
	if settings.GetDialerOpts().LowerKeepAlive {
		// adjust TCP keepalive config if c is a TCPConn
		core.SetKeepAliveConfigSockOpt(c)
	}
}
