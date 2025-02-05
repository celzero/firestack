// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"sync"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/ipn/seasy"
	"github.com/celzero/firestack/intra/ipn/warp"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/netstack"
	"github.com/celzero/firestack/intra/protect"
)

const (
	Block    = x.Block
	Base     = x.Base
	Exit     = x.Exit
	Auto     = x.Auto
	Ingress  = x.Ingress // dummy
	OrbotS5  = x.OrbotS5
	OrbotH1  = x.OrbotH1
	GlobalH1 = x.GlobalH1
	RpnWg    = x.RpnWg
	RpnPro   = x.RpnPro
	RpnAmz   = x.RpnAmz
	RpnWs    = x.RpnWs
	Rpn64    = x.Rpn64
	RpnH2    = x.RpnH2
	RpnSE    = x.RpnSE

	SOCKS5   = x.SOCKS5
	HTTP1    = x.HTTP1
	WG       = x.WG
	PIPH2    = x.PIPH2
	PIPWS    = x.PIPWS
	NOOP     = x.NOOP
	INTERNET = x.INTERNET
	RPN      = x.RPN

	TNT = x.TNT
	TZZ = x.TZZ
	TUP = x.TUP
	TOK = x.TOK
	TKO = x.TKO
	END = x.END

	NOMTU  = 0
	MAXMTU = 65535
)

var (
	errProxyScheme        = errors.New("proxy: unsupported scheme")
	errUnexpectedProxy    = errors.New("proxy: unexpected type")
	errAddProxy           = errors.New("proxy: add failed")
	errProxyNotFound      = errors.New("proxy: not found")
	errGetProxyTimeout    = errors.New("proxy: get timeout")
	errProxyAllDown       = errors.New("proxy: all down")
	errNoProxyHealthy     = errors.New("proxy: none healthy")
	errMissingProxyOpt    = errors.New("proxy: opts nil")
	errNoProxyConn        = errors.New("proxy: not a tcp/udp conn")
	errNotUDPConn         = errors.New("proxy: not a udp conn")
	errProxyStopped       = errors.New("proxy: stopped")
	errProxyConfig        = errors.New("proxy: invalid config")
	errProxyReadd         = errors.New("proxy: cannot update; readd config")
	errNoProxyResponse    = errors.New("proxy: no response from upstream")
	errNoSig              = errors.New("proxy: auth missing sig")
	errNoMtu              = errors.New("proxy: missing mtu")
	errNoOpts             = errors.New("proxy: no opts")
	errMissingRev         = errors.New("proxy: missing reverse proxy")
	errNoAuto464XLAT      = errors.New("auto: no 464xlat")
	errNotPinned          = errors.New("auto: another proxy pinned")
	errInvalidAddr        = errors.New("proxy: invaild ip:port")
	errNoRouteToHost      = errors.New("proxy: no route to host")
	errMissingProxyID     = errors.New("proxy: missing proxy id")
	errHopDefaultRoutes   = errors.New("proxy: hop must route all ip4/ip6")
	errHopHopping         = errors.New("proxy: hop must not be hopping")
	errNoHop              = errors.New("proxy: no hop")
	errHopSelf            = errors.New("proxy: hop looping back onto hop")
	errHopWireGuard       = errors.New("proxy: hop must be wireguard")
	errHopMtuInsufficient = errors.New("proxy: hop mtu insufficient")
	errHopProxyRoutes     = errors.New("proxy: no routes to hop")
	errHop4Gateway        = errors.New("proxy: hop cannot route ip4")
	errHop6Gateway        = errors.New("proxy: hop cannot route ip6")
	errHopGlobalProxy     = errors.New("proxy: hop must be global proxy")
	errNilAmzId           = errors.New("proxy: amz id nil")
	errNilProtonCfg       = errors.New("proxy: proton cfg nil")
)

const (
	udptimeoutsec         int           = 5 * 60                    // 5m
	tcptimeoutsec         int           = (2 * 60 * 60) + (40 * 60) // 2h40m
	getproxytimeout       time.Duration = 5 * time.Second
	tlsHandshakeTimeout   time.Duration = 30 * time.Second // some proxies take a long time to handshake
	responseHeaderTimeout time.Duration = 60 * time.Second
	tzzTimeout            time.Duration = 2 * time.Minute  // time between new connections before proxies transition to idle
	lastOKThreshold       time.Duration = 10 * time.Minute // time between last OK and now before pinging & un-pinning
	pintimeout            time.Duration = 10 * time.Minute // time to keep a pin
	alwaysPin             bool          = true             // always pin to a proxy no matter the errors
)

// type checks
var _ Proxy = (*base)(nil)
var _ Proxy = (*exit)(nil)
var _ Proxy = (*auto)(nil)
var _ Proxy = (*socks5)(nil)
var _ Proxy = (*http1)(nil)
var _ Proxy = (*wgproxy)(nil)
var _ Proxy = (*ground)(nil)
var _ Proxy = (*pipws)(nil)
var _ Proxy = (*piph2)(nil)

type Proxy interface {
	x.Proxy
	protect.RDialer

	// Dialer returns the dialer for this proxy, which is an
	// adapter for protect.RDialer interface, but with the caveat that
	// not all Proxy instances implement DialTCP and DialUDP, though are
	// guaranteed to implement Dial.
	Dialer() protect.RDialer
	// onNotOK is called by clients when the proxy is not responsive.
	onNotOK() bool
	// onProtoChange returns true if the proxy must be re-added with cfg on proto changes.
	OnProtoChange(lp LinkProps) (cfg string, readd bool)
	// Gateway sets proxy p as the gateway for this router.
	Hop(p Proxy) error
}

type Proxies interface {
	x.Proxies
	// ProxyFor returns a transport from this multi-transport.
	ProxyFor(id string) (Proxy, error)
	// ProxyTo returns the proxy to use for ipp from given pids.
	ProxyTo(ipp netip.AddrPort, uid string, pids []string) (Proxy, error)
	// RefreshProto broadcasts proto change to all active proxies.
	RefreshProto(l3 string, mtu int)
	// LiveProxies returns a csv of active proxies.
	LiveProxies() string
	// Reverser sets the reverse proxy for all proxies.
	Reverser(r netstack.GConnHandler) error
}

type proxifier struct {
	sync.RWMutex
	NoVia

	ctx context.Context
	p   map[string]Proxy

	ctl protect.Controller // dial control provider
	obs x.ProxyListener    // proxy observer

	lp LinkProps // link properties; protected by mu

	staller *core.ExpMap[string, string] // uid+dst(domainOrIP) -> stallSecs

	ipPins  *core.Sieve[netip.AddrPort, string]           // ipp -> proxyid
	uidPins *core.Sieve2K[string, netip.AddrPort, string] // uid -> [dst -> proxyid]

	sched *core.Scheduler

	// immutable proxies
	exit     *exit   // exit proxy, never changes
	exit64   *exit64 // rpn64 proxy, never changes
	base     *base   // base proxy, never changes
	grounded *ground // grounded proxy, never changes
	auto     *auto   // auto proxy, never changes

	extc *warp.Client // external wg registration, never changes
	sec  *seasy.SEApi // se proxy registration, never changes; may be nil

	lastSeErr     *core.Volatile[error] // se proxy registration error
	lastWarpErr   *core.Volatile[error] // warp registration error
	lastAmzErr    *core.Volatile[error] // amnezia registration error
	lastProtonErr *core.Volatile[error] // proton registration error
}

type LinkProps struct {
	l3  string // ip4, ip6, ip46
	mtu int
	rev netstack.GConnHandler // downstream; may be nil
}

func (lp LinkProps) String() string {
	return fmt.Sprintf("l3:%s/mtu:%d/rev:%X", lp.l3, lp.mtu, lp.rev)
}

var _ Proxies = (*proxifier)(nil)
var _ x.Rpn = (*proxifier)(nil)
var _ x.Router = (*proxifier)(nil)
var _ protect.RDialer = (Proxy)(nil)
var _ Proxy = (*NoProxy)(nil)
var _ x.Router = (*NoProxy)(nil)

// NewProxifier returns a new Proxifier instance.
func NewProxifier(pctx context.Context, l3 string, mtu int, c protect.Controller, o x.ProxyListener) *proxifier {
	if c == nil || o == nil {
		return nil
	}

	pxr := &proxifier{
		ctx:   pctx,
		p:     make(map[string]Proxy),
		ctl:   c,
		obs:   o,
		sched: core.NewScheduler(pctx),

		lp: LinkProps{l3: l3, mtu: mtu},

		lastSeErr:     core.NewZeroVolatile[error](),
		lastWarpErr:   core.NewZeroVolatile[error](),
		lastAmzErr:    core.NewZeroVolatile[error](),
		lastProtonErr: core.NewZeroVolatile[error](),
	}

	pxr.exit = NewExitProxy(pctx, c)
	pxr.exit64 = NewExit64Proxy(pctx, c)
	pxr.base = NewBaseProxy(pctx, c)
	pxr.grounded = NewGroundProxy()
	pxr.auto = NewAutoProxy(pctx, pxr)
	pxr.staller = core.NewExpiringMap[string, string](pctx)
	pxr.ipPins = core.NewSieve[netip.AddrPort, string](pctx, pintimeout)
	pxr.uidPins = core.NewSieve2K[string, netip.AddrPort, string](pctx, pintimeout)

	pxr.extc = warp.NewExtClient(pctx, c)
	if se, serr := seasy.NewSEasyClient(pxr.exit); serr != nil {
		pxr.lastSeErr.Store(serr)
	} else {
		pxr.sec = se
	}

	pxr.add(pxr.exit)     // fixed
	pxr.add(pxr.exit64)   // fixed
	pxr.add(pxr.base)     // fixed
	pxr.add(pxr.grounded) // fixed
	pxr.add(pxr.auto)     // fixed

	log.I("proxy: new")

	context.AfterFunc(pctx, pxr.stopProxies)

	return pxr
}

func (px *proxifier) add(p Proxy) (ok bool) {
	var old Proxy
	id := p.ID()

	px.Lock()
	defer px.Unlock()

	defer func() {
		if ok {
			core.Go("pxr.add: "+id, func() {
				px.obs.OnProxyAdded(id)
			})
			// new proxy, invoke Stop on old proxy
			if old != nil && old.Handle() != p.Handle() {
				// holding px.lock, so exec stop in a goroutine
				core.Go("pxr.add.stop: "+id, func() {
					_ = old.Stop()
					// onRmv is not sent here, as one has just been added
				})
			}
		}
	}()

	old = px.p[id]
	if immutable(id) {
		switch id {
		case Exit:
			if x, typeok := p.(*exit); typeok {
				px.exit = x
				px.p[id] = p
				ok = true
			}
		case Base:
			if x, typeok := p.(*base); typeok {
				px.base = x
				px.p[id] = p
				ok = true
			}
		case Block:
			if x, typeok := p.(*ground); typeok {
				px.grounded = x
				px.p[id] = p
				ok = true
			}
		case Rpn64:
			if x, typeok := p.(*exit64); typeok {
				px.exit64 = x
				px.p[id] = p
				ok = true
			}
		case Auto:
			if x, typeok := p.(*auto); typeok {
				px.auto = x
				px.p[id] = p
				ok = true
			}
		}
	} else {
		px.p[id] = p
		ok = true
	}

	logeif(ok)("proxy: add: proxy %s ok? %t", id, ok)
	return ok
}

func (px *proxifier) RemoveProxy(id string) bool {
	defer core.Recover(core.Exit11, "pxr.RemoveProxy."+id)

	return px.removeProxy(id, false /*force remove?*/)
}

func (px *proxifier) removeProxy(id string, force bool) bool {
	if isInternal(id) && !force {
		log.D("proxy: remove: %s; not allowed", id)
		return false
	}

	px.Lock()
	defer px.Unlock()

	perma := immutable(id)
	if p, ok := px.p[id]; ok {
		if !perma {
			delete(px.p, id)
		}
		core.Go("pxr.removeProxy: "+id, func() {
			_ = p.Stop()
			if !perma {
				px.obs.OnProxyRemoved(id)
				log.I("proxy: removed %s", id)
			} else {
				px.obs.OnProxyStopped(id)
				log.I("proxy: stopped (not removed) %s", id)
			}
		})
		return true
	}
	return false
}

// ProxyTo implements Proxies.
// May return both a Proxy and an error, in which case, the error
// denotes that while the Proxy is not healthy, it is still registered.
func (px *proxifier) ProxyTo(ipp netip.AddrPort, uid string, pids []string) (_ Proxy, err error) {
	if len(pids) <= 0 || firstEmpty(pids) {
		return nil, errMissingProxyID
	}
	if !ipp.IsValid() {
		return nil, errMissingAddress
	}

	ippstr := ipp.String()

	if len(pids) == 1 { // there's no other pid to choose from
		// skip hasroute, as there is only one pid to route to
		p, err := px.pinID(uid, ipp, pids[0]) // repin
		if err != nil || p == nil {
			err = core.OneErr(err, errProxyNotFound)
			px.stall(uid + ippstr)
		}
		// alwaysPin is set to true, so return p even if err is not nil
		if alwaysPin && p != nil {
			err = nil
		}
		return p, err
	}

	var lopinned string
	var someproxy Proxy

	pinnedpid, pinok := px.getpin(uid, ipp)
	chosen := has(pids, pinnedpid)
	lo := local(pinnedpid)

	log.VV("proxy: pin: %s+%s; pinned: %s; chosen? %t / local? %t; from pids: %v",
		uid, ippstr, pinnedpid, chosen, lo, pids)

	if pinok && chosen && lo {
		// always favour remote proxy pins over local, if any
		lopinned = pinnedpid
	} else if pinok && chosen {
		p, err := px.pinID(uid, ipp, pinnedpid) // repin
		if p != nil && err == nil && hasroute(p, ippstr) {
			return p, nil
		} // else: pinnedpid not ok or no route
	} else if pinok && !chosen {
		px.delpin(uid, ipp)
	}

	notokproxies := make([]string, 0)
	endproxies := make([]string, 0)
	norouteproxies := make([]string, 0)
	missproxies := make([]string, 0)
	loproxies := make([]string, 0)
	if len(lopinned) > 0 { // lopinned may be empty
		loproxies = append(loproxies, lopinned)
	}

	defer func() {
		logev(err)("proxy: pin: %s+%s; miss: %v; notok: %v; noroute: %v; ended %v",
			uid, ipp, missproxies, notokproxies, norouteproxies, endproxies)
	}()

	for _, pid := range pids {
		if pid == pinnedpid { // already tried above
			continue
		}
		if local(pid) { // skip local; prefer remote
			loproxies = append(loproxies, pid)
			continue // process later
		}

		p, err := px.ProxyFor(pid)
		if err != nil || p == nil { // proxy 404
			missproxies = append(missproxies, pid)
			continue
		}

		if p.Status() == END {
			endproxies = append(endproxies, pid)
			continue
		}

		if hasroute(p, ippstr) {
			err := px.pin(uid, ipp, p) // repin
			if err == nil {
				log.VV("proxy: pin: %s+%s; pinned: %s; from pids: %v", uid, ipp, pid, pids)
				return p, nil
			} // else: proxy not ok
			notokproxies = append(notokproxies, pid)
			if someproxy == nil {
				someproxy = p
			}
		} else { // else: proxy cannot route; split-tunnel
			norouteproxies = append(norouteproxies, pid)
		}
	}

	// can route but not healthy; choose any one on random
	if len(notokproxies) > 0 {
		px.stall(uid + ippstr)
		if alwaysPin && someproxy != nil {
			return someproxy, nil
		}
		return nil, errNoProxyHealthy
	}

	// lopinned is always the first element, if any.
	for _, pid := range loproxies {
		// ignore err, as it unlikely for local proxies
		// that are always available, and are presumed to
		// be gateways (route all ips)
		if p, _ := px.pinID(uid, ipp, pid); p != nil { // repin
			return p, nil
		}
		missproxies = append(missproxies, pid)
	}

	px.stall(uid + ippstr)
	return nil, errProxyAllDown
}
func (px *proxifier) stall(k string) (secs uint32) {
	if n := px.staller.Get(k); n <= 5 {
		secs = (rand.Uint32() % 5) + 1 // up to 5s
	} else if n > 10 {
		secs = 10 // max up to 10s
	} else {
		secs = n
	}
	// track uid->target for 30 secs
	px.staller.Set(k, 30*time.Second)
	if secs > 0 {
		w := time.Duration(secs) * time.Second
		time.Sleep(w)
	}
	return
}

func (px *proxifier) pinID(uid string, ipp netip.AddrPort, id string) (Proxy, error) {
	p, err := px.ProxyFor(id)
	if err != nil || p == nil {
		err = core.OneErr(err, errProxyNotFound)
		return nil, fmt.Errorf("proxy: pin: id %s; err: %v", id, err)
	}
	err = px.pin(uid, ipp, p)
	return p, err
}

func (px *proxifier) pin(uid string, ipp netip.AddrPort, p Proxy) error {
	err := healthy(p) // called to ensure p is ready-to-go
	if err == nil {
		px.uidPins.Put(uid, ipp, p.ID())
		px.ipPins.Put(ipp, p.ID())
	}
	logev(err)("proxy: pin: ok? %t; %s from %s; err? %v",
		err == nil, ipp, p.ID(), err)

	if err != nil {
		return fmt.Errorf("proxy: pin: %s; err: %v", p.ID(), err)
	}
	return nil
}

func (px *proxifier) delpin(uid string, ipp netip.AddrPort) {
	px.uidPins.Del(uid, ipp)
	px.ipPins.Del(ipp)
}

func (px *proxifier) getpin(uid string, ipp netip.AddrPort) (string, bool) {
	if id, ok := px.uidPins.Get(uid, ipp); ok {
		return id, ok
	}
	return px.ipPins.Get(ipp)
}

func (px *proxifier) clearpins() (int, int) {
	totips := px.ipPins.Clear()
	totuids := px.uidPins.Clear()

	return totips, totuids
}

// ProxyFor returns the proxy for the given id or an error.
// As a special case, if it takes longer than getproxytimeout, it returns an error.
// ProxyFor implements Proxies.
func (px *proxifier) ProxyFor(id string) (Proxy, error) {
	defer core.Recover(core.Exit11, "pxr.ProxyFor."+id)

	if len(id) <= 0 {
		return nil, errProxyNotFound
	}

	if immutable(id) { // fast path for immutable proxies
		if id == Exit {
			return px.exit, nil
		} else if id == Base {
			return px.base, nil
		} else if id == Block {
			return px.grounded, nil
		} else if id == Auto {
			return px.auto, nil
		} else if id == Rpn64 {
			return px.exit64, nil
		} // Ingress do not have a fast path
	}

	// go.dev/play/p/xCug1W3OcMH
	p, ok := core.Grx("pxr.ProxyFor: "+id, func(_ context.Context) (Proxy, error) {
		px.RLock()
		defer px.RUnlock()

		return px.p[id], nil
	}, getproxytimeout)

	if !ok {
		log.W("proxy: for: %s; timeout!", id)
		// possibly a deadlock, so return an error
		return nil, errGetProxyTimeout
	}
	if p == nil || core.IsNil(p) {
		log.W("proxy: for: %s; not found", id)
		return nil, errProxyNotFound
	}
	return p, nil
}

// GetProxy implements x.Proxies.
func (px *proxifier) GetProxy(id string) (x.Proxy, error) {
	return px.ProxyFor(id)
}

// Hop implements Proxies.
func (px *proxifier) Hop(via, origin string) error {
	defer core.Recover(core.Exit11, "pxr.Hop."+via+">>"+origin)

	if len(origin) <= 0 {
		return errMissingProxyID
	}
	origPx, err := px.ProxyFor(origin)
	if err != nil || origPx == nil {
		return core.OneErr(err, errProxyNotFound)
	}

	if len(via) <= 0 { // remove hop
		return origPx.Hop(nil)
	}

	if via == origin {
		return errHopSelf
	}

	viaPx, err := px.ProxyFor(via)
	if err != nil || viaPx == nil {
		return core.OneErr(err, errProxyNotFound)
	}
	if viaPx.Status() == END || origPx.Status() == END {
		return errProxyStopped
	}

	viaRouter := viaPx.Router()
	if viaViaVia, _ := viaRouter.Via(); viaViaVia != nil {
		log.W("proxy: triple hop: %s => %s => %s; not allowed", origin, via, viaViaVia.ID())
		return errHopHopping
	} else if !viaRouter.IP4() && !viaRouter.IP6() {
		// via must either route all ip4 or all ip6; ideally both
		return errHopDefaultRoutes
	}

	return origPx.Hop(viaPx)
}

// Router implements x.Proxy.
func (px *proxifier) Router() x.Router {
	return px
}

// Rpn implements x.Proxies.
func (px *proxifier) Rpn() x.Rpn {
	return px
}

func (px *proxifier) stopProxies() {
	px.Lock()
	defer px.Unlock()

	l := len(px.p)
	for _, p := range px.p {
		curp := p
		id := curp.ID()

		core.Go("pxr.stopProxies: "+id, func() {
			_ = curp.Stop()
		})
	}
	clear(px.p)
	px.staller.Clear()
	px.ipPins.Clear()
	px.uidPins.Clear()
	px.sched.Clear()

	core.Go("pxr.onStop", func() { px.obs.OnProxiesStopped() })
	log.I("proxy: all(%d) stopped and removed", l)
}

// RefreshProxies implements x.Proxies.
func (px *proxifier) RefreshProxies() (string, error) {
	defer core.Recover(core.Exit11, "pxr.RefreshProxies")

	ptot, ptotu := px.clearpins()

	px.Lock()
	defer px.Unlock()

	tot := len(px.p)
	log.I("proxy: refresh pxs: %d / removed pins: %d %d", tot, ptot, ptotu)

	var which = make([]string, 0, len(px.p))
	for _, p := range px.p {
		curp := p
		id := curp.ID()
		which = append(which, id)
		// some proxy.Refershes may be slow due to network requests, hence
		// preferred to run in a goroutine to avoid blocking the caller.
		// ex: wgproxy.Refresh -> multihost.Refersh -> dialers.Resolve
		core.Gx("pxr.RefreshProxies: "+id, func() {
			if err := curp.Refresh(); err != nil {
				log.E("proxy: refresh (%s/%s/%s) failed: %v", id, curp.Type(), curp.GetAddr(), err)
			}
		})
	}

	log.I("proxy: refreshed %d / %d: %v", len(which), tot, which)

	return strings.Join(which, ","), nil
}

// LiveProxies implements x.Proxies.
func (px *proxifier) LiveProxies() string {
	px.RLock()
	defer px.RUnlock()

	out := make([]string, 0, len(px.p))
	for id := range px.p {
		out = append(out, id)
	}
	return strings.Join(out, ",")
}

// RefreshProto implements x.Proxies.
func (px *proxifier) RefreshProto(l3 string, mtu int) {
	defer core.Recover(core.Exit11, "pxr.RefreshProto")
	// must unlock from deferred since panics are recovered above
	px.Lock()
	defer px.Unlock()

	if px.lp.l3 == l3 && px.lp.mtu == mtu {
		log.D("proxy: refreshProto (%s == %s & %d == %d) unchanged",
			px.lp.l3, l3, px.lp.mtu, mtu)
		return
	}

	newlp := LinkProps{l3: l3, mtu: mtu, rev: px.lp.rev} // copy
	px.lp = newlp
	for _, p := range px.p {
		curp := p
		id := curp.ID()
		core.Gx("pxr.RefreshProto: "+id, func() {
			// always run in a goroutine (or there is a deadlock)
			// wgproxy.onProtoChange -> multihost.Refresh -> dialers.Resolve
			// -> ipmapper.LookupIPNet -> resolver.LocalLookup -> transport.Query
			// -> ipn.ProxyFor -> px.Lock() -> deadlock
			if cfg, readd := curp.OnProtoChange(newlp); readd {
				// px.addProxy -> px.add -> px.Lock() -> deadlock
				_, err := px.addProxy(id, cfg)
				log.I("proxy: refreshProto (%s/%s/%s) re-add; err? %v",
					id, curp.Type(), curp.GetAddr(), err)
			}
		})
	}
}

func (px *proxifier) Reverser(rhdl netstack.GConnHandler) error {
	px.Lock()
	defer px.Unlock()

	px.lp.rev = rhdl
	return nil
}

// IP4 implements x.Router.
func (px *proxifier) IP4() bool {
	px.RLock()
	defer px.RUnlock()

	for _, p := range px.p {
		if local(p.ID()) {
			continue
		}
		if r := p.Router(); r != nil && !r.IP4() {
			return false
		}
	}
	return len(px.p) > 0
}

// IP6 implements x.Router.
func (px *proxifier) IP6() bool {
	px.RLock()
	defer px.RUnlock()

	for _, p := range px.p {
		if local(p.ID()) {
			continue
		}
		if r := p.Router(); r != nil && !r.IP6() {
			return false
		}
	}

	return len(px.p) > 0
}

// MTU implements x.Router.
func (px *proxifier) MTU() (out int, err error) {
	px.RLock()
	defer px.RUnlock()

	out = MAXMTU
	only4 := false
	minmtu := minmtu6
	for _, p := range px.p {
		if local(p.ID()) {
			continue
		}
		r := p.Router() // never nil
		only4 = only4 || r.IP4() && !r.IP6()
		if only4 && minmtu > minmtu4 {
			minmtu = minmtu4
		}
		if hopping(r) { // skip proxies hopping via another
			continue
		} // inner tunnel MTUs should not have any bearing on outer MTU
		if m, err1 := r.MTU(); err1 == nil {
			out = min(out, max(m, minmtu))
		} // else: NOMTU
	}
	if out == MAXMTU || out == NOMTU { // unchanged or unknown
		err = errNoMtu
	}
	return out, err
}

// Stat implements x.Router.
func (px *proxifier) Stat() *x.RouterStats {
	px.RLock()
	defer px.RUnlock()

	s := new(x.RouterStats)
	for _, p := range px.p {
		if local(p.ID()) {
			continue
		}
		if r := p.Router(); r != nil {
			s = accStats(s, r.Stat())
		}
	}
	return s
}

func accStats(a, b *x.RouterStats) (c *x.RouterStats) {
	c = new(x.RouterStats)
	if a == nil && b == nil {
		return c
	} else if a == nil {
		return b
	} else if b == nil {
		return a
	}
	// c.Addr?
	c.Tx = a.Tx + b.Tx
	c.Rx = a.Rx + b.Rx
	c.ErrRx = a.ErrRx + b.ErrRx
	c.ErrTx = a.ErrTx + b.ErrTx
	c.LastOK = max(a.LastOK, b.LastOK)
	c.LastRx = max(a.LastRx, b.LastRx)
	c.LastTx = max(a.LastTx, b.LastTx)
	// todo: a.Since or b.Since may be zero
	c.Since = min(a.Since, b.Since)
	return
}

// Contains implements x.Router.
func (px *proxifier) Contains(ipprefix string) bool {
	px.RLock()
	defer px.RUnlock()

	for _, p := range px.p {
		// always present local proxies route either everything or
		// nothing: not useful for making routing decisions
		if local(p.ID()) {
			continue
		}
		if r := p.Router(); r != nil && r.Contains(ipprefix) {
			return true
		}
	}
	return false
}

// Reaches implements x.Router.
func (px *proxifier) Reaches(hostportOrIPPortCsv string) bool {
	px.RLock()
	defer px.RUnlock()

	for _, p := range px.p {
		if r := p.Router(); r != nil && r.Reaches(hostportOrIPPortCsv) {
			return true
		}
	}
	return false
}

// RegisterWarp implements x.Rpn.
func (px *proxifier) RegisterWarp(existingStateJson []byte) (stateJson []byte, err error) {
	return px.registerWarp(existingStateJson)
}

func (px *proxifier) registerWarp(existingStateJson []byte) (stateJson []byte, err error) {
	defer func() {
		px.lastWarpErr.Store(err) // may be nil
	}()

	restore := len(existingStateJson) > 0
	var id *warp.Identity // may be nil

	if restore {
		id, err = px.extc.MakeWarpFrom(existingStateJson)
	} else {
		id, err = px.extc.MakeWarp()
	}

	if err != nil {
		log.E("proxy: warp: make for %s failed: %v", id.Of(), err)
		return nil, err
	}

	state, err := id.Json()
	if err != nil {
		return nil, err
	}

	go px.obs.OnRpnUpdated(RpnWg, state)

	const retrydelay = 10 * time.Minute
	const retries = 6 // [1..6]*10m => (6*(6+1)/2)*10m => 210m

	px.sched.Retry(RpnWg, id.Expires(), func() error {
		_, err := px.registerWarp(nil)
		logev(err)("proxy: warp: sched: update: id(%s) until: %s; err? %v",
			id.Of(), id.Expires().Format(time.RFC1123), err)
		return err
	}, retries, retrydelay)

	// TODO: add RpnWg proxy

	return state, nil
}

// RegisterAmnezia implements x.Rpn.
func (px *proxifier) RegisterAmnezia(existingStateJson []byte) (stateJson []byte, err error) {
	return px.registerAmnezia(existingStateJson)
}

func (px *proxifier) registerAmnezia(existingStateJson []byte) (stateJson []byte, err error) {
	defer func() {
		px.lastAmzErr.Store(err) // may be nil
	}()

	restore := len(existingStateJson) > 0
	var id *warp.AmzWgConfig // may be nil

	if restore {
		id, err = px.extc.MakeAmzWgFrom(existingStateJson)
	} else {
		id, err = px.extc.MakeAmzWg()
	}

	if id == nil {
		return nil, errNilAmzId
	}

	if err != nil {
		log.E("proxy: amz: make (restore? %t) failed: %v", restore, err)
		return nil, err
	}

	state, err := id.Json()
	if err != nil {
		return nil, err
	}

	go px.obs.OnRpnUpdated(RpnAmz, state)

	const retrydelay = 10 * time.Minute
	const retries = 6 // [1..6]*10m => (6*(6+1)/2)*10m => 210m
	const twelveHoursInSecs = 12 * 60 * 60

	newAt := time.Unix(id.ExpiresTimestamp-twelveHoursInSecs, 0)
	px.sched.Retry(RpnAmz, newAt, func() error {
		_, errs := px.registerAmnezia(nil)
		logev(errs)("proxy: amz: sched: update: id(%s); err? %v", id.UUID, errs)
		return errs
	}, retries, retrydelay)

	log.I("proxy: amz: registered: %s / %d; new? %t", id.UUID, len(state), !restore)

	return state, nil
}

// RegisterProton implements x.Rpn.
func (px *proxifier) RegisterProton(existingStateJson []byte) (stateJson []byte, err error) {
	defer func() {
		px.lastProtonErr.Store(err) // may be nil
	}()

	const nostore = ""
	var p *warp.ProtonClient // may be nil

	restore := len(existingStateJson) > 0
	if restore {
		p, err = px.extc.MakeProtonWgFrom(existingStateJson, nostore)
	} else {
		p, err = px.extc.MakeProtonWg(nostore)
	}
	if p == nil {
		return nil, errNilProtonCfg
	}
	if err != nil {
		log.E("proxy: proton: make (restore? %t) failed: %v", restore, err)
		return nil, err
	}
	cfg, err := p.Config()
	if err != nil {
		return nil, err
	}

	state, err := cfg.Json()
	if err != nil {
		return nil, err
	}

	go px.obs.OnRpnUpdated(RpnPro, state)

	n := time.Minute // multiplier
	const retrydelay = 10 * time.Minute
	const retryduration = 210 * time.Minute // [1..6]*10m => (6*(6+1)/2)*10m => 210m
	// github.com/ProtonVPN/android-app/blob/b9c6e59de40/app/src/main/java/com/protonvpn/android/vpn/CertificateRepository.kt#L183-L188
	refreshAt := time.Unix(int64(cfg.CertRefreshTime), 0)

	px.sched.Shift(RpnPro, refreshAt, func(next core.CheckIn) (errs error) {
		defer func() {
			px.lastProtonErr.Store(errs) // may be nil
			if errs == nil {
				n = time.Minute
				next(refreshAt)
			} else {
				w := n * retrydelay
				if w <= retryduration {
					n = n + 1
					next(time.Now().Add(w))
				} else {
					log.W("proxy: proton: sched: shift over for serial(%s) n: %d; err? %v",
						cfg.CertSerialNumber, n, errs)
				}
			}
		}()

		if errs = p.Refresh(); errs == nil {
			if updatedCfg, err := p.Config(); err == nil {
				refreshAt = time.Unix(int64(cfg.CertRefreshTime), 0)

				if updatedState, err := updatedCfg.Json(); err == nil {
					px.obs.OnRpnUpdated(RpnPro, updatedState)
				}
				errs = core.JoinErr(errs, err)
			}
			errs = core.JoinErr(errs, err)
		}
		logev(err)("proxy: proton: sched: update: serial(%s); err? %v",
			cfg.CertSerialNumber, errs)
		return errs
	})

	return state, nil
}

// RegisterSE implements x.Rpn.
func (px *proxifier) RegisterSE() error {
	sec := px.sec
	if sec == nil {
		return core.JoinErr(errMissingSEClient, px.lastSeErr.Load())
	}

	sep, err := NewSEasyProxy(px.ctx, px.ctl, sec)
	px.lastSeErr.Store(err) // err may be nil, which unsets lastSeErr

	if err != nil {
		log.E("proxy: se: make failed: %v", err)
		return err
	} else if !px.add(sep) { // unlikely
		return errAddProxy
	}
	return nil
}

// RegisterExit implements x.Rpn.
func (px *proxifier) UnregisterWarp() bool {
	px.sched.Clear(RpnWg)
	return px.removeProxy(RpnWg, true)
}

// UnregisterAmnezia implements x.Rpn.
func (px *proxifier) UnregisterAmnezia() bool {
	px.sched.Clear(RpnAmz)
	return px.removeProxy(RpnAmz, true)
}

// UnregisterProton implements x.Rpn.
func (px *proxifier) UnregisterProton() bool {
	px.sched.Clear(RpnPro)
	return px.removeProxy(RpnPro, true)
}

// UnregisterSE implements x.Rpn.
func (px *proxifier) UnregisterSE() bool {
	return px.removeProxy(RpnSE, true)
}

// Warp implements x.Rpn.
func (px *proxifier) Warp() (x.Proxy, error) {
	warp, err := px.ProxyFor(RpnWg)
	if warp == nil {
		return nil, core.JoinErr(err, px.lastWarpErr.Load())
	}
	return warp, err
}

// Proton implements x.Rpn.
func (px *proxifier) Proton() (x.Proxy, error) {
	pro, err := px.ProxyFor(RpnPro)
	if pro == nil {
		return nil, core.JoinErr(err, px.lastProtonErr.Load())
	}
	return pro, err
}

// Amnezia implements x.Rpn.
func (px *proxifier) Amnezia() (x.Proxy, error) {
	amz, err := px.ProxyFor(RpnAmz)
	if amz == nil {
		return nil, core.JoinErr(err, px.lastAmzErr.Load())
	}
	return amz, err
}

// Pip implements x.Rpn.
func (px *proxifier) Pip() (x.Proxy, error) {
	return px.ProxyFor(RpnWs)
}

// Exit implements x.Rpn.
func (px *proxifier) Exit() (x.Proxy, error) {
	return px.ProxyFor(Exit)
}

// Exit64 implements x.Rpn.
func (px *proxifier) Exit64() (x.Proxy, error) {
	return px.ProxyFor(Rpn64)
}

// SE implements x.Rpn.
func (px *proxifier) SE() (x.Proxy, error) {
	sep, err := px.ProxyFor(RpnSE)
	if sep == nil {
		return nil, core.JoinErr(err, px.lastSeErr.Load())
	}
	return sep, err
}

// TestSE implements x.Rpn.
func (px *proxifier) TestSE() (string, error) {
	sec := px.sec
	if sec == nil {
		return "", px.lastSeErr.Load()
	}

	const maxpings = 5
	oks := make([]string, 0, maxpings)
	for i, v := range shuffle(sec.Addrs()) {
		if i > maxpings {
			break
		}
		ippstr := v.String()
		// base can route back into netstack (settings.LoopingBack)
		// in which  case all endpoints will "seem" reachable.
		// exit, however, never routes back into netstack and has
		// the true, unhindered path to the underlying network.
		if Reaches(px.exit, ippstr, "tcp") {
			oks = append(oks, ippstr)
		}
	}

	if len(oks) <= 0 {
		return "", core.JoinErr(errNoSuitableAddress, px.lastSeErr.Load())
	}
	return strings.Join(oks, ","), nil
}

// TestWarp implements x.Rpn
func (px *proxifier) TestWarp() (string, error) {
	const totalpings = 5

	oks := make([]string, 0, totalpings*2)

	for i := 0; i < totalpings; i++ {
		v4, v6, err := warp.WarpEndpoints()
		if err != nil {
			log.W("proxy: warp: ping#%d: %v", i, err)
			continue
		}
		v4str := v4.String()
		v6str := v6.String()
		// base can route back into netstack (settings.LoopingBack)
		// in which  case all endpoints will "seem" reachable.
		// exit, however, never routes back into netstack and has
		// the true, unhindered path to the underlying network.
		if Reaches(px.exit, v4str, "udp") {
			oks = append(oks, v4str)
		}
		if Reaches(px.exit, v6str, "udp") {
			oks = append(oks, v6str)
		}
	}

	if len(oks) <= 0 {
		return "", core.JoinErr(errNoSuitableAddress, px.lastWarpErr.Load())
	}
	return strings.Join(oks, ","), nil
}

// TestProton implements x.Rpn.
func (px *proxifier) TestProton() (string, error) {
	v4, _, err := warp.ProtonEndpoints()
	if err != nil {
		log.W("proxy: proton: err testing endpoints: %v", err)
		return "", err
	}

	// todo: proton does not use ipv6 for api servers
	oks := make([]string, 0, len(v4))
	for _, ip := range v4 {
		ipstr := ip.String()
		// base can route back into netstack (settings.LoopingBack)
		// in which  case all endpoints will "seem" reachable.
		// exit, however, never routes back into netstack and has
		// the true, unhindered path to the underlying network.
		if Reaches(px.exit, ipstr, "tcp") {
			oks = append(oks, ipstr)
		}
	}

	if len(oks) <= 0 {
		return "", core.JoinErr(errNoSuitableAddress, px.lastProtonErr.Load())
	}
	return strings.Join(oks, ","), nil
}

// TestAmnezia implements x.Rpn.
func (px *proxifier) TestAmnezia() (ips string, errs error) {
	v4, _, err := warp.AmzEndpoints()
	if err != nil {
		log.W("proxy: amz: err testing endpoints: %v", err)
		return "", err
	}

	// todo: amnezia presently does not support ipv6
	oks := make([]string, 0, len(v4))
	for _, ip := range v4 {
		ipstr := ip.String()
		// base can route back into netstack (settings.LoopingBack)
		// in which  case all endpoints will "seem" reachable.
		// exit, however, never routes back into netstack and has
		// the true, unhindered path to the underlying network.
		if Reaches(px.exit, ipstr, "tcp") {
			oks = append(oks, ipstr)
		}
	}

	if len(oks) <= 0 {
		return "", core.JoinErr(errNoSuitableAddress, px.lastAmzErr.Load())
	}
	return strings.Join(oks, ","), nil
}

// TestExit64 implements x.Rpn.
func (px *proxifier) TestExit64() (ips string, errs error) {
	v6, err := warp.Exit64Endpoints()
	if err != nil {
		log.W("proxy: exit64: err testing endpoints %v", err)
		return "", err
	}

	oks := make([]string, 0, len(v6))
	for _, ip := range v6 {
		ipstr := ip.String()
		// base can route back into netstack (settings.LoopingBack)
		// in which  case all endpoints will "seem" reachable.
		// exit, however, never routes back into netstack and has
		// the true, unhindered path to the underlying network.
		if Reaches(px.exit, ipstr, "icmp") {
			oks = append(oks, ipstr)
		}
	}

	if len(oks) <= 0 {
		return "", errNoSuitableAddress
	}
	return strings.Join(oks, ","), nil
}

func isWG(id string) bool {
	return strings.Contains(id, WG)
}

// Base, Block, Exit, Rpn64, Ingress
func local(id string) bool {
	return id == Base || id == Block || id == Exit || id == Rpn64 || id == Ingress
}

func Remote(id string) bool {
	return !local(id)
}

func hopping(r x.Router) bool {
	hop, _ := r.Via()
	return hop != nil
}

func immutable(id string) bool {
	return local(id) || id == Auto
}

func isInternal(id string) bool {
	return isRPN(id) || immutable(id)
}

func isRPN(id string) bool {
	return strings.Contains(id, RPN)
}

func idling(t time.Time) bool {
	return time.Since(t) > tzzTimeout
}

func localDialStrat(d *protect.RDial, network, local, remote string) (protect.Conn, error) {
	return dialers.SplitDialBind(d, network, local, remote)
}

func firstEmpty(arr []string) bool {
	return len(arr) <= 0 || len(arr[0]) <= 0
}
