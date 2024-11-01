// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"context"
	"errors"
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
	"github.com/celzero/firestack/intra/settings"
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
	errProxyScheme       = errors.New("proxy: unsupported scheme")
	errUnexpectedProxy   = errors.New("proxy: unexpected type")
	errAddProxy          = errors.New("proxy: add failed")
	errProxyNotFound     = errors.New("proxy: not found")
	errGetProxyTimeout   = errors.New("proxy: get timeout")
	errProxyAllDown      = errors.New("proxy: all down")
	errNoProxyHealthy    = errors.New("proxy: no chosen healthy")
	errMissingProxyOpt   = errors.New("proxy: opts nil")
	errNoProxyConn       = errors.New("proxy: not a tcp/udp conn")
	errNotUDPConn        = errors.New("proxy: not a udp conn")
	errProxyStopped      = errors.New("proxy: stopped")
	errProxyConfig       = errors.New("proxy: invalid config")
	errNoProxyResponse   = errors.New("proxy: no response from upstream")
	errNoSig             = errors.New("proxy: auth missing sig")
	errNoMtu             = errors.New("proxy: missing mtu")
	errNoOpts            = errors.New("proxy: no opts")
	errMissingRev        = errors.New("proxy: missing reverse proxy")
	errNoAuto464XLAT     = errors.New("auto: no 464xlat")
	errNotPinned         = errors.New("auto: another proxy pinned")
	errInvalidAddr       = errors.New("proxy: invaild ip:port")
	errUnreachable       = errors.New("proxy: destination unreachable")
	errNoRouteToHost     = errors.New("proxy: no route to host")
	errMissingProxyID    = errors.New("proxy: missing proxy id")
	errHopRoutesMismatch = errors.New("proxy: hop routes mismatch")
	errNoHop             = errors.New("proxy: no hop")
	errHopWireGuard      = errors.New("proxy: hop must be wireguard")
	errHopGlobalProxy    = errors.New("proxy: hop must be global proxy")
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
	OnProtoChange() (cfg string, readd bool)
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
	RefreshProto(l3 string)
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

	ctl protect.Controller    // dial control provider
	rev netstack.GConnHandler // may be nil
	obs x.ProxyListener       // proxy observer

	ipPins  *core.Sieve[netip.AddrPort, string]           // ipp -> proxyid
	uidPins *core.Sieve2K[string, netip.AddrPort, string] // uid -> [dst -> proxyid]

	// immutable proxies
	exit     *exit   // exit proxy, never changes
	exit64   *exit64 // rpn64 proxy, never changes
	base     *base   // base proxy, never changes
	grounded *ground // grounded proxy, never changes
	auto     *auto   // auto proxy, never changes

	warpc *warp.Client // warp registration, never changes
	sec   *seasy.SEApi // se proxy registration, never changes; may be nil

	lastSeErr   error // se proxy registration error
	lastWarpErr error // warp registration error

	protos string // ip4, ip6, ip46
}

var _ Proxies = (*proxifier)(nil)
var _ x.Rpn = (*proxifier)(nil)
var _ x.Router = (*proxifier)(nil)
var _ protect.RDialer = (Proxy)(nil)
var _ Proxy = (*NoProxy)(nil)
var _ x.Router = (*NoProxy)(nil)

// NewProxifier returns a new Proxifier instance.
func NewProxifier(pctx context.Context, c protect.Controller, o x.ProxyListener) *proxifier {
	if c == nil || o == nil {
		return nil
	}

	pxr := &proxifier{
		ctx:    pctx,
		p:      make(map[string]Proxy),
		ctl:    c,
		obs:    o,
		protos: settings.IP46, // assume all routes ok (fail open)
	}

	pxr.exit = NewExitProxy(pctx, c)
	pxr.exit64 = NewExit64Proxy(pctx, c)
	pxr.base = NewBaseProxy(pctx, c)
	pxr.grounded = NewGroundProxy()
	pxr.auto = NewAutoProxy(pctx, pxr)
	pxr.ipPins = core.NewSieve[netip.AddrPort, string](pctx, pintimeout)
	pxr.uidPins = core.NewSieve2K[string, netip.AddrPort, string](pctx, pintimeout)

	pxr.warpc = warp.NewWarpClient(pctx, c)
	pxr.sec, pxr.lastSeErr = seasy.NewSEasyClient(pxr.exit)
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
	id := p.ID()

	px.Lock()
	defer px.Unlock()

	defer func() {
		if ok {
			core.Go("pxr.add: "+id, func() { px.obs.OnProxyAdded(id) })
		}
	}()

	if pp := px.p[id]; pp != nil {
		// new proxy, invoke Stop on old proxy
		if pp != p {
			core.Go("pxr.add: "+id, func() { // holding px.lock, so exec stop in a goroutine
				_ = pp.Stop()
				// onRmv is not sent here, as new proxy will be added
			})
		}
	}

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

	log.D("proxy: add: proxy %s ok? %t", id, ok)
	return ok
}

func (px *proxifier) RemoveProxy(id string) bool {
	px.Lock()
	defer px.Unlock()

	if p, ok := px.p[id]; ok {
		delete(px.p, id)
		core.Go("pxr.removeProxy: "+id, func() {
			_ = p.Stop()
			px.obs.OnProxyRemoved(id)
		})
		log.I("proxy: removed %s", id)
		return true
	}
	return false
}

// ProxyTo implements Proxies.
// May return both a Proxy and an error, in which case, the error
// denotes that while the Proxy is not healthy, it is still registered.
func (px *proxifier) ProxyTo(ipp netip.AddrPort, uid string, pids []string) (Proxy, error) {
	if len(pids) <= 0 || firstEmpty(pids) {
		return nil, errMissingProxyID
	}
	if !ipp.IsValid() {
		return nil, errMissingAddress
	}
	if len(pids) == 1 { // there's no other pid to choose from
		return px.pinID(uid, ipp, pids[0])
	}

	var lopinned string

	pinnedpid, pinok := px.getpin(uid, ipp)
	chosen := has(pids, pinnedpid)
	lo := local(pinnedpid)

	log.VV("proxy: pin: %s+%s; pinned: %s; chosen? %t / local? %t; from pids: %v",
		uid, ipp, pinnedpid, chosen, lo, pids)

	if pinok && chosen && lo {
		// always favour remote proxy pins over local, if any
		lopinned = pinnedpid
	} else if pinok && chosen {
		p, err := px.pinID(uid, ipp, pinnedpid)
		if err == nil {
			return p, nil
		} // else: fallthrough
	} else if pinok && !chosen {
		px.delpin(uid, ipp)
	}

	ippstr := ipp.String()
	notokproxies := make([]string, 0)
	endproxies := make([]string, 0)
	norouteproxies := make([]string, 0)
	missproxies := make([]string, 0)
	loproxies := make([]string, 0)
	if len(lopinned) > 0 { // lopinned may be empty
		loproxies = append(loproxies, lopinned)
	}

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
			err := px.pin(uid, ipp, p)
			if err == nil {
				log.VV("proxy: pin: %s+%s; pinned: %s; from pids: %v", uid, ipp, pid, pids)
				return p, nil
			} // else: proxy not ok
			notokproxies = append(notokproxies, pid)
		} // else: proxy cannot route; split-tunnel
		norouteproxies = append(norouteproxies, pid)
	}

	// can route but not healthy; drop
	if len(notokproxies) > 0 {
		return nil, errNoProxyHealthy
	}

	// lopinned is always the first element, if any.
	for _, pid := range loproxies {
		// ignore err, as it unlikely for local proxies
		// that are always available, and are presumed to
		// be gateways (route all ips)
		if p, _ := px.pinID(uid, ipp, pid); p != nil {
			return p, nil
		}
		missproxies = append(missproxies, pid)
	}

	log.VV("proxy: pin: %s+%s; miss: %v; notok: %v; noroute: %v; ended %v",
		uid, ipp, missproxies, notokproxies, norouteproxies, endproxies)
	return nil, errProxyAllDown
}

func (px *proxifier) pinID(uid string, ipp netip.AddrPort, id string) (Proxy, error) {
	p, err := px.ProxyFor(id)
	if err != nil {
		return nil, err
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
	return err
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
func (px *proxifier) ProxyFor(id string) (Proxy, error) {
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
		return nil, errProxyNotFound
	}
	return p, nil
}

// GetProxy implements x.Proxies.
func (px *proxifier) GetProxy(id string) (x.Proxy, error) {
	return px.ProxyFor(id)
}

func (px *proxifier) Hop(via, origin string) error {
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

	viaPx, err := px.ProxyFor(via)
	if err != nil || viaPx == nil {
		return core.OneErr(err, errProxyNotFound)
	}
	if viaPx.Status() == END || origPx.Status() == END {
		return errProxyStopped
	}
	if viaPx.Router().IP4() != origPx.Router().IP4() ||
		viaPx.Router().IP6() != origPx.Router().IP6() {
		return errHopRoutesMismatch
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
	px.ipPins.Clear()
	px.uidPins.Clear()

	core.Go("pxr.onStop", func() { px.obs.OnProxiesStopped() })
	log.I("proxy: all(%d) stopped and removed", l)
}

// RefreshProxies implements x.Proxies.
func (px *proxifier) RefreshProxies() (string, error) {
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
func (px *proxifier) RefreshProto(l3 string) {
	defer core.Recover(core.Exit11, "pxr.RefreshProto")
	// must unlock from deferred since panics are recovered above
	px.Lock()
	defer px.Unlock()

	if px.protos == l3 {
		log.D("proxy: refreshProto (%s) unchanged", l3)
		return
	}

	px.protos = l3
	for _, p := range px.p {
		curp := p
		id := curp.ID()
		core.Gx("pxr.RefreshProto: "+id, func() {
			// always run in a goroutine (or there is a deadlock)
			// wgproxy.onProtoChange -> multihost.Refresh -> dialers.Resolve
			// -> ipmapper.LookupIPNet -> resolver.LocalLookup -> transport.Query
			// -> ipn.ProxyFor -> px.Lock() -> deadlock
			if cfg, readd := curp.OnProtoChange(); readd {
				// px.addProxy -> px.add -> px.Lock() -> deadlock
				_, err := px.addProxy(id, cfg)
				log.I("proxy: refreshProto (%s/%s/%s) re-add; err? %v", id, curp.Type(), curp.GetAddr(), err)
			}
		})
	}
}

func (px *proxifier) Reverser(rhdl netstack.GConnHandler) error {
	px.Lock()
	defer px.Unlock()

	px.rev = rhdl
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
	safemtu := minmtu6
	for _, p := range px.p {
		if local(p.ID()) {
			continue
		}
		var r x.Router
		if r = p.Router(); r == nil {
			continue
		}
		if m, err1 := r.MTU(); err1 == nil {
			if p.Type() == WG {
				m = calcNetMtu(m)
			}
			out = min(out, max(m, safemtu))
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
func (px *proxifier) RegisterWarp(pub string) ([]byte, error) {
	id, err := px.warpc.Make(pub, "")
	px.lastWarpErr = err // may be nil
	if err != nil {
		log.E("proxy: warp: make for %s failed: %v", pub, err)
		return nil, err
	}
	// create a byte writer and write the identity to it

	return id.Json()
}

// RegisterSE implements x.Rpn.
func (px *proxifier) RegisterSE() error {
	sec := px.sec
	if sec == nil {
		return errors.Join(errMissingSEClient, px.lastSeErr)
	}

	sep, err := NewSEasyProxy(px.ctx, px.ctl, sec)
	px.lastSeErr = err // err may be nil, which unsets lastSeErr

	if err != nil {
		log.E("proxy: se: make failed: %v", err)
		return err
	} else if !px.add(sep) { // unlikely
		return errAddProxy
	}
	return nil
}

// Warp implements x.Rpn.
func (px *proxifier) Warp() (x.Proxy, error) {
	warp, err := px.ProxyFor(RpnWg)
	if warp == nil {
		return nil, errors.Join(err, px.lastWarpErr)
	}
	return warp, err
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
	sep, err := px.ProxyFor(RpnWg)
	if sep == nil {
		return nil, errors.Join(err, px.lastSeErr)
	}
	return sep, err
}

func (px *proxifier) TestSE() (string, error) {
	sec := px.sec
	if sec == nil {
		return "", px.lastSeErr
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
		return "", errors.Join(errNoSuitableAddress, px.lastSeErr)
	}
	return strings.Join(oks, ","), nil
}

func (px *proxifier) TestWarp() (string, error) {
	const totalpings = 5

	oks := make([]string, 0, totalpings*2)

	for i := 0; i < totalpings; i++ {
		v4, v6, err := warp.Endpoints()
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
		return "", errors.Join(errNoSuitableAddress, px.lastWarpErr)
	}
	return strings.Join(oks, ","), nil
}

func isRPN(id string) bool {
	return strings.Contains(id, RPN)
}

func isWG(id string) bool {
	return strings.Contains(id, WG)
}

// Base, Block, Exit, Rpn64, Ingress
func local(id string) bool {
	return id == Base || id == Block || id == Exit || id == Rpn64 || id == Ingress
}

func immutable(id string) bool {
	return local(id) || id == Auto
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
