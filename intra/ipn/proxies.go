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
	"net"
	"net/netip"
	"strconv"
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

	NOMTU    = 0
	MAXMTU   = 65535
	AUTOMTU  = "auto"
	AUTOMTU2 = "(auto)"
)

var (
	errProxyScheme        = errors.New("proxy: unsupported scheme")
	errUnexpectedProxy    = errors.New("proxy: unexpected type")
	errAddProxy           = errors.New("proxy: add failed")
	errAddProxyAsRpn      = errors.New("proxy: cannot add rpn proxy")
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
	errNoAuto464XLAT      = errors.New("auto: no 464xlat")
	errNotPinned          = errors.New("auto: another proxy pinned")
	errInvalidAddr        = errors.New("proxy: invaild ip:port")
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
	errHopNotConnected    = errors.New("proxy: set but not connected over hop")
	errNilAmzId           = errors.New("proxy: amz id nil")
	errNilProtonCfg       = errors.New("proxy: proton cfg nil")
	errNilWarpId          = errors.New("proxy: warp id nil")
	errNilSEProxy         = errors.New("proxy: se proxy nil")
	errNotRpnProxy        = errors.New("proxy: rpn not found")
	errNotRpnID           = errors.New("proxy: not rpn id")
	errNotRpnAcc          = errors.New("proxy: not rpn account")
	errNotRemote          = errors.New("proxy: not a remote proxy")
)

const (
	udptimeoutsec         = 5 * 60                    // 5m
	tcptimeoutsec         = (2 * 60 * 60) + (40 * 60) // 2h40m
	getproxytimeout       = 5 * time.Second
	tlsHandshakeTimeout   = 30 * time.Second // some proxies take a long time to handshake
	responseHeaderTimeout = 60 * time.Second
	tzzTimeout            = 2 * time.Minute  // time between new connections before proxies transition to idle
	lastOKThreshold       = 10 * time.Minute // time between last OK and now before pinging & un-pinning
	pintimeout            = 10 * time.Minute // time to keep a pin
	alwaysPin             = true             // always pin to a proxy no matter the errors
	maxFailingPinTrackTTl = 30 * time.Second // max period to track a failing to-be-pinned proxy
	maxStallPeriodSec     = 10               // max duration to stall a failing proxy
)

// type checks
var _ Proxy = (*base)(nil)
var _ Proxy = (*exit)(nil)
var _ Proxy = (*exit64)(nil)
var _ Proxy = (*auto)(nil)
var _ Proxy = (*socks5)(nil)
var _ Proxy = (*http1)(nil)
var _ Proxy = (*wgproxy)(nil)
var _ Proxy = (*seproxy)(nil)
var _ Proxy = (*ground)(nil)
var _ Proxy = (*pipws)(nil)
var _ Proxy = (*piph2)(nil)

type Proxy interface {
	x.Proxy
	protect.RDialer

	// DialerHandle uniquely identifies the concrete type backing this proxy's dialer.
	// Useful as a phantom reference to this dialer.
	// github.com/hashicorp/terraform/blob/325d18262/internal/configs/configschema/decoder_spec.go#L32
	DialerHandle() uintptr
	// Handle uniquely identifies the concrete type backing this proxy.
	Handle() uintptr
	// Dialer returns the dialer for this proxy, which is an
	// adapter for protect.RDialer interface, but with the caveat that
	// not all Proxy instances implement DialTCP and DialUDP, though are
	// guaranteed to implement Dial.
	Dialer() protect.RDialer
	// onNotOK is called by clients when the proxy is not responsive.
	onNotOK() (refreshed, allok bool)
	// onProtoChange returns true if the proxy must be re-added with cfg on proto changes.
	OnProtoChange(lp LinkProps) (cfg string, readd bool)
	// Gateway sets proxy p as the gateway for this router.
	Hop(p Proxy, dryrun bool) error
}

type Rpn interface {
	x.Rpn
	rpnProxyProvider
	// addRpnProxy adds an RPN proxy to this multi-transport.
	addRpnProxy(acc RpnAcc, cc string) (Proxy, error)
	// removeRpnProxy removes an RPN proxy from this multi-transport.
	removeRpnProxy(acc RpnAcc, cc string) bool
}

type rpnProxyProvider interface {
	// mainRpnProxyFor returns the main (default) RPN proxy from this multi-transport.
	mainRpnProxyOf(provider string) (RpnProxy, error)
	// rpnProxyFor returns a country-specific RPN proxy from this multi-transport.
	rpnProxyFor(provider, cc string) (Proxy, error)
	// AutoActive returns true if any of the RPN proxies are in-use by ipn.Auto.
	AutoActive() bool
}

type ProxyProvider interface {
	rpnProxyProvider
	// ProxyFor returns a transport from this multi-transport.
	ProxyFor(id string) (Proxy, error)
	// ProxyTo returns the proxy to use for ipp from given pids.
	ProxyTo(ipp netip.AddrPort, uid string, pids []string) (Proxy, error)
}

type Proxies interface {
	x.Proxies
	ProxyProvider
	Rpn
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

	rpnmu sync.RWMutex        // protects rp
	rp    map[string]RpnProxy // rpn proxies

	hmu sync.RWMutex        // protects hp
	hp  map[string][]string // hopproxy => [proxyid]

	ctl protect.Controller // dial control provider
	obs x.ProxyListener    // proxy observer

	lp LinkProps // link properties; protected by mu

	staller *core.ExpMap[string, string] // uid+dst(domainOrIP) -> stallSecs

	ipPins  *core.Sieve[netip.AddrPort, string]           // ipp -> proxyid
	uidPins *core.Sieve2K[string, netip.AddrPort, string] // uid -> [dst -> proxyid]

	// immutable proxies
	exit     *exit   // exit proxy, never changes
	exit64   *exit64 // rpn64 proxy, never changes
	base     *base   // base proxy, never changes
	grounded *ground // grounded proxy, never changes
	auto     *auto   // auto proxy, never changes

	extc *warp.Client // external wg registration, never changes

	sec *seasy.SEApi // se proxy registration, never changes; may be nil

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
		ctx: pctx,
		p:   make(map[string]Proxy),
		ctl: c,
		obs: o,

		lp: LinkProps{l3: l3, mtu: mtu},

		hp: make(map[string][]string),

		rp:            make(map[string]RpnProxy),
		lastSeErr:     core.NewZeroVolatile[error](),
		lastWarpErr:   core.NewZeroVolatile[error](),
		lastAmzErr:    core.NewZeroVolatile[error](),
		lastProtonErr: core.NewZeroVolatile[error](),
	}

	pxr.exit = NewExitProxy(pctx, c)
	pxr.exit64 = NewExit64Proxy(pctx, c)
	pxr.base = NewBaseProxy(pctx, c, pxr)
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
	pxr.add(pxr.base)     // fixed
	pxr.add(pxr.grounded) // fixed
	pxr.add(pxr.auto)     // fixed

	if _, err := pxr.addRpnProxy2(pxr.exit64, pxr.exit64); err != nil { // fixed
		// TODO: lastExit64Err?
		log.W("proxy: rpn64: add: %v", err)
	}

	log.I("proxy: new")

	context.AfterFunc(pctx, pxr.stopProxies)

	return pxr
}

// add adds a proxy to the proxifier and invokes OnProxyAdded.
// It returns true if the proxy was added successfully.
// It stops old proxy if a new one with the same ID is added.
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
			if old != nil && !Same(old, p) {
				// holding px.lock, so exec stop in a goroutine
				core.Go("pxr.add.stop: "+id, func() {
					if oldVia, _ := old.Router().Via(); oldVia != nil {
						px.Hop(oldVia.ID(), p.ID())
					}
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
				// do not addRpnProxy from here
				// it will result in a loop of calls
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

	logeif(!ok)("proxy: add: proxy %s ok? %t", id, ok)
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
			px.unmapHopFrom(p, false /*dryrun*/)
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

	stalledSec := uint32(0)
	ippstr := ipp.String()

	if len(pids) == 1 { // there's no other pid to choose from
		// skip hasroute, as there is only one pid to route to
		p, err := px.pinID(uid, ipp, pids[0]) // repin
		if err != nil || p == nil {
			err = core.OneErr(err, errProxyNotFound)
			stalledSec = px.stall(uid + ippstr)
		}
		logev(err)("proxy: pin: %s+%s; pin pid0: %s (stalled? %ds); err? %v",
			uid, ippstr, pids[0], stalledSec, err)
		// alwaysPin is set to true, so wipe out err; return p, even if err is not nil
		if alwaysPin && p != nil {
			return p, nil
		}
		return nil, err
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
		logev(err)("proxy: pin: %s+%s; stalled? %ds; miss: %v; notok: %v; noroute: %v; ended %v",
			uid, ipp, stalledSec, missproxies, notokproxies, norouteproxies, endproxies)
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

		if noop(p.Type()) {
			loproxies = append(loproxies, pid)
			continue
		}

		if hasroute(p, ippstr) {
			err := px.pin(uid, ipp, p) // repin
			if err == nil {
				log.VV("proxy: pin: %s+%s; pinned: %s; from pids: %v",
					uid, ipp, pid, pids)
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
		stalledSec = px.stall(uid + ippstr)
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

	stalledSec = px.stall(uid + ippstr)
	return nil, errProxyAllDown
}

func (px *proxifier) stall(k string) (secs uint32) {
	if n := px.staller.Get(k); n <= 3 {
		secs = (rand.Uint32() % 3) + 1 // up to 3s
	} else {
		secs = n
	}
	px.staller.Set(k, maxFailingPinTrackTTl)           // track uid=>target for 30s
	if secs = min(maxStallPeriodSec, secs); secs > 0 { // max up to 10s
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
		err == nil, ipp, idstr(p), err)

	if err != nil {
		return fmt.Errorf("proxy: pin: %s; err: %v", idstr(p), err)
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
	p, completed := core.Grx("pxr.ProxyFor: "+id, func(_ context.Context) (Proxy, error) {
		px.RLock()
		defer px.RUnlock()

		return px.p[id], nil
	}, getproxytimeout)

	if !completed {
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

func (px *proxifier) AutoActive() bool {
	return settings.AutoActive()
}

func (px *proxifier) mainRpnProxyOf(provider string) (RpnProxy, error) {
	if !isRPN(provider) {
		return nil, errNotRpnID
	}
	px.rpnmu.RLock()
	rp := px.rp[provider]
	px.rpnmu.RUnlock()
	if rp == nil {
		return nil, errNotRpnProxy
	}
	return rp, nil
}

func (px *proxifier) rpnProxyFor(provider, cc string) (Proxy, error) {
	id := provider + cc
	p, err := px.ProxyFor(id)
	if p == nil {
		return nil, core.OneErr(err, errProxyNotFound)
	}
	return p, err
}

// GetProxy implements x.Proxies.
func (px *proxifier) GetProxy(id string) (x.Proxy, error) {
	return px.ProxyFor(id)
}

// TestHop implements Proxies.
func (px *proxifier) TestHop(via, origin string) string {
	defer core.Recover(core.Exit11, "pxr.TestHop."+via+">>"+origin)
	if err := px.hop(via, origin, true /*dryrun*/); err != nil {
		return err.Error()
	}
	return "" // all ok
}

// Hop implements Proxies.
func (px *proxifier) Hop(via, origin string) error {
	return px.hop(via, origin, false /*dryrun*/)
}

func (px *proxifier) hop(via, origin string, dryrun bool) error {
	defer core.Recover(core.Exit11, "pxr.Hop."+via+">>"+origin)

	if len(origin) <= 0 {
		return errMissingProxyID
	}
	origPx, err := px.ProxyFor(origin)
	if err != nil || origPx == nil {
		return core.OneErr(err, errProxyNotFound)
	}

	oldViaPx, _ := origPx.Router().Via() // may be nil

	if len(via) <= 0 { // remove hop if needed
		err = origPx.Hop(nil, dryrun)
		_ = px.unmapHop(oldViaPx, origPx, err != nil || dryrun)
		return err
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

	if idstr(oldViaPx) == idstr(viaPx) {
		if !dryrun {
			go origPx.Refresh()
		}
		log.I("proxy: hop: %s => %s (no change)", origin, via)
		return nil // no change
	}

	viaRouter := viaPx.Router()
	if viaViaVia, _ := viaRouter.Via(); viaViaVia != nil {
		log.W("proxy: triple hop: %s => %s => %s; not allowed", origin, via, viaViaVia.ID())
		return errHopHopping
	} else if !viaRouter.IP4() && !viaRouter.IP6() {
		// via must either route all ip4 or all ip6; ideally both
		return errHopDefaultRoutes
	}

	_ = px.unmapHop(oldViaPx, origPx, dryrun)
	err = origPx.Hop(viaPx, dryrun)
	_ = px.mapHop(viaPx, origPx, err != nil || dryrun)

	return err
}

func (px *proxifier) mapHop(hop x.Proxy, orig x.Proxy, dryrun bool) (mapped bool) {
	if dryrun {
		return
	}

	hopID := idstr(hop)
	origID := idstr(orig)
	if len(hopID) <= 0 || len(origID) <= 0 {
		return
	}

	px.hmu.Lock()
	defer px.hmu.Unlock()
	px.hp[hopID] = addElem(px.hp[hopID], origID)
	return true
}

func (px *proxifier) unmapHopFrom(orig x.Proxy, dryrun bool) (unmapped bool) {
	via, _ := orig.Router().Via() // may be nil
	return px.unmapHop(via, orig, dryrun)
}

func (px *proxifier) unmapHop(hop x.Proxy, orig x.Proxy, dryrun bool) (unmapped bool) {
	if dryrun {
		return
	}

	hopID := idstr(hop)
	origID := idstr(orig)
	if len(hopID) <= 0 || len(origID) <= 0 {
		return
	}

	px.hmu.Lock()
	defer px.hmu.Unlock()

	if in, ok := px.hp[hopID]; ok {
		out := removeElem(in, origID)
		px.hp[hopID] = out
		unmapped = len(out) < len(in)
	}
	return
}

func (px *proxifier) refreshHopOriginsIfAny(hop Proxy, why string) (n int) {
	hopID := idstr(hop)
	if len(hopID) <= 0 {
		return
	}

	px.hmu.RLock()
	origins := px.hp[hopID]
	px.hmu.RUnlock()

	if len(origins) <= 0 {
		log.D("proxy: refreshHopOrigins for %s: no-op", why)
		return
	}

	px.RLock()
	for _, origin := range origins {
		if p := px.p[origin]; p != nil {
			n++
			go p.Refresh()
		}
	}
	px.RUnlock()

	log.I("proxy: refreshHopOrigins for %s: %d[%v]", why, n, origins)
	return
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
	px.rpnmu.Lock()
	n := len(px.rp)
	for _, rp := range px.rp {
		x := rp
		id := x.ID()
		core.Go("pxr.stopProxies.purgeRpn: "+id, func() {
			_ = x.PurgeAll()
		})
	}
	clear(px.rp)
	px.rpnmu.Unlock()

	px.hmu.Lock()
	clear(px.hp)
	px.hmu.Unlock()

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

	core.Go("pxr.onStop", func() { px.obs.OnProxiesStopped() })
	log.I("proxy: stopped and removed %d+%d", n, l)
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
				// TODO: preserve hop?
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
		if local(p.ID()) || noop(p.Type()) {
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
		if local(p.ID()) || noop(p.Type()) {
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
		if local(p.ID()) || noop(p.Type()) {
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
		pid := p.ID()
		ptyp := p.Type()
		if local(pid) || isInternal(pid) || noop(ptyp) {
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
		if local(p.ID()) || noop(p.Type()) {
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
	defer func() {
		px.lastWarpErr.Store(err) // may be nil
	}()
	restore := len(existingStateJson) > 0

	wc, err := px.registerWarp(existingStateJson)
	if err != nil || core.IsNil(wc) {
		return nil, core.JoinErr(err, errNilWarpId)
	}
	state, err := wc.State()
	if err != nil {
		return nil, err
	}

	rp, err := px.addRpnProxy(wc, mainCountryCode)
	if err != nil || rp == nil {
		log.E("proxy: warp: add wg for %s failed: %v", wc.Who(), err)
		return nil, core.JoinErr(err, errNotRpnProxy)
	}

	log.I("proxy: warp: registered: %s / %d, new? %t", wc.Who(), len(state), !restore)
	return state, nil
}

func (px *proxifier) registerWarp(existingStateJson []byte) (wc RpnAcc, err error) {
	if len(existingStateJson) > 0 {
		return px.extc.MakeWarpFrom(existingStateJson)
	} else {
		return px.extc.MakeWarp()
	}
}

// RegisterAmnezia implements x.Rpn.
func (px *proxifier) RegisterAmnezia(existingStateJson []byte) (stateJson []byte, err error) {
	defer func() {
		px.lastAmzErr.Store(err) // may be nil
	}()
	restore := len(existingStateJson) > 0

	ac, err := px.registerAmnezia(existingStateJson)

	if err != nil || core.IsNil(ac) {
		log.E("proxy: amz: make (restore? %t) failed: %v", restore, err)
		return nil, core.JoinErr(err, errNilAmzId)
	}

	state, err := ac.State()
	if err != nil {
		return nil, err
	}

	rp, err := px.addRpnProxy(ac, mainCountryCode)
	if err != nil || rp == nil {
		log.E("proxy: amz: add wg for %s failed: %v", ac.Who(), err)
		return nil, core.JoinErr(err, errNotRpnProxy)
	}

	log.I("proxy: amz: registered: %s / %d; new? %t", ac.Who(), len(state), !restore)
	return state, nil
}

func (px *proxifier) registerAmnezia(existingStateJson []byte) (RpnAcc, error) {
	if len(existingStateJson) > 0 { // restore
		return px.extc.MakeAmzWgFrom(existingStateJson)
	} else {
		return px.extc.MakeAmzWg()
	}
}

// RegisterProton implements x.Rpn.
func (px *proxifier) RegisterProton(existingStateJson []byte) (stateJson []byte, err error) {
	defer func() {
		px.lastProtonErr.Store(err) // may be nil
	}()
	restore := len(existingStateJson) > 0

	pro, err := px.registerProton(existingStateJson)
	if err != nil || core.IsNil(pro) {
		log.E("proxy: proton: make failed: %v", err)
		return nil, core.JoinErr(err, errNilProtonCfg)
	}

	state, err := pro.State()
	if err != nil {
		// TODO: RpnAcc may be stateless, in which case err is expected & could be ignored
		return nil, err
	}

	rp, err := px.addRpnProxy(pro, mainCountryCode)
	if err != nil || rp == nil {
		log.E("proxy: proton: add wg for %s failed: %v", pro.Who(), err)
		return nil, core.JoinErr(err, errNotRpnProxy)
	}

	log.I("proxy: proton: registered: %s / %d; new? %t", pro.Who(), len(state), !restore)
	return state, nil
}

func (px *proxifier) registerProton(existingStateJson []byte) (RpnAcc, error) {
	const nostore = ""
	if len(existingStateJson) > 0 {
		return px.extc.MakeProtonWgFrom(existingStateJson, nostore)
	} else {
		return px.extc.MakeProtonWg(nostore)
	}
}

// RegisterSE implements x.Rpn.
func (px *proxifier) RegisterSE() (err error) {
	defer func() {
		px.lastSeErr.Store(err) // err may be nil, which unsets lastSeErr
	}()

	sec := px.sec
	if sec == nil {
		return core.JoinErr(errMissingSEClient, px.lastSeErr.Load())
	}

	sep, err := NewSEasyProxy(px.ctx, px.ctl, px, sec)

	if err != nil || sep == nil {
		log.E("proxy: se: make failed: %v", err)
		return core.JoinErr(err, errNilSEProxy)
	}

	if p, err := px.addRpnProxy2(sep, sep); p == nil || err != nil { // unlikely
		return core.JoinErr(err, errAddProxy)
	}

	log.I("proxy: se: registered: %s", sep.Who())
	return nil
}

// RegisterExit implements x.Rpn.
func (px *proxifier) UnregisterWarp() bool {
	return px.unregisterRpn(RpnWg)
}

// UnregisterAmnezia implements x.Rpn.
func (px *proxifier) UnregisterAmnezia() bool {
	return px.unregisterRpn(RpnAmz)
}

// UnregisterProton implements x.Rpn.
func (px *proxifier) UnregisterProton() bool {
	return px.unregisterRpn(RpnPro)
}

// UnregisterSE implements x.Rpn.
func (px *proxifier) UnregisterSE() bool {
	return px.unregisterRpn(RpnSE)
}

func (px *proxifier) unregisterRpn(provider string) bool {
	rp, _ := px.mainRpnProxyOf(provider)
	if rp == nil {
		return false
	}

	n := rp.PurgeAll() // n == 1 for single country rpn

	px.rpnmu.Lock()
	delete(px.rp, provider)
	px.rpnmu.Unlock()

	log.I("proxy: %s: unregistered; forks: %d", provider, n)
	return true
}

// Warp implements x.Rpn.
func (px *proxifier) Warp() (x.RpnProxy, error) {
	rp, err := px.mainRpnProxyOf(RpnWg)
	if rp == nil {
		return nil, core.JoinErr(err, px.lastWarpErr.Load())
	}
	return rp, nil
}

// Proton implements x.Rpn.
func (px *proxifier) Proton() (x.RpnProxy, error) {
	pro, err := px.mainRpnProxyOf(RpnPro)
	if pro == nil {
		return nil, core.JoinErr(err, px.lastProtonErr.Load())
	}
	return pro, nil
}

// Amnezia implements x.Rpn.
func (px *proxifier) Amnezia() (x.RpnProxy, error) {
	amz, err := px.mainRpnProxyOf(RpnAmz)
	if amz == nil {
		return nil, core.JoinErr(err, px.lastAmzErr.Load())
	}
	return amz, nil
}

// Pip implements x.Rpn.
func (px *proxifier) Pip() (x.RpnProxy, error) {
	// TODO: Register and Unregister for Pip
	// TODO: Pip asRpnProxy (with multi-country support)
	return px.mainRpnProxyOf(RpnWs)
}

// Exit64 implements x.Rpn.
func (px *proxifier) Exit64() (x.RpnProxy, error) {
	return px.mainRpnProxyOf(Rpn64)
}

// SE implements x.Rpn.
func (px *proxifier) SE() (x.RpnProxy, error) {
	sep, err := px.mainRpnProxyOf(RpnSE)
	if sep == nil {
		return nil, core.JoinErr(err, px.lastSeErr.Load())
	}
	return sep, err
}

// TestSE implements x.Rpn.
func (px *proxifier) TestSE() (string, error) {
	sec := px.sec
	if sec == nil {
		return "", core.OneErr(px.lastSeErr.Load(), errNilSEProxy)
	}

	const maxpings = 5
	oks := make([]string, 0, maxpings)
	notoks := make([]string, 0, maxpings)
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
		} else {
			notoks = append(notoks, ippstr)
		}
	}

	if len(oks) <= 0 {
		log.E("proxy: se: no reachable addrs among %v", notoks)
		return "", core.JoinErr(errNoSuitableAddress, px.lastSeErr.Load())
	}
	return strings.Join(oks, ","), nil
}

// TestWarp implements x.Rpn
func (px *proxifier) TestWarp() (string, error) {
	const totalpings = 5

	oks := make([]string, 0, totalpings*2)
	notoks := make([]string, 0, totalpings)

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
		} else {
			notoks = append(notoks, v4str)
		}
		if Reaches(px.exit, v6str, "udp") {
			oks = append(oks, v6str)
		} else {
			notoks = append(notoks, v6str)
		}
	}

	if len(oks) <= 0 {
		log.E("proxy: warp: no reachable addrs among %v", notoks)
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
		log.E("proxy: proton: no reachable addrs among %v", v4)
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
		log.E("proxy: amz: no reachable addrs among %v", v4)
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
		log.E("proxy: exit64: no reachable addrs among %v", v6)
		return "", errNoSuitableAddress
	}
	return strings.Join(oks, ","), nil
}

func isWG(id string) bool {
	return strings.Contains(id, WG)
}

func IsAnyLocalProxy(ids ...string) bool {
	for _, id := range ids {
		if local(id) {
			return true
		}
	}
	return false
}

// Base, Block, Exit, Rpn64, Ingress
func local(id string) bool {
	return id == Base || id == Block || id == Exit || id == Rpn64 || id == Ingress
}

func noop(typ string) bool {
	return typ == NOOP
}

// TODO: check for hops on "noop" transports; if those
// are NOT hoppping, then those are NOT remote, either
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

func dialAny(all []protect.RDialer, network, local, remote string) (protect.Conn, error) {
	return dialers.DialAny(all, str2addr(network, local), str2addr(network, remote))
}

func str2addr(network, addrport string) net.Addr {
	ip, port, err := net.SplitHostPort(addrport)
	if err != nil {
		return nil
	}
	portno, err := strconv.Atoi(port)
	if err != nil {
		return nil
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
		return &net.TCPAddr{
			IP:   net.ParseIP(ip),
			Port: portno,
		}
	case "udp", "udp4", "udp6":
		fallthrough
	default:
		return &net.UDPAddr{
			IP:   net.ParseIP(ip),
			Port: portno,
		}
	}
}

func firstEmpty(arr []string) bool {
	return len(arr) <= 0 || len(arr[0]) <= 0
}
