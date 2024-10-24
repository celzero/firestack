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
	"math/rand/v2"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/ipn/warp"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/netstack"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
)

const (
	Block   = x.Block
	Base    = x.Base
	Exit    = x.Exit
	Auto    = x.Auto
	Ingress = x.Ingress // dummy
	OrbotS5 = x.OrbotS5
	OrbotH1 = x.OrbotH1
	RpnWg   = x.RpnWg
	RpnWs   = x.RpnWs
	Rpn64   = x.Rpn64
	RpnH2   = x.RpnH2

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

	// DNS addrs, urls, or stamps
	nodns = "" // no DNS

	NOMTU  = 0
	MAXMTU = 65535
)

var (
	errProxyScheme          = errors.New("proxy: unsupported scheme")
	errUnexpectedProxy      = errors.New("proxy: unexpected type")
	errAddProxy             = errors.New("proxy: add failed")
	errProxyNotFound        = errors.New("proxy: not found")
	errGetProxyTimeout      = errors.New("proxy: gettimeout")
	errMissingProxyOpt      = errors.New("proxy: opts nil")
	errNoProxyConn          = errors.New("proxy: not a tcp/udp conn")
	errNotUDPConn           = errors.New("proxy: not a udp conn")
	errAnnounceNotSupported = errors.New("proxy: announce not supported")
	errProbeNotSupported    = errors.New("proxy: probe not supported")
	errProxyStopped         = errors.New("proxy: stopped")
	errProxyConfig          = errors.New("proxy: invalid config")
	errNoProxyResponse      = errors.New("proxy: no response from upstream")
	errNoSig                = errors.New("proxy: auth missing sig")
	errNoMtu                = errors.New("proxy: missing mtu")
	errNoOpts               = errors.New("proxy: no opts")
	errMissingRev           = errors.New("proxy: missing reverse proxy")
	errNoAuto464XLAT        = errors.New("auto: no 464xlat")
	errNotPinned            = errors.New("auto: another proxy pinned")
	errInvalidAddr          = errors.New("proxy: invaild ip:port")
	errUnreachable          = errors.New("proxy: destination unreachable")
	errMissingFlowID        = errors.New("proxy: missing flow id")
)

const (
	udptimeoutsec         int           = 5 * 60                    // 5m
	tcptimeoutsec         int           = (2 * 60 * 60) + (40 * 60) // 2h40m
	getproxytimeout       time.Duration = 5 * time.Second
	tlsHandshakeTimeout   time.Duration = 30 * time.Second // some proxies take a long time to handshake
	responseHeaderTimeout time.Duration = 60 * time.Second
	tzzTimeout            time.Duration = 2 * time.Minute  // time between new connections before proxies transition to idle
	lastOKThreshold       time.Duration = 10 * time.Minute // time between last OK and now before pinging & un-pinning
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
	// Dial(network, addr string) (protect.Conn, error)
	// Announce(network, local string) (protect.PacketConn, error)
	// Accept(network, local string) (protect.Listener, error)
	protect.RDialer

	// Dialer returns the dialer for this proxy, which is an
	// adapter for protect.RDialer interface, but with the caveat that
	// not all Proxy instances implement DialTCP and DialUDP, though are
	// guaranteed to implement Dial.
	Dialer() protect.RDialer
	// onProtoChange returns true if the proxy must be re-added with cfg on proto changes.
	onProtoChange() (cfg string, readd bool)
}

type Proxies interface {
	x.Proxies
	// Get returns a transport from this multi-transport.
	ProxyFor(id string) (Proxy, error)
	// PinOne pins a proxy to one from the list of pids.
	PinOne(fid string, pids []string) (string, error)
	// RefreshProto broadcasts proto change to all active proxies.
	RefreshProto(l3 string)
	// LiveProxies returns a csv of active proxies.
	LiveProxies() string
	// Reverser sets the reverse proxy for all proxies.
	Reverser(r netstack.GConnHandler) error
}

type proxifier struct {
	sync.RWMutex
	p map[string]Proxy

	ctl protect.Controller    // dial control provider
	rev netstack.GConnHandler // may be nil
	obs x.ProxyListener       // proxy observer

	pinned *core.Sieve[string, string] // flowid -> proxyid

	// immutable proxies
	exit     *exit   // exit proxy, never changes
	base     *base   // base proxy, never changes
	grounded *ground // grounded proxy, never changes
	auto     *auto   // auto proxy, never changes

	warpc  *warp.Client // warp registration, never changes
	protos string       // ip4, ip6, ip46
}

var _ Proxies = (*proxifier)(nil)
var _ x.Rpn = (*proxifier)(nil)
var _ x.Router = (*proxifier)(nil)
var _ x.Router = (*gw)(nil)
var _ protect.RDialer = (Proxy)(nil)

func NewProxifier(pctx context.Context, c protect.Controller, o x.ProxyListener) *proxifier {
	if c == nil || o == nil {
		return nil
	}

	pxr := &proxifier{
		p:      make(map[string]Proxy),
		ctl:    c,
		obs:    o,
		protos: settings.IP46, // assume all routes ok (fail open)
	}

	pxr.exit = NewExitProxy(c)
	pxr.base = NewBaseProxy(c)
	pxr.grounded = NewGroundProxy()
	pxr.auto = NewAutoProxy(pctx, pxr)
	pxr.pinned = core.NewSieve[string, string](pctx, 10*time.Minute)

	pxr.warpc = warp.NewWarpClient(pctx, c)
	pxr.add(pxr.exit)     // fixed
	pxr.add(pxr.base)     // fixed
	pxr.add(pxr.grounded) // fixed
	pxr.add(pxr.auto)
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

func (px *proxifier) PinOne(fid string, pids []string) (string, error) {
	if len(pids) <= 0 {
		return "", errNotPinned
	} else if len(fid) <= 0 {
		return "", errMissingFlowID
	} else if len(pids) == 1 {
		pid := pids[0]
		// ok is called to make sure the proxy is ready-to-go
		// ignore err as there's no other pid to choose from
		_ = px.ok(pid)
		px.pinned.Put(fid, pid)
		return pids[0], nil
	}

	all := make(map[string]struct{}, len(pids))
	for _, pid := range pids {
		all[pid] = struct{}{}
	}

	if pid, pinok := px.pinned.Get(fid); pinok {
		_, chosen := all[pid]

		if !chosen {
			px.pinned.Del(fid)
			log.D("proxy: pin: unpinned %s from %s; not in %v", fid, pid, pids)
			goto pinNew
		}

		delete(all, pid) // mark visited
		err := px.ok(pid)

		loged(err)("proxy: pin: %s from %s; err? %v", fid, pid, err)
		if err == nil {
			return pid, nil
		} // else: fallthrough to pinNew
	}

pinNew:
	notok := make([]string, 0)
	for pid := range all {
		if err := px.ok(pid); err != nil {
			notok = append(notok, pid)
			continue
		}
		px.pinned.Put(fid, pid)
		log.I("proxy: pin: pinned %s to %s; discarded: %v", fid, pid, notok)
		return pid, nil
	}

	randpid := pids[rand.IntN(len(all))]
	log.W("proxy: pin: %s to random %s; all not ok: %v", fid, randpid, notok)
	return randpid, nil
}

func (px *proxifier) ok(pid string) error {
	if local(pid) { // fast path for local proxies which are always ok
		return nil
	}

	p, err := px.ProxyFor(pid)
	if err != nil {
		return err
	}

	if r := p.Router(); r != nil {
		now := now()
		lastOK := r.Stat().LastOK
		lastOKNeverOK := lastOK <= 0
		lastOKBeyondThres := now-lastOK > lastOKThreshold.Milliseconds()
		if lastOKNeverOK || lastOKBeyondThres {
			p.Ping()
			return fmt.Errorf("proxy: %s not ok; lastOK: zz? %t / thres? %t",
				pid, lastOKNeverOK, lastOKBeyondThres)
		} else if now-lastOK > tzzTimeout.Milliseconds() {
			p.Ping()
		}
	}
	if p.Status() == END {
		return errProxyStopped
	} // TODO: err on TNT, TKO?

	return nil // ok
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
		} // Ingress & Exit64 do not have a fast path
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

func (px *proxifier) Router() x.Router {
	return px
}

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

	core.Go("pxr.onStop", func() { px.obs.OnProxiesStopped() })
	log.I("proxy: all(%d) stopped and removed", l)
}

func (px *proxifier) RefreshProxies() (string, error) {
	px.Lock()
	defer px.Unlock()

	ptot := px.pinned.Clear()

	tot := len(px.p)
	log.I("proxy: refresh pxs: %d / remove pins: %d", tot, ptot)

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

func (px *proxifier) LiveProxies() string {
	px.RLock()
	defer px.RUnlock()

	out := make([]string, 0, len(px.p))
	for id := range px.p {
		out = append(out, id)
	}
	return strings.Join(out, ",")
}

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
			if cfg, readd := curp.onProtoChange(); readd {
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

// Implements Router.
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

// Implements Router.
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

// Implements Router.
func (px *proxifier) Stat() *x.RouterStats {
	px.RLock()
	defer px.RUnlock()

	var s *x.RouterStats
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

// Implements Router.
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

// Implements x.Rpn.
func (px *proxifier) RegisterWarp(pub string) ([]byte, error) {
	id, err := px.warpc.Make(pub, "")
	if err != nil {
		log.E("proxy: warp: make for %s failed: %v", pub, err)
		return nil, err
	}
	// create a byte writer and write the identity to it

	return id.Json()
}

// Warp Implements x.Rpn.
func (px *proxifier) Warp() (x.Proxy, error) {
	return px.ProxyFor(RpnWg)
}

// Pip Implements x.Rpn.
func (px *proxifier) Pip() (x.Proxy, error) {
	return px.ProxyFor(RpnWs)
}

// Exit Implements x.Rpn.
func (px *proxifier) Exit() (x.Proxy, error) {
	return px.ProxyFor(Exit)
}

// Exit64 Implements x.Rpn.
func (px *proxifier) Exit64() (x.Proxy, error) {
	return px.ProxyFor(Rpn64)
}

func (px *proxifier) TestWarp() (string, error) {
	const totalpings = 5
	pingch := make(chan netip.AddrPort, totalpings*2)
	// ips := make([]netip.AddrPort, 0)
	wg := sync.WaitGroup{}
	wg.Add(totalpings)

	for i := 0; i < totalpings; i++ {
		v4, v6, err := warp.Endpoints()
		if err != nil {
			log.W("proxy: warp: ping#%d: %v", i, err)
			continue
		}
		core.Go("pxr.testwarp", func() {
			defer wg.Done()

			var c4, c6 protect.Conn
			var err4, err6 error
			// base can route back into netstack (settings.LoopingBack)
			// in which  case all endpoints will "seem" reachable.
			// exit, however, never routes back into netstack and has
			// the true, unhindered path to the underlying network.
			c4, err4 = px.exit.Dial("udp", v4.String())
			c6, err6 = px.exit.Dial("udp", v6.String())
			defer core.CloseConn(c4, c6)

			// net.OpError => os.SyscallError => syscall.Errno
			if syserr := new(os.SyscallError); errors.As(err4, &syserr) {
				if syserr.Err == syscall.ECONNREFUSED {
					err4 = nil
				}
			}
			if syserr := new(os.SyscallError); errors.As(err6, &syserr) {
				if syserr.Err == syscall.ECONNREFUSED {
					err6 = nil
				}
			}
			if err4 == nil {
				pingch <- v4
			}
			if err6 == nil {
				pingch <- v6
			}
		})
	}

	core.Go("pxr.testwarp.closer", func() {
		defer close(pingch)
		wg.Wait()
	})

	addrs := make([]string, 0, totalpings)
	timeout := time.After(15 * time.Second)
	i := 0
	for ip := range pingch {
		log.I("proxy: warp: ping#%d: %s ok", i, ip)
		addrs = append(addrs, ip.String())
		if closed(timeout) {
			log.I("proxy: warp: ping#%d: timeout", i)
			break
		}
		i++
	}

	if len(addrs) <= 0 {
		return "", errNoSuitableAddress
	}
	return strings.Join(addrs, ","), nil
}

func isRPN(id string) bool {
	return strings.Contains(id, RPN)
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

func closed[T any](ch <-chan T) bool {
	select {
	case <-ch:
		return true
	default:
	}
	return false
}
