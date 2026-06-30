// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/ipn/rpn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
)

type RpnProxy interface {
	x.RpnProxy
	Proxy
	GetInternal(cc string) (Proxy, error)
	Emplace(Proxy) error
	PurgeAll() (n uint32)
}

type RpnAcc = rpn.RpnAcc

// and kick-off an update if the acc is expired?
type rpnp struct {
	mu sync.RWMutex // protects p, s, kids, & skids

	// parent proxy
	p Proxy
	// Rpn-specific accounting
	// TODO: unembed to type assert RpnAcc impl
	RpnAcc

	// rpn proxy manager
	pxr Rpn

	// forked child proxy IDs, may be empty (returned proxy IDs may have stopped)
	kids map[string]struct{}
	// server metadata for each forked kid (keyed by CC)
	skids map[string]*x.RpnServer
	// server metadata for the main proxy
	s *x.RpnServer
}

var _ RpnProxy = (*rpnp)(nil)
var _ RpnAcc = (*rpnp)(nil) // (useless) assertion always succeeds, see above
var _ Proxy = (*rpnp)(nil)  // (useless) assertion always succeeds, see above

var (
	errRpnMissing          = errors.New("proxy: rpn: missing")
	errRpnBadArgs          = errors.New("proxy: rpn: bad args")
	errRpnBadEmplace       = errors.New("proxy: rpn: emplace: bad args")
	errRpnBadCC            = errors.New("proxy: rpn: bad country code")
	errRpnIDsMismatch      = errors.New("proxy: rpn: provider x proxy mismatch")
	errRpnMainProxyMissing = errors.New("proxy: rpn: cannot fork; main proxy missing")
	errRpnMainProxyStopped = errors.New("proxy: rpn: cannot fork; main proxy stopped")
	errRpnNotForked        = errors.New("proxy: rpn: not forked")
)

// nb: client code isn't really expecting error from asRpnProxy.
func asRpnProxy(e Proxy, srv *x.RpnServer, acc RpnAcc, pxr Rpn) (RpnProxy, error) {
	if e == nil || acc == nil || pxr == nil {
		return nil, errRpnBadArgs
	}

	proxyid := idstr(e) // must be of form "provider-id + country-code"
	providerid := acc.ProviderID()
	if !strings.HasPrefix(proxyid, providerid) {
		log.W("proxy: rpn: make: %s <> %s mismatch", proxyid, providerid)
		return nil, errRpnIDsMismatch
	}
	log.D("proxy: rpn: make: %s[%s]", providerid, proxyid)
	return &rpnp{sync.RWMutex{}, e, acc, pxr, make(map[string]struct{}, 0), make(map[string]*x.RpnServer, 0), srv}, nil
}

func (r *rpnp) ensureProxy() Proxy {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.p == nil {
		panic(fmt.Sprintf("proxy: rpn: missing main for %s using provider %s",
			r.RpnAcc.Who(), r.RpnAcc.ProviderID()))
	}
	return r.p
}

func (r *rpnp) currentProxy() Proxy {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.p
}

func (r *rpnp) requireProxy() (Proxy, error) {
	if p := r.currentProxy(); p != nil {
		return p, nil
	}
	return nil, errRpnMissing
}

// ID implements x.Proxy.
func (r *rpnp) ID() string {
	// Must match the ID as added in the regular proxy map
	// Or clients trying to find its dnsx.Transport added via
	// AddProxyDNS may not find it available (since dnsx.Transport
	// use ProxyProvider, which only retrieves from proxy map).
	return r.ensureProxy().ID()
}

// Type implements x.Proxy.
func (r *rpnp) Type() string {
	return r.ensureProxy().Type()
}

// Router implements x.Proxy.
func (r *rpnp) Router() x.Router {
	return r.ensureProxy().Router()
}

// Client implements x.Proxy.
func (r *rpnp) Client() x.Client {
	return r.ensureProxy().Client()
}

// GetAddr implements x.Proxy.
func (r *rpnp) GetAddr() string {
	return r.ensureProxy().GetAddr()
}

// DNS implements x.Proxy.
func (r *rpnp) DNS() string {
	return r.ensureProxy().DNS()
}

// Status implements x.Proxy.
func (r *rpnp) Status() int {
	return r.ensureProxy().Status()
}

// Ping implements x.Proxy.
func (r *rpnp) Ping() bool {
	if p := r.currentProxy(); p != nil {
		return p.Ping()
	}
	return false
}

// Pause implements x.Proxy.
func (r *rpnp) Pause() bool {
	if p := r.currentProxy(); p != nil {
		return p.Pause()
	}
	return false
}

// Resume implements x.Proxy.
func (r *rpnp) Resume() bool {
	if p := r.currentProxy(); p != nil {
		return p.Resume()
	}
	return false
}

// Stop implements x.Proxy.
func (r *rpnp) Stop() error {
	r.PurgeAll()
	return nil
}

// Refresh implements x.Proxy.
func (r *rpnp) Refresh() error {
	p, err := r.requireProxy()
	if err != nil {
		return err
	}
	return p.Refresh()
}

// DialerHandle implements Proxy.
func (r *rpnp) DialerHandle() uint64 {
	return r.ensureProxy().DialerHandle()
}

// Handle implements Proxy.
func (r *rpnp) Handle() uint64 {
	return r.ensureProxy().Handle()
}

// Dialer implements Proxy.
func (r *rpnp) Dialer() protect.RDialer {
	return r
}

// onNotOK implements Proxy.
func (r *rpnp) onNotOK() (bool, bool) {
	if p := r.currentProxy(); p != nil {
		return p.onNotOK()
	}
	return false, false
}

// OnProtoChange implements Proxy.
func (r *rpnp) OnProtoChange(lp LinkProps) (string, bool) {
	if p := r.currentProxy(); p != nil {
		return p.OnProtoChange(lp)
	}
	return "", false
}

// Hop implements Proxy.
func (r *rpnp) Hop(via *core.WeakRef[Proxy], dryrun bool) error {
	main, err := r.requireProxy()
	if err != nil {
		return err
	}
	return main.Hop(via, dryrun)
}

// Dial implements Proxy.
func (r *rpnp) Dial(network, addr string) (protect.Conn, error) {
	if p, err := r.requireProxy(); err == nil {
		return p.Dial(network, addr)
	} else {
		return nil, err
	}
}

// DialBind implements Proxy.
func (r *rpnp) DialBind(network, local, remote string) (protect.Conn, error) {
	if p, err := r.requireProxy(); err == nil {
		return p.DialBind(network, local, remote)
	} else {
		return nil, err
	}
}

// Probe implements Proxy.
func (r *rpnp) Announce(network, local string) (protect.PacketConn, error) {
	if p, err := r.requireProxy(); err == nil {
		return p.Announce(network, local)
	} else {
		return nil, err
	}
}

// Accept implements Proxy.
func (r *rpnp) Accept(network, local string) (protect.Listener, error) {
	if p, err := r.requireProxy(); err == nil {
		return p.Accept(network, local)
	} else {
		return nil, err
	}
}

// Probe implements Proxy.
func (r *rpnp) Probe(network, local string) (protect.PacketConn, error) {
	if p, err := r.requireProxy(); err == nil {
		return p.Probe(network, local)
	} else {
		return nil, err
	}
}

// Emplace implements RpnProxy.
func (r *rpnp) Emplace(new Proxy) (err error) {
	if new == nil {
		log.W("proxy: rpn: emplace: no-op as new proxy nil")
		return errRpnBadEmplace
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	old := r.p
	oldid := idstr(old)
	newid := idstr(new)

	defer func() {
		if err != nil {
			core.Go("rpn.emplace."+oldid, func() {
				n := r.PurgeAll() // purge all kids on error
				log.E("proxy: rpn: emplace: %s[%s] failed; purged %d kids; emplace err: %v", oldid, newid, n, err)
			})
		}
	}()

	if oldid != newid {
		log.W("proxy: rpn: emplace: %s <> %s mismatch", oldid, newid)
	}

	r.p = new

	log.D("proxy: rpn: emplace: %s[%s]", r.RpnAcc.ProviderID(), newid)
	return nil
}

// Fork implements x.RpnProxy.
func (r *rpnp) Fork(cc string) (x.Proxy, error) {
	return r.fork(cc)
}

// cc may be a fully qualified ID (in case of re-forking the main proxy), too.
func (r *rpnp) fork(cc string) (x.Proxy, error) {
	// do not hold lock while calling into pxr as it can callback via Emplace.
	main, err := r.requireProxy()
	if err != nil || main == nil {
		return nil, core.OneErr(err, errRpnMainProxyMissing)
	}
	acc := r.RpnAcc

	mainpid := idstr(main)
	if len(mainpid) <= 0 {
		return nil, errMissingProxyID
	}

	provider := acc.ProviderID()
	if mainpid == provider+cc || // true when cc == noCountryForOldMen or anyCountryCode
		mainpid == cc || // true when cc is fully-qualified ID of the main proxy
		(cc == noCountryForOldMen && !acc.MultiCountry()) ||
		(cc == anyCountryCode && acc.MultiCountry()) {
		// re-forking main proxy (which may not be multi-country acc) via Update() => forkAll()
		log.I("proxy: rpn: fork: %s main cc %s; re-adding...", provider, cc)
		// expect Emplace to be called
		kid, srv, err := r.pxr.addRpnProxy(acc, cc) // re-generates conf and re-adds
		if kid != nil && core.IsNotNil(kid) {
			r.mu.Lock()
			r.s = srv
			r.mu.Unlock()
		}
		return kid, err
	}

	// check main's status if not forking main
	if main.Status() == END {
		// TODO: PurgeAll?
		return nil, errRpnMainProxyStopped
	}

	if len(cc) < 2 {
		return nil, errRpnBadCC
	}
	cc = strings.ToUpper(cc)
	if !acc.MultiCountry() {
		return nil, log.EE("proxy: rpn: fork: %s not multi-country %s", cc, provider)
	}

	log.I("proxy: rpn: fork: %s[%s]", provider, cc)

	// re-adds + updates if the proxy already exists
	kid, srv, err := r.pxr.addRpnProxy(acc, cc)

	if kid != nil && core.IsNotNil(kid) {
		r.mu.Lock()
		r.kids[cc] = struct{}{}
		if srv != nil {
			r.skids[cc] = srv
		}
		r.mu.Unlock()
	}

	return kid, err
}

func (r *rpnp) forkMain() error {
	main, err := r.requireProxy()
	if err != nil || main == nil {
		return log.EE("proxy: rpn: forkMain: main missing; err? %v", err)
	}

	mainpid := idstr(main)

	_, err = r.fork(mainpid) // re-adds main proxy (via Emplace)

	logei(err)("proxy: rpn: forkMain: %s; err? %v", mainpid, err)
	return err
}

// ccCsvAsSet mods a comma-separated list of country codes into a lookup set.
func ccCsvAsSet(csv string) map[string]struct{} {
	parts := strings.Split(csv, ",")
	out := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		p = strings.ToUpper(strings.TrimSpace(p))
		if len(p) > 0 {
			out[p] = struct{}{}
		}
	}
	return out
}

func (r *rpnp) forkAll() error {
	provider := r.RpnAcc.ProviderID()
	kids := r.flattenKids()

	errs := make([]error, 0) // may contain nil errors

	excludedSet := make(map[string]struct{}, 0)
	// ops is never expected to be nil; the check is for nilaway/vet
	if ops := r.RpnAcc.Ops(); ops != nil {
		excludedSet = ccCsvAsSet(ops.ExcludeCCs())
	}

	log.I("proxy: rpn: forkAll: %s [%v] incl: %d / excl: %d", provider, kids, len(kids), len(excludedSet))

	e := r.forkMain()
	errs = append(errs, e)

	for _, cc := range kids {
		if _, excluded := excludedSet[cc]; excluded {
			r.purge(cc) // remove excluded kid
			log.I("proxy: rpn: forkAll: %s[%s] excluded; purged", provider, cc)
		} else {
			_, e := r.fork(cc)
			loged(e)("proxy: rpn: forkAll: forked %s[%s]; err? %v", provider, cc, e)
			errs = append(errs, e)
		}
	}
	return core.JoinErr(errs...)
}

func (r *rpnp) Redo() (err error) {
	return r.forkAll()
}

func (r *rpnp) PingAll() (csvpids string, err error) {
	start := time.Now()
	provider := r.RpnAcc.ProviderID()
	kids := r.flattenKids()
	main, err := r.requireProxy()

	logei(err)("proxy: rpn: pingAll: %s[%v]; got main? %t; err: %v",
		provider, kids, main != nil, err)

	if err != nil {
		return
	}

	mainpinged := main.Ping()
	if !mainpinged {
		log.W("proxy: rpn: pingAll: main proxy %s failed ping", provider)
	}

	kidspinged := make([]string, 0, len(kids))
	errs := make([]error, 0)
	for _, cc := range kids {
		p, rerr := r.pxr.rpnProxyFor(provider, cc)
		if rerr != nil {
			errs = append(errs, rerr)
			continue
		}
		if !p.Ping() {
			log.W("proxy: rpn: pingAll: proxy for %s[%s] failed ping", provider, cc)
		} else {
			kidspinged = append(kidspinged, cc)
		}
	}

	err = core.JoinErr(errs...)
	logei(err)("proxy: rpn: pingAll: %s[%v] done in %s; main pinged? %t / kids pinged? %v; err? %v",
		provider, kids, core.FmtTimeAsPeriod(start), mainpinged, kidspinged, errs)

	return strings.Join(kidspinged, ","), err
}

func (r *rpnp) PurgeAll() (n uint32) {
	for _, cc := range r.flattenKids() {
		if r.purge(cc) {
			n++
		}
	}

	if r.purgeMain() {
		n++
	}
	return
}

func (r *rpnp) purgeMain() bool {
	main, err := r.requireProxy()
	mainpid := idstr(main)
	logei(err)("proxy: rpn: purgeMain: %s; err? %v", mainpid, err)
	if err != nil {
		return false
	}
	r.mu.Lock()
	r.s = nil
	r.mu.Unlock()
	return r.pxr.removeRpnProxy(r.RpnAcc, mainpid)
}

// Purge implements x.RpnProxy.
func (r *rpnp) Purge(cc string) bool {
	return r.purge(cc)
}

func (r *rpnp) purge(cc string) bool {
	main, err := r.requireProxy()
	if err != nil {
		log.W("proxy: rpn: purge: no main proxy %s", err)
		return false
	}
	acc := r.RpnAcc

	provider := acc.ProviderID()
	mainpid := idstr(main)
	cc = strings.ToUpper(cc)

	if !acc.MultiCountry() {
		log.D("proxy: rpn: purge: %s not multi-country %s", cc, provider)
		return false
	} else if cc == mainpid || provider+cc == mainpid {
		log.W("proxy: rpn: purge: %s is main; call PurgeAll instead", cc, provider)
		return false
	} else if len(cc) < 2 {
		log.W("proxy: rpn: purge: %s bad country code; not purging", cc)
		return false
	}

	rmv := r.pxr.removeRpnProxy(acc, cc)

	r.mu.Lock()
	delete(r.kids, cc)
	delete(r.skids, cc)
	r.mu.Unlock()

	log.D("proxy: rpn: purge: %s[%s]? %t", provider, cc, rmv)
	return rmv
}

func (r *rpnp) GetInternal(cc string) (Proxy, error) {
	return r.get(cc)
}

// Get implements x.RpnProxy.
func (r *rpnp) Get(cc string) (x.Proxy, error) {
	return r.get(cc)
}

func (r *rpnp) get(cc string) (Proxy, error) {
	acc := r.RpnAcc
	provider := acc.ProviderID()

	if cc == noCountryForOldMen && !acc.MultiCountry() {
		return r, nil
	}
	if !acc.MultiCountry() {
		return nil, log.EE("proxy: rpn: get: %s not multi-country %s", cc, provider)
	}

	// cc may be fully-qualified ex: "typcity;cc"
	// but we need cc to be "city;cc"  (ref addRpnProxy(acc, cc))
	cc, _ = strings.CutPrefix(cc, provider)

	cc = strings.ToUpper(cc)

	r.mu.RLock()
	main := r.p
	_, gotCC := r.kids[cc]
	r.mu.RUnlock()

	mainpid := idstr(main)
	// see fork(cc)
	if provider+cc == mainpid || // true when cc == anyCountryCode
		cc == mainpid || // true when cc is fully-qualified ID of the main proxy
		cc == anyCountryCode && acc.MultiCountry() {
		// return r as-is; r.p is always got after r.mu.RLock()
		return r, nil
	}

	if len(cc) < 2 {
		log.W("proxy: rpn: get: %s bad country code", cc)
		return nil, errRpnBadCC
	}

	if !gotCC {
		return nil, errRpnNotForked
	}
	return r.pxr.rpnProxyFor(provider, cc)
}

// Kids implements x.RpnProxy.
func (r *rpnp) Kids() x.RpnServers {
	r.mu.RLock()
	all := make([]x.RpnServer, 0, len(r.skids))
	for _, s := range r.skids {
		if s != nil {
			all = append(all, *s)
		}
	}
	r.mu.RUnlock()
	return &liveServers{all: all}
}

func (r *rpnp) flattenKids() (ccs []string) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ccs = make([]string, 0, len(r.kids))
	for cc := range r.kids {
		ccs = append(ccs, cc)
	}
	return
}

// liveServers implements x.RpnServers.
type liveServers struct {
	all []x.RpnServer
}

var _ x.RpnServers = (*liveServers)(nil)

func (s *liveServers) Get(i int) (*x.RpnServer, error) {
	if i < 0 || i >= len(s.all) {
		return nil, fmt.Errorf("rpn: live: %d out of range [0, %d)", i, len(s.all))
	}
	return &s.all[i], nil
}

func (s *liveServers) Len() int {
	return len(s.all)
}

func (s *liveServers) Json() ([]byte, error) {
	if s == nil || len(s.all) <= 0 {
		return nil, fmt.Errorf("rpn: live: no servers")
	}
	b, err := json.Marshal(s.all)
	if err != nil {
		return nil, fmt.Errorf("rpn: live: json: %w", err)
	}
	return b, nil
}

// Main implements x.RpnProxy.
func (r *rpnp) Main() (m *x.RpnServer) {
	r.mu.RLock()
	if s := r.s; s != nil {
		m = new(x.RpnServer)
		*m = *s
	}
	r.mu.RUnlock()
	return
}

// Update implements RpnAcc.
func (r *rpnp) Update(ops *x.RpnOps) (newState []byte, err error) {
	newState, err = r.RpnAcc.Update(ops)
	if len(newState) <= 0 && err == nil {
		// updated and no state change
		return nil, nil
	} else if err == nil {
		core.Gxe("rpn.fork."+r.ProviderID(), r.forkAll)
	}
	return
}
