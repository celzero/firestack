// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/ipn/rpn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
)

type RpnProxy interface {
	x.RpnProxy
	Proxy
	Emplace(Proxy) error
	PurgeAll() (n uint32)
}

type RpnAcc = rpn.RpnAcc

// and kick-off an update if the acc is expired?
type rpnp struct {
	mu sync.RWMutex // protects Proxy & kids

	// parent proxy
	p Proxy
	// Rpn-specific accounting
	// TODO: unembed to type assert RpnAcc impl
	RpnAcc

	// rpn proxy manager
	pxr Rpn

	// forked child proxy IDs, may be empty (returned proxy IDs may have stopped)
	kids map[string]struct{}
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
	errRpnMainProxyStopped = errors.New("proxy: rpn: cannot fork; main proxy stopped")
	errRpnNotForked        = errors.New("proxy: rpn: not forked")
)

// nb: client code isn't really expecting error from asRpnProxy.
func asRpnProxy(e Proxy, acc RpnAcc, pxr Rpn) (RpnProxy, error) {
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
	return &rpnp{sync.RWMutex{}, e, acc, pxr, make(map[string]struct{}, 0)}, nil
}

func (r *rpnp) ensureProxy() Proxy {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.p == nil {
		panic(fmt.Sprintf("proxy: rpn: missing main for %s using provider %s", r.RpnAcc.Who(), r.RpnAcc.ProviderID()))
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
func (r *rpnp) ID() *x.Gostr {
	return r.ensureProxy().ID()
}

// Type implements x.Proxy.
func (r *rpnp) Type() *x.Gostr {
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
func (r *rpnp) GetAddr() *x.Gostr {
	return r.ensureProxy().GetAddr()
}

// DNS implements x.Proxy.
func (r *rpnp) DNS() *x.Gostr {
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
	p, err := r.requireProxy()
	if err != nil {
		return err
	}
	return p.Stop()
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
func (r *rpnp) DialerHandle() uintptr {
	return r.ensureProxy().DialerHandle()
}

// Handle implements Proxy.
func (r *rpnp) Handle() uintptr {
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
func (r *rpnp) Hop(p Proxy, dryrun bool) error {
	main, err := r.requireProxy()
	if err != nil {
		return err
	}
	return main.Hop(p, dryrun)
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
		core.Go("rpn.emplace."+oldid, func() {
			if err != nil {
				n := r.PurgeAll() // purge all kids on error
				log.I("proxy: rpn: emplace: %s[%s] failed; purged %d kids", oldid, newid, n)
			} else if !Same(old, new) {
				serr := old.Stop() // stop old proxy if it is different
				log.I("proxy: rpn: emplace: %s; %s stopped; err %v", oldid, newid, serr)
			}
		})
	}()

	if oldid != newid {
		log.W("proxy: rpn: emplace: %s <> %s mismatch", oldid, newid)
	}

	r.p = new

	log.D("proxy: rpn: emplace: %s[%s]", r.RpnAcc.ProviderID(), newid)
	return nil
}

// Fork implements x.RpnProxy.
func (r *rpnp) Fork(cc *x.Gostr) (x.Proxy, error) {
	return r.fork(cc.V())
}

// cc may be a fully qualified ID (in case of re-forking the main proxy), too.
func (r *rpnp) fork(cc string) (x.Proxy, error) {
	// do not hold lock while calling into pxr as it can callback via Emplace.
	main, err := r.requireProxy()
	if err != nil {
		return nil, err
	}
	acc := r.RpnAcc

	mainpid := idstr(main)
	if len(mainpid) <= 0 || main.Status() == END {
		// TODO: PurgeAll?
		return nil, errRpnMainProxyStopped
	}

	provider := acc.ProviderID()
	if mainpid == provider+cc || mainpid == cc {
		// re-forking main proxy (which may not be multi-country acc) via Update() => forkAll()
		log.I("proxy: rpn: fork: %s main cc %s; re-adding...", provider, cc)
		// expect Emplace to be called
		return r.pxr.addRpnProxy(acc, cc) // re-generates conf and re-adds
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
	kid, err := r.pxr.addRpnProxy(acc, cc)

	if kid != nil {
		r.mu.Lock()
		r.kids[cc] = struct{}{}
		r.mu.Unlock()
	}

	return kid, err
}

func (r *rpnp) forkMain() {
	main, err := r.requireProxy()
	if err != nil {
		return
	}

	mainpid := idstr(main)

	_, err = r.fork(mainpid) // re-adds main proxy (via Emplace)

	logei(err)("proxy: rpn: forkMain: %s; err? %v", mainpid, err)
}

func (r *rpnp) forkAll() {
	provider := r.RpnAcc.ProviderID()
	log.I("proxy: rpn: forkAll: %s[%s]", provider, r.kidsCsv())

	r.forkMain()

	for _, cc := range r.flattenKids() {
		_, err := r.fork(cc)
		loged(err)("proxy: rpn: forkAll: forked %s[%s]; err? %v", provider, cc, err)
	}
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
	return r.pxr.removeRpnProxy(r.RpnAcc, mainpid)
}

// Purge implements x.RpnProxy.
func (r *rpnp) Purge(cc *x.Gostr) bool {
	return r.purge(cc.V())
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
	r.mu.Unlock()

	log.D("proxy: rpn: purge: %s[%s]? %t", provider, cc, rmv)
	return rmv
}

// Get implements x.RpnProxy.
func (r *rpnp) Get(cc *x.Gostr) (x.Proxy, error) {
	return r.get(cc.V())
}

func (r *rpnp) get(cc string) (x.Proxy, error) {
	acc := r.RpnAcc
	rpnid := acc.ProviderID()

	if cc == noCountryForOldMen && !acc.MultiCountry() {
		return r, nil
	}
	if !acc.MultiCountry() {
		return nil, log.EE("proxy: rpn: get: %s not multi-country %s", cc, rpnid)
	}
	if len(cc) < 2 {
		log.W("proxy: rpn: get: %s bad country code", cc)
		return nil, errRpnBadCC
	}
	cc = strings.ToUpper(cc)

	r.mu.RLock()
	main := r.p
	_, gotCC := r.kids[cc]
	r.mu.RUnlock()

	if rpnid+cc == idstr(main) {
		// FIXME: r.Proxy needs to be got after r.mu.RLock()
		return r, nil
	}
	if !gotCC {
		return nil, errRpnNotForked
	}
	return r.pxr.rpnProxyFor(rpnid, cc)
}

// Kids implements x.RpnProxy.
func (r *rpnp) Kids() (csvpids *x.Gostr) {
	return x.StrOf(r.kidsCsv())
}

func (r *rpnp) kidsCsv() string {
	return strings.Join(r.flattenKids(), ",")
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

// Update implements RpnAcc.
func (r *rpnp) Update() (newState *x.Gobyte, err error) {
	newState, err = r.RpnAcc.Update()
	if err == nil {
		core.Gx("rpn.fork."+r.ProviderID(), r.forkAll)
	}
	return
}
