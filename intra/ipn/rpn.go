// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"errors"
	"strings"
	"sync"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/ipn/rpn"
	"github.com/celzero/firestack/intra/log"
)

type RpnProxy interface {
	x.RpnProxy
	Proxy
	Emplace(Proxy) error
	PurgeAll() (n uint32)
}

type RpnAcc = rpn.RpnAcc

// TODO: override Probe, Ping, Announce, Accept, Dial, DialBind
// and kick-off an update if the acc is expired?
type rpnp struct {
	mu sync.RWMutex // protects Proxy & kids

	// parent Proxy
	// TODO: unembed to type assert Proxy impl and to use mu
	Proxy
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

// Emplace implements RpnProxy.
func (r *rpnp) Emplace(new Proxy) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	old := r.Proxy
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

	if new == nil {
		log.W("proxy: rpn: emplace: bad args; remove all...")
		return errRpnBadEmplace
	}

	if oldid != newid {
		log.W("proxy: rpn: emplace: %s <> %s mismatch", oldid, newid)
	}

	r.Proxy = new

	log.D("proxy: rpn: emplace: %s[%s]", r.RpnAcc.ProviderID(), newid)
	return nil
}

// Fork implements x.RpnProxy.
func (r *rpnp) Fork(cc *x.Gostr) (x.Proxy, error) {
	return r.fork(cc.V())
}

func (r *rpnp) fork(cc string) (x.Proxy, error) {
	// do not hold lock while calling into pxr as it can callback via Emplace.
	r.mu.RLock()
	main := r.Proxy
	acc := r.RpnAcc
	r.mu.RUnlock()

	mainpid := idstr(main)
	if len(mainpid) <= 0 || main.Status() == END {
		// TODO: PurgeAll?
		return nil, errRpnMainProxyStopped
	}

	provider := acc.ProviderID()
	if strings.HasSuffix(mainpid, cc) {
		// re-forking main proxy (which may not be multi-country acc) via Update() => forkAll()
		log.I("proxy: rpn: fork: %s main cc %s<>%s; re-adding...", provider, maincc(acc), cc)
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
	provider := r.RpnAcc.ProviderID()
	cc := maincc(r.RpnAcc)

	_, err := r.fork(cc) // re-adds main proxy (via Emplace)

	logei(err)("proxy: rpn: forkMain: %s[%s]; err? %v", provider, cc, err)
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
	return r.pxr.removeRpnProxy(r.RpnAcc, maincc(r.RpnAcc))
}

// Purge implements x.RpnProxy.
func (r *rpnp) Purge(cc *x.Gostr) bool {
	return r.purge(cc.V())
}

func (r *rpnp) purge(cc string) bool {
	acc := r.RpnAcc
	provider := acc.ProviderID()
	cc = strings.ToUpper(cc)

	if !acc.MultiCountry() {
		log.D("proxy: rpn: purge: %s not multi-country %s", cc, provider)
		return false
	} else if cc == maincc(acc) {
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
	if len(cc) < 2 {
		log.W("proxy: rpn: get: %s bad country code", cc)
		return nil, errRpnBadCC
	}
	cc = strings.ToUpper(cc)

	acc := r.RpnAcc
	if cc == maincc(acc) {
		// TODO: r.Proxy needs to be got after r.mu.RLock()
		return r, nil
	} else if !acc.MultiCountry() {
		return nil, log.EE("proxy: rpn: get: %s not multi-country %s", cc, acc.ProviderID())
	}

	r.mu.RLock()
	_, gotCC := r.kids[cc]
	r.mu.RUnlock()

	if !gotCC {
		return nil, errRpnNotForked
	}
	return r.pxr.rpnProxyFor(acc.ProviderID(), cc)
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

func (r *rpnp) Created() int64 {
	return r.RpnAcc.Created()
}

func (r *rpnp) Expires() int64 {
	return r.RpnAcc.Expires()
}

func (r *rpnp) Update() (newState *x.Gobyte, err error) {
	newState, err = r.RpnAcc.Update()
	if err == nil {
		go r.forkAll()
	}
	return
}

func (r *rpnp) Locations() (x.RpnServers, error) {
	return r.RpnAcc.Locations()
}
