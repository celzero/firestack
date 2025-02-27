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
	"github.com/celzero/firestack/intra/ipn/warp"
	"github.com/celzero/firestack/intra/log"
)

type RpnProxy = warp.RpnProxy

type RpnAcc = warp.RpnAcc

// TODO: override Probe, Ping, Announce, Accept, Dial, DialBind
// and kick-off an update if the acc is expired?
type rpnp struct {
	Proxy
	RpnAcc

	pxr Rpn

	kids map[string]struct{}
	kmu  sync.RWMutex
}

var _ RpnProxy = (*rpnp)(nil)

var (
	errRpnBadArgs          = errors.New("proxy: rpn: bad args")
	errRpnBadCC            = errors.New("proxy: rpn: bad country code")
	errRpnNotMultiCC       = errors.New("proxy: rpn: not multi-country")
	errRpnIDsMismatch      = errors.New("proxy: rpn: provider x proxy mismatch")
	errRpnMainProxyStopped = errors.New("proxy: rpn: cannot fork; main proxy stopped")
	errRpnNotForked        = errors.New("proxy: rpn: not forked")
)

func asRpnProxy(e Proxy, acc RpnAcc, pxr Rpn) (RpnProxy, error) {
	if e == nil || acc == nil || pxr == nil {
		return nil, errRpnBadArgs
	}

	proxyid := e.ID() // must be of form "provider-id + country-code"
	providerid := acc.ProviderID()
	if !strings.HasPrefix(proxyid, providerid) {
		log.W("proxy: rpn: make: %s <> %s mismatch", proxyid, providerid)
		return nil, errRpnIDsMismatch
	}
	log.D("proxy: rpn: make: %s[%s]", providerid, proxyid)
	return &rpnp{e, acc, pxr, make(map[string]struct{}, 0), sync.RWMutex{}}, nil
}

func (r *rpnp) Fork(cc string) (x.Proxy, error) {
	if !r.RpnAcc.MultiCountry() {
		return nil, errRpnNotMultiCC
	}
	if len(cc) < 2 {
		return nil, errRpnBadCC
	}
	cc = strings.ToUpper(cc)
	provider := r.RpnAcc.ProviderID()

	pid := r.Proxy.ID()
	if strings.HasSuffix(pid, cc) {
		log.W("proxy: rpn: fork: %s already cc %s", provider, cc)
		return r, nil
	}

	if r.Proxy.Status() == END {
		return nil, errRpnMainProxyStopped
	}

	// re-adds + updates if the proxy already exists
	rp, err := r.pxr.addRpnProxy(r.RpnAcc, cc)

	if rp != nil {
		r.kmu.Lock()
		r.kids[cc] = struct{}{}
		r.kmu.Unlock()
	}

	return rp, err
}

func (r *rpnp) PurgeAll() (n uint32) {
	for _, cc := range r.flattenKids() {
		if r.Purge(cc) {
			n++
		}
	}

	if r.pxr.removeRpnProxy(r.RpnAcc, mainCountryCode) {
		n++
	}
	return
}

// Purge implements x.RpnProxy.
func (r *rpnp) Purge(cc string) bool {
	provider := r.RpnAcc.ProviderID()
	if !r.RpnAcc.MultiCountry() {
		log.D("proxy: rpn: purge: %s not multi-country %s", cc, provider)
		return false
	} else if cc == mainCountryCode {
		log.W("proxy: rpn: purge: %s is main; call unregister instead", cc, provider)
		return false
	}

	rmv := r.pxr.removeRpnProxy(r.RpnAcc, cc)
	delete(r.kids, cc)

	log.D("proxy: rpn: purge: %s[%s]? %t", provider, cc, rmv)
	return rmv
}

// Get implements x.RpnProxy.
func (r *rpnp) Get(cc string) (x.Proxy, error) {
	if !r.RpnAcc.MultiCountry() {
		return nil, errRpnNotMultiCC
	}

	if _, ok := r.kids[cc]; ok {
		cc = strings.ToUpper(cc)
		return r.pxr.rpnProxyFor(r.RpnAcc.ProviderID(), cc)
	}
	return nil, errRpnNotForked
}

// Kids implements x.RpnProxy.
func (r *rpnp) Kids() string {
	return strings.Join(r.flattenKids(), ",")
}

func (r *rpnp) flattenKids() (ids []string) {
	r.kmu.RLock()
	defer r.kmu.RUnlock()

	ids = make([]string, len(r.kids))
	for k := range r.kids {
		ids = append(ids, k)
	}
	return
}

func (r *rpnp) State() (existingState []byte, err error) {
	return r.RpnAcc.State()
}

func (r *rpnp) Created() int64 {
	return r.RpnAcc.Created()
}

func (r *rpnp) Expires() int64 {
	return r.RpnAcc.Expires()
}

func (r *rpnp) Update() (newState []byte, err error) {
	return r.RpnAcc.Update()
}
