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

type RpnProxy = x.RpnProxy
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
	errRpnForkFromMain     = errors.New("proxy: rpn: must call fork on main")
	errRpnMainProxyStopped = errors.New("proxy: rpn: cannot fork; main proxy stopped")
)

func AsRpnProxy(e Proxy, acc RpnAcc, pxr Rpn) (RpnProxy, error) {
	if e == nil || acc == nil || pxr == nil {
		return nil, errRpnBadArgs
	}

	proxyid := e.ID() // must be of form "provider-id + country-code"
	providerid := acc.ProviderID()
	if !strings.HasPrefix(proxyid, providerid) {
		return nil, errRpnIDsMismatch
	}
	return &rpnp{e, acc, pxr, make(map[string]struct{}, 0), sync.RWMutex{}}, nil
}

func mainRpnProxyID(acc RpnAcc) string {
	typ := acc.ProviderID()
	cc := noCountryForOldMen
	if !acc.MultiCountry() {
		cc = defaultCountryCode
	}
	return typ + cc
}

func (r *rpnp) isMain() bool {
	pid := r.Proxy.ID()
	mid := mainRpnProxyID(r.RpnAcc)
	y := mid == pid
	log.VV("proxy: rpn: %s (by %s) is main? %t", pid, mid, y)
	return y
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

	if !r.isMain() {
		return nil, errRpnForkFromMain
	}
	if r.Proxy.Status() == END {
		return nil, errRpnMainProxyStopped
	}

	// re-adds + updates if the proxy already exists
	p, err := r.pxr.addRpnProxy(r.RpnAcc, cc)

	if p != nil {
		r.kmu.Lock()
		r.kids[cc] = struct{}{}
		r.kmu.Unlock()
	}

	return p, err
}

// Purge implements x.RpnProxy.
func (r *rpnp) Purge(cc string) bool {
	provider := r.RpnAcc.ProviderID()
	if !r.RpnAcc.MultiCountry() {
		log.D("proxy: rpn: purge: %s not multi-country %s", cc, provider)
		return false
	} else if cc == defaultCountryCode {
		log.W("proxy: rpn: purge: %s is main; call unregister instead", cc, provider)
		return false
	}
	if !r.isMain() { // only main can call purge
		log.W("proxy: rpn: purge: %s not called on main %s", cc, provider)
		return false
	}

	n := r.pxr.removeRpnProxy(r.RpnAcc, cc) // n is expected to be 0 or 1
	if n == 1 {
		delete(r.kids, cc)
	} // else: shouldn't happen as only unregistering "main" will rmv 1+

	log.D("proxy: rpn: purge: %s removed from %s? (1 == %d)", cc, provider, n)
	return n > 0
}

// Get implements x.RpnProxy.
func (r *rpnp) Get(cc string) (x.Proxy, error) {
	if !r.RpnAcc.MultiCountry() {
		return nil, errRpnNotMultiCC
	}

	cc = strings.ToUpper(cc)
	return r.pxr.rpnProxyFor(r.RpnAcc, cc)
}

// Kids implements x.RpnProxy.
func (r *rpnp) Kids() string {
	return strings.Join(r.kiddies(), ",")
}

func (r *rpnp) kiddies() (ids []string) {
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
