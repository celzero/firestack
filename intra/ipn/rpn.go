// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"errors"
	"strings"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/ipn/warp"
	"github.com/celzero/firestack/intra/log"
)

type RpnProxy = x.RpnProxy
type RpnAcc = warp.RpnAcc

type rpnp struct {
	Proxy
	RpnAcc

	pxr Rpn
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
	return &rpnp{e, acc, pxr}, nil
}

func mainRpnProxyID(acc RpnAcc) string {
	typ := acc.ProviderID()
	cc := noCountryForOldMen
	if !acc.MultiCountry() {
		cc = defaultCountryCode
	}
	return typ + cc
}

func (r *rpnp) IsMain() bool {
	pid := r.Proxy.ID()
	mid := mainRpnProxyID(r.RpnAcc)
	y := mid == pid
	log.VV("proxy: rpn: %s (by %s) is main? %t", pid, mid, y)
	return y
}

func (r *rpnp) Fork(cc string) (x.RpnProxy, error) {
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

	if !r.IsMain() {
		return nil, errRpnForkFromMain
	}
	if r.Proxy.Status() == END {
		return nil, errRpnMainProxyStopped
	}
	// re-adds + updates if the proxy already exists
	return r.pxr.addRpnProxy(r.RpnAcc, cc)
}

// Purge implements x.RpnProxy.
func (r *rpnp) Purge(cc string) bool {
	if !r.RpnAcc.MultiCountry() {
		log.D("proxy: rpn: purge: %s not multi-country %s", r.ProviderID(), cc)
		return false
	}

	return r.pxr.removeRpnProxy(r.RpnAcc, cc)
}

// Get implements x.RpnProxy.
func (r *rpnp) Get(cc string) (x.RpnProxy, error) {
	if !r.RpnAcc.MultiCountry() {
		return nil, errRpnNotMultiCC
	}

	cc = strings.ToUpper(cc)
	return r.pxr.rpnProxyFor(r.RpnAcc, cc)
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
