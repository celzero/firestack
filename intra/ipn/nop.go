// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/protect"
)

// gw is a no-op/stub gateway that is either dualstack or not and has dummy stats.
type gw struct {
	dual  bool    // is dualstack
	stats x.Stats // zero stats
}

// IP4 implements Router.
func (w *gw) IP4() bool { return w.dual }

// IP6 implements Router.
func (w *gw) IP6() bool { return w.dual }

// MTU implements Router.
func (w *gw) MTU() (int, error) { return NOMTU, errNoMtu }

// Stat implements Router.
func (w *gw) Stat() *x.Stats { return &w.stats }

// Contains implements Router.
func (w *gw) Contains(string) bool { return w.dual }

// PROXYGATEWAY is a stub Router that routes everything.
var PROXYGATEWAY = &gw{dual: true}

// PROXYNOGATEWAY is a stub Router that routes nothing.
var PROXYNOGATEWAY = &gw{dual: false}

// protoagnostic is a proxy that does not care about protocol changes.
type protoagnostic struct{}

// onProtoChange implements Proxy.
func (protoagnostic) onProtoChange() (string, bool) { return "", false }

// skiprefresh is a proxy that does not need to be refreshed or pinged on network changes.
type skiprefresh struct{}

// Refresh implements Proxy.
func (skiprefresh) Refresh() error { return nil }

// Ping implements Proxy.
func (skiprefresh) Ping() bool { return false }

// nofwd is a proxy that does not support listening or forwarding.
type nofwd struct{}

// Announce implements Proxy.
func (nofwd) Announce(network, local string) (protect.PacketConn, error) {
	return nil, errAnnounceNotSupported
}

// Accept implements Proxy.
func (nofwd) Accept(network, local string) (protect.Listener, error) {
	return nil, errAnnounceNotSupported
}
