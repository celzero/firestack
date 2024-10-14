// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"net/netip"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/protect"
)

// gw is a no-op/stub gateway that is either dualstack or not and has dummy stats.
type gw struct {
	nov4, nov6 bool          // is dualstack
	stats      x.RouterStats // zero stats
}

var _ x.Router = (*gw)(nil)

// IP4 implements Router.
func (w *gw) IP4() bool { return !w.nov4 }

// IP6 implements Router.
func (w *gw) IP6() bool { return !w.nov6 }

// MTU implements Router.
func (w *gw) MTU() (int, error) { return NOMTU, errNoMtu }

// Stat implements Router.
func (w *gw) Stat() *x.RouterStats { return &w.stats }

// Contains implements Router.
func (w *gw) Contains(prefix string) bool {
	ipnet, err := netip.ParsePrefix(prefix)
	if err != nil {
		return false
	}
	return (w.ok(ipnet.Addr()))
}

func (w *gw) ok(ip netip.Addr) bool  { return w.ok4(ip) || w.ok6(ip) }
func (w *gw) ok4(ip netip.Addr) bool { return w.IP4() && ip.IsValid() && ip.Is4() }
func (w *gw) ok6(ip netip.Addr) bool { return w.IP6() && ip.IsValid() && ip.Is6() }

func (w *gw) Reaches(hostportOrIPPortCsv string) bool {
	if len(hostportOrIPPortCsv) <= 0 {
		return true
	}
	ips := dialers.For(hostportOrIPPortCsv)
	for _, ip := range ips {
		if w.ok(ip) {
			return true
		}
	}
	return false
}

// proxynogateway is a Router that routes nothing.
var proxynogateway = gw{nov4: true, nov6: true}

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

// Probe implements Proxy.
func (nofwd) Probe(string, string) (protect.PacketConn, error) {
	return nil, errProbeNotSupported
}
