// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"errors"
	"net/netip"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/protect"
)

var (
	errProbeNotSupported    = errors.New("proxy: probe not supported")
	errAnnounceNotSupported = errors.New("proxy: announce not supported")
	errAcceptNotSupported   = errors.New("proxy: accept not supported")
)

const nodns = "" // no DNS

// todo: impl a baseproxy for common fns ID, GetAddr, Status, Via, Hop etc
type GWNoVia struct {
	NoVia
	GW
}

// GW is a no-op/stub gateway that is either dualstack or not and has dummy stats.
type GW struct {
	nov4, nov6 bool          // is dualstack
	stats      x.RouterStats // zero stats
}

var _ x.Router = (*GWNoVia)(nil)

// IP4 implements x.Router.
func (w *GW) IP4() bool { return !w.nov4 }

// IP6 implements x.Router.
func (w *GW) IP6() bool { return !w.nov6 }

// MTU implements x.Router.
func (w *GW) MTU() (int, error) { return NOMTU, errNoMtu }

// Stat implements x.Router.
func (w *GW) Stat() *x.RouterStats {
	if !w.nov4 || !w.nov6 {
		w.stats.LastOK = now() // always OK
	}
	return &w.stats
}

// Contains implements x.Router.
func (w *GW) Contains(ippOrCidr string) bool {
	prefix, err := core.IP2Cidr2(ippOrCidr)
	if err != nil {
		return false
	}
	return w.ok(prefix.Addr())
}

func (w *GW) ok(ip netip.Addr) bool  { return w.ok4(ip) || w.ok6(ip) }
func (w *GW) ok4(ip netip.Addr) bool { return w.IP4() && ip.IsValid() && ip.Is4() }
func (w *GW) ok6(ip netip.Addr) bool { return w.IP6() && ip.IsValid() && ip.Is6() }

// Reaches implements Router.
func (w *GW) Reaches(hostportOrIPPortCsvStr string) bool {
	hostportOrIPPortCsv := hostportOrIPPortCsvStr

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

// ProxyNoGateway is a Router that routes nothing.
var ProxyNoGateway = GWNoVia{GW: GW{nov4: true, nov6: true}}

// ProtoAgnostic is a proxy that does not care about protocol changes.
type ProtoAgnostic struct{}

// OnProtoChange implements Proxy.
func (ProtoAgnostic) OnProtoChange(_ LinkProps) (string, bool) { return "", false }

// SkipRefresh is a proxy that does not need to be refreshed or pinged on network changes.
type SkipRefresh struct{}

// Refresh implements Proxy.
func (SkipRefresh) Refresh() error { return nil }

func (SkipRefresh) onNotOK() (didRefresh bool, allOK bool) { return false, true }

// Ping implements Proxy.
func (SkipRefresh) Ping() bool { return false }

type CantPause struct{}

// Pause implements Proxy.
func (CantPause) Pause() bool { return false }

// Resume implements Proxy.
func (CantPause) Resume() bool { return false }

// NoFwd is a proxy that does not support listening or forwarding.
type NoFwd struct{}

// Announce implements Proxy.
func (NoFwd) Announce(network, local string) (protect.PacketConn, error) {
	return nil, errAnnounceNotSupported
}

// Accept implements Proxy.
func (NoFwd) Accept(network, local string) (protect.Listener, error) {
	return nil, errAcceptNotSupported
}

// Probe implements Proxy.
func (NoFwd) Probe(string, string) (protect.PacketConn, error) {
	return nil, errProbeNotSupported
}

type NoDNS struct{}

func (NoDNS) DNS() string {
	return nodns
}

type NoVia struct{}

func (NoVia) Via() (x.Proxy, error) { return nil, errNop }
func (NoVia) Hop(Proxy, bool) error { return errNop }

var errNop = errors.New("proxy: nop")

type NoClient struct{}

func (NoClient) Client() x.Client { return nil }

type NoProxy struct {
	NoDNS
	ProtoAgnostic
	SkipRefresh
	NoFwd
	CantPause
	GWNoVia
}

func (NoProxy) Handle() uintptr                                       { return core.Nobody }
func (NoProxy) DialerHandle() uintptr                                 { return core.Nobody }
func (NoProxy) ID() string                                            { return "" }
func (NoProxy) Type() string                                          { return "" }
func (NoProxy) Router() x.Router                                      { return nil }
func (NoProxy) Reaches(string) bool                                   { return false }
func (NoProxy) Dial(string, string) (protect.Conn, error)             { return nil, errNop }
func (NoProxy) DialBind(string, string, string) (protect.Conn, error) { return nil, errNop }
func (NoProxy) Dialer() protect.RDialer                               { return nil }
func (NoProxy) Status() int                                           { return 0 }
func (NoProxy) GetAddr() string                                       { return "" }
func (NoProxy) Stop() error                                           { return nil }
func (NoProxy) Client() x.Client                                      { return nil }
