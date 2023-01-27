// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package intra

import (
	"net/netip"
	"strings"

	"github.com/celzero/firestack/intra/dns53"
	"github.com/celzero/firestack/intra/dnscrypt"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/doh"
	"github.com/celzero/firestack/intra/protect"
)

func NewDNSProxy(id, ip, port string) (d dnsx.Transport, err error) {
	return dns53.NewTransport(id, ip, port)
}

func newDNSProxy(id string, ipp netip.AddrPort) (d dnsx.Transport, err error) {
	return dns53.NewTransportFrom(id, ipp)
}

func NewGroundedTransport() (d dnsx.Transport) {
	return dns53.NewGroundedTransport()
}

func newDNSCryptTransport() (p dnsx.TransportMult) {
	p = dnscrypt.NewProxy()
	return
}

// NewDoHTransport returns a DNSTransport that connects to the specified DoH server.
// `url` is the URL of a DoH server (no template, POST-only).  If it is nonempty, it
//   overrides `udpdns` and `tcpdns`.
// `ips` is an optional comma-separated list of IP addresses for the server.  (This
//   wrapper is required because gomobile cannot make bindings for []string.)
// `protector` is the socket protector to use for all external network activity.
// `auth` will provide a client certificate if required by the TLS server.
// `listener` will be notified after each DNS query succeeds or fails.
func NewDoHTransport(id, url string, ips string, auth doh.ClientAuth) (dnsx.Transport, error) {
	split := []string{}
	if len(ips) > 0 {
		split = strings.Split(ips, ",")
	}
	dialer := protect.MakeDialer(nil)
	return doh.NewTransport(id, url, split, dialer, auth)
}

func NewDNSCryptTransport(r dnsx.Resolver, id, stamp string) (d dnsx.Transport, err error) {
	if tm, err := r.DcProxy(); err == nil {
		if p, ok := tm.(*dnscrypt.Proxy); ok {
			return dnscrypt.NewTransport(p, id, stamp)
		} else {
			err = dnsx.ErrNoDcProxy
		}
	}
	return nil, err
}

func NewDNSCryptRelay(r dnsx.Resolver, stamp string) (dnsx.Transport, error) {
	if tm, err := r.DcProxy(); err == nil {
		if p, ok := tm.(*dnscrypt.Proxy); ok {
			return dnscrypt.NewRelayTransport(p, stamp)
		} else {
			return nil, dnsx.ErrNoDcProxy
		}
	} else {
		return nil, err
	}
}
