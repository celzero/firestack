// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package intra

import (
	"errors"
	"net/netip"
	"strings"

	"github.com/celzero/firestack/intra/dns53"
	"github.com/celzero/firestack/intra/dnscrypt"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/doh"
	"github.com/celzero/firestack/intra/log"
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

func (t *intratunnel) NewDNSCryptProxy(resolvers, relays string) (dnscrypt.Controller, error) {
	var err error
	if t.dnscrypt != nil {
		return nil, errors.New("dnscrypt already configured")
	}
	p := dnscrypt.NewProxy()

	if _, err = p.AddServers(resolvers); err == nil {
		if len(relays) > 0 {
			_, err = p.AddRoutes(relays)
		}
	}
	if err != nil {
		return nil, err
	}

	t.dnscrypt = p

	log.Infof("tun: DNSCrypt set to %s:%s", resolvers, relays)

	// TODO: impl stop/start apis in transport.go?
	p.StartProxy()

	return p, nil
}

func (t *intratunnel) GetDNSCryptProxy() dnscrypt.Controller {
	return t.dnscrypt
}

// NewDoHTransport returns a DNSTransport that connects to the specified DoH server.
// `url` is the URL of a DoH server (no template, POST-only).  If it is nonempty, it
//   overrides `udpdns` and `tcpdns`.
// `ips` is an optional comma-separated list of IP addresses for the server.  (This
//   wrapper is required because gomobile cannot make bindings for []string.)
// `protector` is the socket protector to use for all external network activity.
// `auth` will provide a client certificate if required by the TLS server.
// `listener` will be notified after each DNS query succeeds or fails.
func NewDoHTransport(url string, ips string, auth doh.ClientAuth) (dnsx.Transport, error) {
	split := []string{}
	if len(ips) > 0 {
		split = strings.Split(ips, ",")
	}
	dialer := protect.MakeDialer(nil)
	return doh.NewTransport(url, split, dialer, auth)
}
