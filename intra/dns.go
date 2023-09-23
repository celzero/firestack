// Copyright (c) 2022 RethinkDNS and its authors.
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
	"github.com/celzero/firestack/intra/ipn"
)

func NewDNSProxy(id, ip, port string, px ipn.Proxies) (d dnsx.Transport, err error) {
	return dns53.NewTransport(id, ip, port, px)
}

func newSystemDNSProxy(ipp netip.AddrPort) (d dnsx.Transport, err error) {
	return dns53.NewTransportFrom(dnsx.System, ipp)
}

func newBlockAllTransport() (d dnsx.Transport) {
	return dns53.NewGroundedTransport(dnsx.BlockAll)
}

func newDNSCryptTransport(px ipn.Proxies) (p dnsx.TransportMult) {
	p = dnscrypt.DcMult(px)
	return
}

func NewGroundedTransport(id string) (d dnsx.Transport) {
	return dns53.NewGroundedTransport(id)
}

func NewMDNSTransport(protos string) (d dnsx.Transport) {
	return dns53.NewMDNSTransport(protos)
}

// NewDoHTransport returns a DNSTransport that connects to the specified DoH server.
// `url` is the URL of a DoH server (no template, POST-only).
func NewDoHTransport(id, url, ips string, px ipn.Proxies) (dnsx.Transport, error) {
	split := []string{}
	if len(ips) > 0 {
		split = strings.Split(ips, ",")
	}
	return doh.NewTransport(id, url, split, px)
}

func NewODoHTransport(id, proxy, resolver, proxyips string, px ipn.Proxies) (dnsx.Transport, error) {
	split := []string{}
	if len(proxyips) > 0 {
		split = strings.Split(proxyips, ",")
	}
	return doh.NewOdohTransport(id, proxy, resolver, split, px)
}

func NewDoTTransport(id, url string, px ipn.Proxies) (dnsx.Transport, error) {
	return dns53.NewTLSTransport(id, url, px)
}

func NewDNSCryptTransport(id, stamp string, r dnsx.Resolver) (d dnsx.Transport, err error) {
	var tm dnsx.TransportMult
	if tm, err = r.GetMult(dnsx.DcProxy); err == nil {
		// todo: unexpose DcMulti, cast to TransportMult
		if p, ok := tm.(*dnscrypt.DcMulti); ok {
			return dnscrypt.NewTransport(p, id, stamp)
		} else {
			err = dnsx.ErrNoDcProxy
		}
	}
	return nil, err
}

func NewDNSCryptRelay(r dnsx.Resolver, stamp string) (dnsx.Transport, error) {
	if tm, err := r.GetMult(dnsx.DcProxy); err == nil {
		if p, ok := tm.(*dnscrypt.DcMulti); ok {
			return dnscrypt.NewRelayTransport(p, stamp)
		} else {
			return nil, dnsx.ErrNoDcProxy
		}
	} else {
		return nil, err
	}
}
