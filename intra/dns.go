// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package intra

import (
	"net"
	"net/netip"
	"strings"

	"github.com/celzero/firestack/intra/dns53"
	"github.com/celzero/firestack/intra/dnscrypt"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/doh"
	"github.com/celzero/firestack/intra/ipn"
)

func NewDNSProxy(t Tunnel, id, ip, port string) (d dnsx.Transport, err error) {
	return dns53.NewTransport(id, ip, port, t.GetProxies())
}

func newSystemDNSProxy(ipp netip.AddrPort) (d dnsx.Transport, err error) {
	return dns53.NewTransportFrom(dnsx.System, ipp, nil)
}

func newBlockAllTransport() (d dnsx.Transport) {
	return dns53.NewGroundedTransport(dnsx.BlockAll)
}

func newDNSCryptTransport(px ipn.Proxies) (p dnsx.TransportMult) {
	p = dnscrypt.DcMult(px)
	return
}

func newMDNSTransport(protos string) (d dnsx.Transport) {
	return dns53.NewMDNSTransport(protos)
}

func NewDefaultDoH(url, ips string) (dnsx.Transport, error) {
	split := []string{}
	if len(ips) > 0 {
		split = strings.Split(ips, ",")
	}
	return doh.NewTransport(dnsx.Default, url, split, nil)
}

func NewProxyDNS(t Tunnel, p ipn.Proxy) (d dnsx.Transport, err error) {
	ipcsv := p.DNS()
	if len(ipcsv) == 0 {
		return nil, dnsx.ErrNoProxyDNS
	}
	ips := []string{}
	if len(ipcsv) > 0 {
		ips = strings.Split(ipcsv, ",")
	}
	ipport, err := netip.ParseAddrPort(ips[0])
	if err != nil {
		ips[0] = net.JoinHostPort(ips[0], dns53.Port)
		ipport, err = netip.ParseAddrPort(ips[0])
	}
	// todo: may be stamp or url
	if err != nil {
		return nil, err
	}
	return dns53.NewTransportFrom(p.ID(), ipport, t.GetProxies())
}

// NewDoHTransport returns a DNSTransport that connects to the specified DoH server.
// `url` is the URL of a DoH server (no template, POST-only).
func NewDoHTransport(t Tunnel, id, url, ips string) (dnsx.Transport, error) {
	split := []string{}
	if len(ips) > 0 {
		split = strings.Split(ips, ",")
	}
	return doh.NewTransport(id, url, split, t.GetProxies())
}

func NewODoHTransport(t Tunnel, id, endpoint, resolver, epips string) (dnsx.Transport, error) {
	split := []string{}
	if len(epips) > 0 {
		split = strings.Split(epips, ",")
	}
	return doh.NewOdohTransport(id, endpoint, resolver, split, t.GetProxies())
}

func NewDoTTransport(t Tunnel, id, url string) (dnsx.Transport, error) {
	return dns53.NewTLSTransport(id, url, t.GetProxies())
}

func NewDNSCryptTransport(t Tunnel, id, stamp string) (d dnsx.Transport, err error) {
	r := t.GetResolver()
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

func NewDNSCryptRelay(t Tunnel, stamp string) (dnsx.Transport, error) {
	r := t.GetResolver()
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
