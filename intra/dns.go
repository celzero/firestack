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
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/xdns"
)

func addIPMapper(r dnsx.Resolver) {
	dns53.AddIPMapper(r)
}

func AddDNSProxy(t Tunnel, id, ip, port string) error {
	r := t.GetResolver()
	p := t.GetProxies()
	g := t.getBridge()
	if dns, err := dns53.NewTransport(id, ip, port, p, g); err != nil {
		return err
	} else {
		return addDNSTransport(r, dns)
	}
}

func newSystemDNSProxy(g Bridge, p ipn.Proxies, ipp netip.AddrPort) (d dnsx.Transport, err error) {
	return dns53.NewTransportFrom(dnsx.System, ipp, p, g)
}

func SetSystemDNS(t Tunnel, ippcsv string) int {
	r := t.GetResolver()
	g := t.getBridge()
	d := r.RemoveSystemDNS()
	p := t.GetProxies()

	ipports := strings.Split(ippcsv, ",")
	if len(ipports) <= 0 {
		log.I("dns: removed %d system dns(es)", d)
		return 0
	}
	n := 0
	for _, ipport := range ipports {
		if ipp, err := xdns.DnsIPPort(ipport); err == nil {
			if sdns, err := newSystemDNSProxy(g, p, ipp); err == nil {
				r.AddSystemDNS(sdns)
				n += 1
			} else {
				log.W("dns: new system dns %s; err(%v)", ipport, err)
			}
		} else {
			log.W("dns: invalid system dns %s; err(%v)", ipport, err)
		}
	}
	log.I("dns: new %d system dns(es) from %s", n, ipports)
	return n
}

func newGoosTransport(g Bridge, p ipn.Proxies) (d dnsx.Transport) {
	d, _ = dns53.NewGoosTransport(p, g)
	return
}

func newBlockAllTransport() (d dnsx.Transport) {
	return dns53.NewGroundedTransport(dnsx.BlockAll)
}

func newDNSCryptTransport(px ipn.Proxies, bdg Bridge) (p dnsx.TransportMult) {
	p = dnscrypt.NewDcMult(px, bdg)
	return
}

func newMDNSTransport(protos string) (d dnsx.Transport) {
	return dns53.NewMDNSTransport(protos)
}

func AddDefaultTransport(t Tunnel, typ, ippOrUrl, ips string) error {
	r := t.GetResolver()
	tr, err := r.Get(dnsx.Default)
	if err != nil {
		return err
	}
	defaultransport, ok := tr.(DefaultDNS)
	if !ok {
		return dnsx.ErrNotDefaultTransport
	}
	return defaultransport.reinit(typ, ippOrUrl, ips)
}

func AddProxyDNS(t Tunnel, p ipn.Proxy) error {
	pxr := t.GetProxies()
	r := t.GetResolver()
	g := t.getBridge()
	ipcsv := p.DNS()
	if len(ipcsv) == 0 {
		return dnsx.ErrNoProxyDNS
	}
	ips := []string{}
	if len(ipcsv) > 0 {
		ips = strings.Split(ipcsv, ",")
	}
	ipport, err := xdns.DnsIPPort(ips[0])
	// todo: may be stamp or url
	if err != nil {
		return err
	}
	// register transport with the resolver
	if dns, err := dns53.NewTransportFrom(p.ID(), ipport, pxr, g); err != nil {
		return err
	} else {
		return addDNSTransport(r, dns)
	}
}

// SetDoHTransport returns a DNSTransport that connects to the specified DoH server.
// `url` is the URL of a DoH server (no template, POST-only).
func AddDoHTransport(t Tunnel, id, url, ips string) error {
	pxr := t.GetProxies()
	r := t.GetResolver()
	g := t.getBridge()
	split := []string{}
	if len(ips) > 0 {
		split = strings.Split(ips, ",")
	}
	if dns, err := doh.NewTransport(id, url, split, pxr, g); err != nil {
		return err
	} else {
		return addDNSTransport(r, dns)
	}
}

func AddODoHTransport(t Tunnel, id, endpoint, resolver, epips string) error {
	pxr := t.GetProxies()
	r := t.GetResolver()
	g := t.getBridge()
	split := []string{}
	if len(epips) > 0 {
		split = strings.Split(epips, ",")
	}
	if dns, err := doh.NewOdohTransport(id, endpoint, resolver, split, pxr, g); err != nil {
		return err
	} else {
		return addDNSTransport(r, dns)
	}
}

func AddDoTTransport(t Tunnel, id, url, ips string) error {
	pxr := t.GetProxies()
	r := t.GetResolver()
	g := t.getBridge()
	split := []string{}
	if len(ips) > 0 {
		split = strings.Split(ips, ",")
	}
	if dns, err := dns53.NewTLSTransport(id, url, split, pxr, g); err != nil {
		return err
	} else {
		return addDNSTransport(r, dns)
	}
}

func AddDNSCryptTransport(t Tunnel, id, stamp string) (err error) {
	r := t.GetResolver()

	var tm dnsx.TransportMult
	if tm, err = r.GetMult(dnsx.DcProxy); err != nil {
		return err
	}
	// todo: unexpose DcMulti, cast to TransportMult
	if p, ok := tm.(*dnscrypt.DcMulti); ok {
		if dns, err := dnscrypt.NewTransport(p, id, stamp); err != nil {
			return err
		} else {
			return addDNSTransport(r, dns)
		}
	} else {
		return dnsx.ErrNoDcProxy
	}
}

func AddDNSCryptRelay(t Tunnel, stamp string) error {
	var tm dnsx.TransportMult
	var err error
	r := t.GetResolver()
	if tm, err = r.GetMult(dnsx.DcProxy); err != nil {
		return err
	}
	if p, ok := tm.(*dnscrypt.DcMulti); ok {
		// relay transports are not added to the resolver
		return dnscrypt.AddRelayTransport(p, stamp)
	} else {
		return dnsx.ErrNoDcProxy
	}

}

func addDNSTransport(r dnsx.Resolver, t dnsx.Transport) error {
	if !r.Add(t) {
		return dnsx.ErrAddFailed
	}
	return nil
}
