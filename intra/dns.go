// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package intra

import (
	"errors"
	"strings"

	"github.com/celzero/firestack/intra/dns53"
	"github.com/celzero/firestack/intra/dnscrypt"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/doh"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/xdns"
)

func addIPMapper(r dnsx.Resolver) {
	dns53.AddIPMapper(r)
}

// AddDNSProxy creates and adds a DNS53 transport to the tunnel's resolver.
func AddDNSProxy(t Tunnel, id, ip, port string) error {
	p, perr := t.GetProxies()
	r, rerr := t.GetResolver()
	if rerr != nil || perr != nil {
		return errors.Join(rerr, perr)
	}
	g := t.getBridge()
	if dns, err := dns53.NewTransport(id, ip, port, p, g); err != nil {
		return err
	} else {
		return addDNSTransport(r, dns)
	}
}

func newSystemDNSProxy(g Bridge, p ipn.Proxies, ipcsv string) (d dnsx.Transport, err error) {
	specialHostname := protect.UidSystem // never resolved by ipmap:LookupNetIP
	return dns53.NewTransportFromHostname(dnsx.System, specialHostname, ipcsv, p, g)
}

// SetSystemDNS creates and adds a DNS53 transport of the specified IP addresses.
func SetSystemDNS(t Tunnel, ipcsv string) int {
	r, rerr := t.GetResolver()
	p, perr := t.GetProxies()
	g := t.getBridge()
	if r == nil || p == nil {
		log.W("dns: cannot set system dns: %v %v", rerr, perr)
		return 0
	}

	// remove all system dns transports
	c := r.RemoveSystemDNS()

	if len(ipcsv) <= 0 {
		log.I("dns: removed %d system dns(es)", c)
		return 0
	}

	n := 0

	if sdns, err := newSystemDNSProxy(g, p, ipcsv); err == nil {
		r.AddSystemDNS(sdns)
		n++
	}

	log.I("dns: new %d system dns(es) from %s", n, ipcsv)
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

// AddDefaultTransport adds a special default transport to the tunnel's resolver
// It may be either a DoH or a DNS53 transport.
func AddDefaultTransport(t Tunnel, typ, ippOrUrl, ips string) error {
	r, rerr := t.GetResolver()
	if rerr != nil {
		return rerr
	}
	tr, err := r.Get(dnsx.Default)
	if err != nil {
		return err
	}
	defaultransport, ok := tr.(DefaultDNS)
	if !ok {
		return dnsx.ErrNotDefaultTransport
	}
	// on error, default transport remains unchanged
	return defaultransport.reinit(typ, ippOrUrl, ips)
}

// AddProxyDNS creates and adds a DNS53 transport as defined in Proxy's configuration.
func AddProxyDNS(t Tunnel, p ipn.Proxy) error {
	pxr, perr := t.GetProxies()
	r, rerr := t.GetResolver()
	if rerr != nil || perr != nil {
		return errors.Join(rerr, perr)
	}
	g := t.getBridge()
	ipOrHostCsv := p.DNS()
	if len(ipOrHostCsv) == 0 {
		return dnsx.ErrNoProxyDNS
	}
	ipsOrHost := []string{}
	if len(ipOrHostCsv) > 0 {
		ipsOrHost = strings.Split(ipOrHostCsv, ",")
	}
	if len(ipsOrHost) == 0 {
		return dnsx.ErrNoProxyDNS
	}
	ipport, err := xdns.DnsIPPort(ipsOrHost[0])
	hostname := ipsOrHost[0] // could be multiple hostnames, but choose the first
	if err != nil {          // use hostname
		if dns, err := dns53.NewTransportFromHostname(p.ID(), hostname, "", pxr, g); err != nil {
			return err
		} else {
			return addDNSTransport(r, dns)
		}
	}
	// register transport with the resolver
	if dns, err := dns53.NewTransportFrom(p.ID(), ipport, pxr, g); err != nil {
		return err
	} else {
		return addDNSTransport(r, dns)
	}
}

// AddDoHTransport creates and adds a Transport that connects to the specified DoH server.
// `url` is the URL of a DoH server (no template, POST-only).
func AddDoHTransport(t Tunnel, id, url, ips string) error {
	pxr, perr := t.GetProxies()
	r, rerr := t.GetResolver()
	if rerr != nil || perr != nil {
		return errors.Join(rerr, perr)
	}
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

// AddODoHTransport creates and adds a Transport that connects to the specified ODoH server.
// `endpoint` is the entry / proxy for the ODoH server, `resolver` is the URL of the target ODoH server.
func AddODoHTransport(t Tunnel, id, endpoint, resolver, epips string) error {
	pxr, perr := t.GetProxies()
	r, rerr := t.GetResolver()
	if rerr != nil || perr != nil {
		return errors.Join(rerr, perr)
	}
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

// AddDoTTransport creates and adds a Transport that connects to the specified DoT server.
func AddDoTTransport(t Tunnel, id, url, ips string) error {
	pxr, perr := t.GetProxies()
	r, rerr := t.GetResolver()
	if rerr != nil || perr != nil {
		return errors.Join(rerr, perr)
	}
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

// AddDNSCryptTransport creates and adds a DNSCrypt transport to the tunnel's resolver.
func AddDNSCryptTransport(t Tunnel, id, stamp string) (err error) {
	r, rerr := t.GetResolver()
	if rerr != nil {
		return rerr
	}

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

// AddDNSCryptRelay adds a DNSCrypt relay transport to the tunnel's resolver.
func AddDNSCryptRelay(t Tunnel, stamp string) error {
	var tm dnsx.TransportMult
	var err error
	r, rerr := t.GetResolver()
	if rerr != nil {
		return rerr
	}
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
