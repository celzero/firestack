// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package intra

import (
	"context"
	"strings"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dns53"
	"github.com/celzero/firestack/intra/dnscrypt"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/doh"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/xdns"
)

func addIPMapper(ctx context.Context, r dnsx.Resolver, protos string) {
	dns53.AddIPMapper(r, protos, false /*clear cache*/)
	context.AfterFunc(ctx, func() {
		dns53.AddIPMapper(nil, "", true /*clear cache*/)
	})
}

// AddDNSProxy creates and adds a DNS53 transport to the tunnel's resolver.
func AddDNSProxy(t Tunnel, id, ip, port *x.Gostr) error {
	p, perr := t.internalProxies()
	r, rerr := t.internalResolver()
	if rerr != nil || perr != nil {
		return core.JoinErr(rerr, perr)
	}
	ctx := t.internalCtx()
	if dns, err := dns53.NewTransport(ctx, id.V(), ip.V(), port.V(), p); err != nil {
		return err
	} else {
		return addDNSTransport(r, dns)
	}
}

func newSystemDNSProxy(ctx context.Context, p ipn.ProxyProvider, ipcsv string) (d dnsx.Transport, err error) {
	specialHostname := protect.UidSystem // never resolved by ipmap:LookupNetIP
	return dns53.NewTransportFromHostname(ctx, dnsx.System, specialHostname, ipcsv, p)
}

// SetSystemDNS creates and adds a DNS53 transport of the specified IP addresses.
func SetSystemDNS(t Tunnel, ipcsvx *x.Gostr) error {
	r, rerr := t.internalResolver()
	p, perr := t.internalProxies()
	ctx := t.internalCtx()
	ipcsv := ipcsvx.V()
	n := len(ipcsv)
	if r == nil || p == nil {
		log.W("dns: cannot set system dns; n: %d, errs: %v %v", n, rerr, perr)
		return core.JoinErr(dnsx.ErrAddFailed, rerr, perr)
	}

	if n <= 0 {
		log.W("dns: no system dns IPs to set; fallback to Goos")
		r.Remove(x.StrOf(dnsx.System))
		return nil
	}

	// if the ipcsv is localhost, use loopback addresses.
	// this is the case if kotlin-land is unable to determine
	// DNS servers. This is equivalent to using x.Goos Transport.
	if strings.HasPrefix(ipcsv, "localhost") {
		ipcsv = localip4 + "," + localip6
	}

	var ok bool
	if sdns, err := newSystemDNSProxy(ctx, p, ipcsv); err == nil {
		ok = r.Add(sdns)
	} else {
		return err
	}

	log.I("dns: new system dns from %s; ok? %t", ipcsv, ok)
	return nil
}

func newGoosTransport(ctx context.Context, px ipn.ProxyProvider) (d dnsx.Transport) {
	d, _ = dns53.NewGoosTransport(ctx, px)
	return
}

func newBlockAllTransport() dnsx.Transport {
	return dns53.NewGroundedTransport(dnsx.BlockAll)
}

func newFixedTransport() dnsx.Transport {
	return dns53.NewErrorerTransport(dnsx.Fixed)
}

func newPlusTransport(ctx context.Context, r dnsx.Resolver) dnsx.Transport {
	return dnsx.NewPlusTransport(ctx, r /*and zero transports*/)
}

func newDNSCryptTransport(ctx context.Context, px ipn.ProxyProvider, bdg Bridge) (p dnsx.TransportMult) {
	p = dnscrypt.NewDcMult(ctx, px, bdg)
	return
}

func newMDNSTransport(ctx context.Context, protos string, px ipn.ProxyProvider) (d dnsx.Transport) {
	return dns53.NewMDNSTransport(ctx, protos, px)
}

// AddDefaultTransport adds a special default transport to the tunnel's resolver
// It may be either a DoH or a DNS53 transport.
func AddDefaultTransport(t Tunnel, typ, ippOrUrl, ips *x.Gostr) error {
	r, rerr := t.GetResolver()
	if rerr != nil {
		return rerr
	}
	tr, err := r.Get(x.StrOf(dnsx.Default))
	if err != nil {
		return err
	}
	defaultransport, ok := tr.(DefaultDNS)
	if !ok {
		return dnsx.ErrNotDefaultTransport
	}
	// on error, default transport remains unchanged
	return defaultransport.reinit(typ.V(), ippOrUrl.V(), ips.V())
}

// AddProxyDNS creates and adds a DNS53 transport as defined in Proxy's configuration.
func AddProxyDNS(t Tunnel, p x.Proxy) error {
	pxr, perr := t.internalProxies()
	r, rerr := t.internalResolver()
	if rerr != nil || perr != nil {
		return core.JoinErr(rerr, perr)
	}
	pid := p.ID().V()
	ctx := t.internalCtx()
	ipOrHostCsv := p.DNS().V() // may return csv(host:port), csv(ip:port), csv(ips), csv(host)
	if len(ipOrHostCsv) == 0 {
		log.W("dns: no proxy dns for %s @ %s", pid, p.GetAddr())
		return dnsx.ErrNoProxyDNS
	}
	ipsOrHost := strings.Split(ipOrHostCsv, ",")
	if len(ipsOrHost) == 0 {
		log.W("dns: no dns for %s @ %s", pid, p.GetAddr())
		return dnsx.ErrNoProxyDNS
	}
	first := ipsOrHost[0]
	ipport, err := xdns.DnsIPPort(first)
	hostOrHostport := first // could be multiple hostnames or host:ports, but choose the first
	if err != nil {         // use hostname
		if dns, err := dns53.NewTransportFromHostname(ctx, pid, hostOrHostport, "", pxr); err != nil {
			return err
		} else {
			return addDNSTransport(r, dns)
		}
		// use ipports; register with same id as the proxy p
	} else if dns, err := dns53.NewTransportFrom(ctx, pid, ipport, pxr); err != nil {
		return err
	} else {
		return addDNSTransport(r, dns)
	}
}

// AddDoHTransport creates and adds a Transport that connects to the specified DoH server.
// `url` is the URL of a DoH server (no template, POST-only).
func AddDoHTransport(t Tunnel, id, url, ipcsv *x.Gostr) error {
	pxr, perr := t.internalProxies()
	r, rerr := t.internalResolver()
	if rerr != nil || perr != nil {
		return core.JoinErr(rerr, perr)
	}
	ips := ipcsv.V()
	ctx := t.internalCtx()
	split := []string{}
	if len(ips) > 0 {
		split = strings.Split(ips, ",")
	}
	if dns, err := doh.NewTransport(ctx, id.V(), url.V(), split, pxr); err != nil {
		return err
	} else {
		return addDNSTransport(r, dns)
	}
}

// AddODoHTransport creates and adds a Transport that connects to the specified ODoH server.
// `endpoint` is the entry / proxy for the ODoH server, `resolver` is the URL of the target ODoH server.
func AddODoHTransport(t Tunnel, id, endpoint, resolver, epipcsv *x.Gostr) error {
	pxr, perr := t.internalProxies()
	r, rerr := t.internalResolver()
	if rerr != nil || perr != nil {
		return core.JoinErr(rerr, perr)
	}
	epips := epipcsv.V()
	ctx := t.internalCtx()
	split := []string{}
	if len(epips) > 0 {
		split = strings.Split(epips, ",")
	}
	if dns, err := doh.NewOdohTransport(ctx, id.V(), endpoint.V(), resolver.V(), split, pxr); err != nil {
		return err
	} else {
		return addDNSTransport(r, dns)
	}
}

// AddDoTTransport creates and adds a Transport that connects to the specified DoT server.
func AddDoTTransport(t Tunnel, id, url, ipcsv *x.Gostr) error {
	pxr, perr := t.internalProxies()
	r, rerr := t.internalResolver()
	if rerr != nil || perr != nil {
		return core.JoinErr(rerr, perr)
	}
	ctx := t.internalCtx()
	split := []string{}
	ips := ipcsv.V()
	if len(ips) > 0 {
		split = strings.Split(ips, ",")
	}
	if dns, err := dns53.NewTLSTransport(ctx, id.V(), url.V(), split, pxr); err != nil {
		return err
	} else {
		return addDNSTransport(r, dns)
	}
}

// AddDNSCryptTransport creates and adds a DNSCrypt transport to the tunnel's resolver.
func AddDNSCryptTransport(t Tunnel, id, stamp *x.Gostr) (err error) {
	r, rerr := t.internalResolver()
	if rerr != nil {
		return rerr
	}

	var tm dnsx.TransportMult
	if tm, err = r.GetMultInternal(dnsx.DcProxy); err != nil {
		return err
	}
	// todo: unexpose DcMulti, cast to TransportMult
	if p, ok := tm.(*dnscrypt.DcMulti); ok {
		if dns, err := dnscrypt.AddTransport(p, id.V(), stamp.V()); err != nil {
			return err
		} else {
			return addDNSTransport(r, dns)
		}
	} else {
		return dnsx.ErrNoDcProxy
	}
}

// AddDNSCryptRelay adds a DNSCrypt relay transport to the tunnel's resolver.
func AddDNSCryptRelay(t Tunnel, stamp *x.Gostr) error {
	var tm dnsx.TransportMult
	var err error
	r, rerr := t.internalResolver()
	if rerr != nil {
		return rerr
	}
	if tm, err = r.GetMultInternal(dnsx.DcProxy); err != nil {
		return err
	}
	if p, ok := tm.(*dnscrypt.DcMulti); ok {
		// relay transports are not added to the resolver
		return dnscrypt.AddRelayTransport(p, stamp.V())
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
