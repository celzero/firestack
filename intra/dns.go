// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package intra

import (
	"context"
	"strconv"
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
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/xdns"
)

func addIPMapper(ctx context.Context, r dnsx.Resolver, protos string) {
	dns53.AddIPMapper(r, protos, false /*clear cache*/)
	context.AfterFunc(ctx, func() {
		dns53.AddIPMapper(nil, "", true /*clear cache*/)
	})
}

// AddDNSProxy creates and adds a DNS53 transport to the tunnel's resolver.
func AddDNSProxy(t Tunnel, id, ippcsv string) error {
	p, perr := t.internalProxies()
	r, rerr := t.internalResolver()
	if rerr != nil || perr != nil {
		return core.JoinErr(rerr, perr)
	}
	ctx := t.internalCtx()
	specialHostname := protect.HostlessPrefix + id
	if dns, err := dns53.NewTransportFromHostname(ctx, id, specialHostname, ippcsv, p); err != nil {
		return err
	} else {
		return addDNSTransport(r, dns)
	}
}

func newSystemDNSProxy(ctx context.Context, p ipn.ProxyProvider, ipcsv string) (d dnsx.Transport, err error) {
	specialHostname := protect.Systemhost // never resolved by ipmap:LookupNetIP
	return dns53.NewTransportFromHostname(ctx, dnsx.System, specialHostname, ipcsv, p)
}

// SetSystemDNS creates and adds a DNS53 transport of the specified IP addresses.
func SetSystemDNS(t Tunnel, ipcsvx string) error {
	r, rerr := t.internalResolver()
	p, perr := t.internalProxies()
	ctx := t.internalCtx()
	ipcsv := ipcsvx
	n := len(ipcsv)
	if r == nil || p == nil {
		log.W("dns: cannot set system dns; n: %d, errs: %v %v", n, rerr, perr)
		return core.JoinErr(dnsx.ErrAddFailed, rerr, perr)
	}

	if n <= 0 {
		log.W("dns: no system dns IPs to set; fallback to Goos")
		r.Remove(dnsx.System)
		return nil
	}

	// if the ipcsv is localhost, use loopback addresses.
	// this is the case if kotlin-land is unable to determine
	// DNS servers. This is equivalent to using x.Goos Transport.
	if strings.HasPrefix(ipcsv, "localhost") {
		if settings.Debug {
			log.D("dns: system dns is localhost, using loopback")
		}
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

func newMDNSTransport(ctx context.Context, protos string, px ipn.ProxyProvider) (d dnsx.MDNSTransport) {
	return dns53.NewMDNSTransport(ctx, protos, px)
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
func AddProxyDNS(t Tunnel, p x.Proxy) error {
	pxr, perr := t.internalProxies()
	r, rerr := t.internalResolver()
	if rerr != nil || perr != nil {
		return core.JoinErr(rerr, perr)
	}
	pid := p.ID()
	ctx := t.internalCtx()
	// TODO: create dns53.NewTransportForProxy() which is self-healing and
	// uses updated DNS addresses if p.DNS() has changed/updated
	ipOrHostCsv := p.DNS() // may return csv(host:port), csv(ip:port), csv(ips), csv(host)
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
		if dns, err := dns53.NewTransportFromHostname(ctx, pid, hostOrHostport, "" /*ip or ip:port csv*/, pxr); err != nil {
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
func AddDoHTransport(t Tunnel, id, url, ipcsv string) error {
	pxr, perr := t.internalProxies()
	r, rerr := t.internalResolver()
	if rerr != nil || perr != nil {
		return core.JoinErr(rerr, perr)
	}
	ips := ipcsv
	ctx := t.internalCtx()
	split := []string{}
	if len(ips) > 0 {
		split = strings.Split(ips, ",")
	}
	if dns, err := doh.NewTransport(ctx, id, url, split, pxr); err != nil {
		return err
	} else {
		return addDNSTransport(r, dns)
	}
}

// AddODoHTransport creates and adds a Transport that connects to the specified ODoH server.
// `endpoint` is the entry / proxy for the ODoH server, `resolver` is the URL of the target ODoH server.
func AddODoHTransport(t Tunnel, id, endpoint, resolver, epipcsv string) error {
	pxr, perr := t.internalProxies()
	r, rerr := t.internalResolver()
	if rerr != nil || perr != nil {
		return core.JoinErr(rerr, perr)
	}
	epips := epipcsv
	ctx := t.internalCtx()
	split := []string{}
	if len(epips) > 0 {
		split = strings.Split(epips, ",")
	}
	if dns, err := doh.NewOdohTransport(ctx, id, endpoint, resolver, split, pxr); err != nil {
		return err
	} else {
		return addDNSTransport(r, dns)
	}
}

// AddDoTTransport creates and adds a Transport that connects to the specified DoT server.
func AddDoTTransport(t Tunnel, id, url, ipcsv string) error {
	pxr, perr := t.internalProxies()
	r, rerr := t.internalResolver()
	if rerr != nil || perr != nil {
		return core.JoinErr(rerr, perr)
	}
	ctx := t.internalCtx()
	split := []string{}
	ips := ipcsv
	if len(ips) > 0 {
		split = strings.Split(ips, ",")
	}
	if dns, err := dns53.NewTLSTransport(ctx, id, url, split, pxr); err != nil {
		return err
	} else {
		return addDNSTransport(r, dns)
	}
}

// AddDNSCryptTransport creates and adds a DNSCrypt transport to the tunnel's resolver.
func AddDNSCryptTransport(t Tunnel, id, stamp string) (err error) {
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
		// add to both DcMulti and Resolver
		if dns, err := dnscrypt.AddTransport(p, id, stamp); err != nil {
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
	r, rerr := t.internalResolver()
	if rerr != nil {
		return rerr
	}
	if tm, err = r.GetMultInternal(dnsx.DcProxy); err != nil {
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

func csv2ssv(csv string) string {
	return strings.ReplaceAll(csv, ",", ";")
}

func fetchDNSInfo(r dnsx.Resolver, id string) string {
	if tr, rerr := r.GetInternal(id); rerr == nil {
		tid := tr.ID()

		if tid != id {
			// replace tr with the actual transport, if it is TransportMult
			// with one or more internal/hidden away transports.
			var mtr dnsx.TransportMult
			var err error
			if mtr, err = r.GetMultInternal(tid); err == nil {
				tr, err = mtr.GetInternal(id)
			}
			if tr == nil {
				return id + " <x?x> " + err.Error()
			}
		}

		var sb strings.Builder
		if tid != id {
			sb.WriteString(id + " <<?>> " + tid)
		} else {
			sb.WriteString(id)
		}
		sb.WriteString(":")
		sb.WriteString(tr.GetAddr())
		sb.WriteString("[")
		sb.WriteString(tr.Type())
		sb.WriteString("/")
		sb.WriteString(dnsx.Status2Str(tr.Status()))
		sb.WriteString("/")
		sb.WriteString(strconv.FormatInt(tr.P50(), 10))
		sb.WriteString("ms] ")
		for _, ipp := range tr.IPPorts() {
			if ipp.IsValid() {
				sb.WriteString(ipp.Addr().String())
				sb.WriteString(";")
			}
		}
		return sb.String()
	} else {
		return id + " <<?>> " + rerr.Error()
	}
}
