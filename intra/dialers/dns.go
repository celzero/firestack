// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dialers

import (
	"context"
	"net/netip"
	"net/url"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

// ResolveFor resolves nom to IPs using transport designated for given uid.
func ResolveFor(nom string, uid string) ([]netip.Addr, error) {
	// ipm.LookupNetIP itself has a short-term cache (ipmapper.go:battl)
	// and since TIDs are specified, the ipmap cache is not used.
	return ipm.LookupNetIPFor(context.Background(), "ip", nom, uid)
}

// Resolve resolves hostname to IP addresses, bypassing cache.
// If resolution fails, entries from the cache are returned, if any.
func Resolve(hostname string, tids ...string) (addrs []netip.Addr, err error) {
	ctx := context.Background()
	// both lookups may return addrs = nil, err = nil
	// (see: ipmapper.go:queryIP2 and protect.NeverResolve)
	// ipm.LookupNetIPxxx itself has a short-term cache (ipmapper.go:battl)
	addrs, err = ipm.LookupNetIPOn(ctx, "ip", hostname, tids...)

	if len(addrs) <= 0 { // check cache
		if addrs = CachedAddrs(hostname); len(addrs) > 0 {
			return addrs, nil
		} // else: no cached addrs
		// even if ipmapper lookups return no addrs, raw ipset
		// may have seed addrs; which when empty, error out.
		err = core.OneErr(err, errNoIps)
	}
	return addrs, err
}

func ResolveForUrl(s string) []netip.Addr {
	u, err := url.Parse(s) // works if s is mere hostname; ex: example.com
	if err != nil {
		return For(s) // fallback on hostOrIP
	}
	return For(u.Hostname())
}

// SampleHosts returns a slice of random hosts, of size n, for the given ipver.
// ipver is one of "v4", "v6", or "" (for both).
func SampleHosts(n uint8, ipver string) []string {
	return ipm.ReverseGetMany(n, ipver)
}

// SampleIPs returns a slice of random IPs, of size n, for the given ipver.
// ipver is one of "v4", "v6", or "" (for both).
func SampleIPs(n uint8, ipver string) []netip.Addr {
	return ipm.GetMany(n, ipver)
}

// ECH returns the ECH config, if any, for the given hostname.
// The query is resolved using IPMapper's default resolver.
func ECH(hostname string) ([]byte, error) {
	q, err := xdns.Question(hostname, dns.TypeHTTPS)
	if err != nil {
		return nil, err
	}
	res, err := ipm.LocalLookup(q)
	if err != nil {
		return nil, err
	}
	ans := &dns.Msg{}
	if err = ans.Unpack(res); err != nil {
		return nil, err
	}
	for _, a := range ans.Answer {
		if rr, ok := a.(*dns.HTTPS); ok {
			for i, kv := range rr.Value {
				if kv.Key() == dns.SVCB_ECHCONFIG {
					if v, ok := rr.Value[i].(*dns.SVCBECHConfig); ok {
						return v.ECH, nil
					} // else: unlikely
				} // else: not ech config
			} // done iter https rr
		} // else: not https rr
	} // done iter answers
	return nil, errNoEch
}

// Query sends a DNS query to the Default DNS and
// returns the answer.
func Query(msg *dns.Msg, tids ...string) (*dns.Msg, error) {
	q, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	r, err := ipm.Lookup(q, protect.MyUid, tids...)
	if err != nil {
		return nil, err
	}

	ans := &dns.Msg{}
	if err = ans.Unpack(r); err != nil {
		return nil, err
	}
	return ans, nil
}

// QueryFor forward a DNS request for uid (if set)
// or to chosen transport, tid (if uid is not set).
func QueryFor(msg *dns.Msg, uid, tid string) (*dns.Msg, error) {
	q, qerr := msg.Pack()
	if qerr != nil {
		return nil, qerr
	}

	// uid may be core.UNKNOWN_UID_STR
	r, rerr := ipm.Lookup(q, uid, tid)

	if rerr != nil {
		return nil, rerr
	}

	ans := &dns.Msg{}
	if aerr := ans.Unpack(r); aerr != nil {
		return nil, aerr
	}
	return ans, nil
}
