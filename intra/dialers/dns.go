// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dialers

import (
	"context"
	"net/netip"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/protect/ipmap"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

// ResolveFor resolves nom to IPs,  bypassing cache, using transport
// designated for given uid. If resolution fails, entries from the
// cache are returned, if any.
func ResolveFor(m ipmap.IPMapper, nom string, uid string, tids ...string) ([]netip.Addr, error) {
	// both lookups may return addrs = nil, err = nil
	// (see: ipmapper.go:lookup and protect.NeverResolve)
	// ipm.LookupNetIP itself has a short-term cache (ipmapper.go:battl)
	// and since TIDs are specified, the ipmap cache is not used.
	addrs, err := m.LookupNetIP(context.Background(), "ip", nom, uid, tids...)

	if len(addrs) <= 0 { // check cache
		if addrs = CachedAddrs(nom); len(addrs) > 0 {
			return addrs, nil
		} // else: no cached addrs
		// even if ipmapper lookups return no addrs, raw ipset
		// may have seed addrs; which when empty, error out.
		err = core.OneErr(err, errNoIps)
	} else if uid == protect.MyUid {
		// cache for dialers to use; only for MyUid, not for other uids
		cache(nom, addrs)
	}
	return addrs, err
}

// Resolve is like ResolverFor but with uid = protect.MyUid.
// See: [For] to get cached addrs and optionally resolve, and [CachedAddrs] to only get cached addrs.
func Resolve(hostname string, tids ...string) (addrs []netip.Addr, err error) {
	return ResolveFor(ipm, hostname, protect.MyUid, tids...)
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
	q, err := xdns.QuestionMsg(hostname, dns.TypeHTTPS)
	if err != nil {
		return nil, err
	}
	// bound the lookup: a slow or absent resolver must not stall callers
	// (transport constructors & first-query paths) for the full resolver
	// timeout; most public resolvers publish no ECH config anyway.
	const echTimeout = 25 * time.Second
	ans, ok := core.Grx("dialers.ech."+hostname, func(_ context.Context) (*dns.Msg, error) {
		return ipm.Lookup(q, protect.MyUid)
	}, echTimeout)
	if !ok {
		return nil, errEchQTimeout
	}
	if ans == nil {
		return nil, errNoEch
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

// Query is like [QueryFor] but with uid set to [protect.MyUid].
// m is the IPMapper implementation to query with, never nil.
func Query(m ipmap.IPMapper, msg *dns.Msg, tids ...string) (*dns.Msg, error) {
	a, err := QueryFor(m, msg, protect.MyUid, tids...)
	if err == nil {
		cache2(a)
	}
	return a, err
}

// QueryFor forward a DNS request for tid (if set) attributed to uid,
// or to transport chosen for uid, which may be core.UNKNOWN_UID_STR.
// QueryFor allows specifying both uid and tids. QueryFor, unlike
// ResolveFor is not just for A/AAAA records but for any record type.
// It bypasses the cache and returns the answer from tid or
// from transport designated for uid.
// m is the IPMapper implementation to query with, never nil.
func QueryFor(m ipmap.IPMapper, msg *dns.Msg, uid string, tids ...string) (*dns.Msg, error) {
	return m.Lookup(msg, uid, tids...)
}
