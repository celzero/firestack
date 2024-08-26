// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dialers

import (
	"context"
	"net/netip"

	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

// Resolve resolves hostname to IP addresses, bypassing cache.
// If resolution fails, entries from the cache are returned, if any.
func Resolve(hostname string) ([]netip.Addr, error) {
	// ipm.LookupNetIP itself has a short-term cache (ipmapper.go:battl)
	addrs, err := ipm.LookupNetIP(context.Background(), "ip", hostname)
	if len(addrs) <= 0 { // check cache
		if addrs = ipm.GetAny(hostname).Addrs(); len(addrs) > 0 {
			return addrs, nil
		} // else: no cached addrs
	}
	return addrs, err
}

// ECH returns the ECH config, if any, for the given hostname.
func ECH(hostname string) ([]byte, error) {
	q, err := xdns.Question(hostname, dns.TypeHTTPS)
	if err != nil {
		return nil, err
	}
	res, err := ipm.Lookup(q)
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
					}
				}
			}
		}
	}
	return nil, errNoEch
}

// Query sends a DNS query to the Default DNS and
// returns the answer.
func Query(msg *dns.Msg) (*dns.Msg, error) {
	q, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	r, err := ipm.Lookup(q)
	if err != nil {
		return nil, err
	}

	ans := &dns.Msg{}
	if err = ans.Unpack(r); err != nil {
		return nil, err
	}
	return ans, nil
}
