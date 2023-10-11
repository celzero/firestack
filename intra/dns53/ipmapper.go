// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dns53

import (
	"context"
	"errors"
	"net/netip"

	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/split"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

var (
	errNoHost = errors.New("no hostname")
	errNoAns  = errors.New("no answer")
	errNoNet  = errors.New("unknown network")
)

type ipmapper struct {
	id string
	r  dnsx.Resolver
}

func AddIPMapper(r dnsx.Resolver) {
	m := &ipmapper{dnsx.IpMapper, r}
	split.Mapper(m)
}

func str2ip(host string) (netip.Addr, error) {
	return netip.ParseAddr(host)
}

func (m *ipmapper) LookupNetIP(ctx context.Context, network, host string) (_ []netip.Addr, err error) {
	if len(host) <= 0 {
		return nil, errNoHost
	}
	// no lookups when host is already an IP
	if ip, err := str2ip(host); err == nil {
		return []netip.Addr{ip}, nil
	}

	var q4, q6 []byte
	var err4, err6 error
	switch network {
	case "ip":
		q4, err4 = dnsmsg(host, dns.TypeA)
		q6, err6 = dnsmsg(host, dns.TypeAAAA)
	case "ip4":
		q4, err4 = dnsmsg(host, dns.TypeA)
	case "ip6":
		q6, err6 = dnsmsg(host, dns.TypeAAAA)
	default:
		return nil, errNoNet
	}

	if err4 != nil || err6 != nil {
		return nil, errors.Join(err4, err6)
	}

	r4, lerr4 := m.r.LocalLookup(q4)
	r6, lerr6 := m.r.LocalLookup(q6)

	if len(r4) <= 0 && len(r6) <= 0 {
		return nil, errors.Join(errNoAns, lerr4, lerr6)
	} else if lerr4 != nil && lerr6 != nil {
		return nil, errors.Join(lerr4, lerr6)
	}

	ips := make([]netip.Addr, 0, len(r4)+len(r6))
	ip4 := addrs(r4)
	ip6 := addrs(r6)
	ips = append(ips, ip4...)
	ips = append(ips, ip6...)
	return ips, nil
}

func addrs(a []byte) []netip.Addr {
	msg := xdns.AsMsg(a)
	if msg == nil {
		return nil
	}
	ips := make([]netip.Addr, 0, len(msg.Answer))
	for _, rr := range msg.Answer {
		switch rr := rr.(type) {
		case *dns.A:
			if ip4, ok := netip.AddrFromSlice(rr.A); ok {
				ips = append(ips, ip4.Unmap())
			}
		case *dns.AAAA:
			if ip6, ok := netip.AddrFromSlice(rr.AAAA); ok {
				ips = append(ips, ip6)
			}
		default:
			log.V("ipmapper: unexpected ans type: %v", rr)
		}
	}
	return ips
}

func dnsmsg(host string, qtype uint16) ([]byte, error) {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
		},
		Question: []dns.Question{
			{
				Name:   dns.Fqdn(host),
				Qtype:  qtype,
				Qclass: dns.ClassINET,
			},
		},
	}
	return msg.Pack()
}
