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
	errNoIps  = errors.New("no ips")
)

type ipmapper struct {
	r dnsx.Resolver
}

func AddIPMapper(r dnsx.Resolver) {
	m := &ipmapper{r}
	split.Mapper(m)
}

func (m *ipmapper) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if len(host) <= 0 {
		return nil, errNoHost
	}

	q4, err4 := query(host, dns.TypeA)
	q6, err6 := query(host, dns.TypeAAAA)
	if err4 != nil || err6 != nil {
		return nil, errors.Join(err4, err6)
	}
	r4, err4 := m.r.Forward(q4)
	r6, err6 := m.r.Forward(q6)
	if len(r4) <= 0 && len(r6) <= 0 {
		return nil, errors.Join(errNoAns, err4, err6)
	}
	ips := make([]netip.Addr, 0, len(r4)+len(r6))
	ip4 := addrs(r4)
	ip6 := addrs(r6)
	ips = append(ips, ip4...)
	ips = append(ips, ip6...)
	if len(ips) <= 0 {
		return nil, errNoIps
	}
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

func query(host string, qtype uint16) ([]byte, error) {
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
