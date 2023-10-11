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
	"time"

	"github.com/celzero/firestack/intra/core"
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
	errNoNet  = errors.New("unknown network")

	ttl5s = 5 * time.Second
)

type ipmapper struct {
	id string
	r  dnsx.Resolver
	l  dnsx.DNSListener
	ba *core.Barrier
}

func AddIPMapper(r dnsx.Resolver, l dnsx.DNSListener) {
	m := &ipmapper{dnsx.IpMapper, r, l, core.NewBarrier(ttl5s)}
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

	ssu4 := &dnsx.Summary{
		QName:  host,
		QType:  int(dns.TypeA),
		Status: dnsx.Start,
	}
	ssu6 := &dnsx.Summary{
		QName:  host,
		QType:  int(dns.TypeAAAA),
		Status: dnsx.Start,
	}

	defer func() {
		if err != nil && !errors.Is(err, errNoIps) {
			log.W("ipmapper: lookup(%s), err: %v", host, err)
			ssu4.RCode = dns.RcodeServerFailure
			ssu4.RData = xdns.GetInterestingRData(nil)
			ssu4.Status = dnsx.SendFailed
			ssu4.ID = m.id
			ssu6.RCode = dns.RcodeServerFailure
			ssu6.RData = xdns.GetInterestingRData(nil)
			ssu6.Status = dnsx.SendFailed
			ssu6.ID = m.id
		}
		go m.l.OnResponse(ssu4)
		go m.l.OnResponse(ssu6)
	}()

	// TODO: m.l.OnQuery() to determine transport with suggested_id?
	tr, errtr := m.determineTransport()
	if errtr != nil {
		return nil, errtr
	}

	r4, err4 := tr.Query(dnsx.NetTypeUDP, q4, ssu4)
	r6, err6 := tr.Query(dnsx.NetTypeUDP, q6, ssu6)

	if len(r4) <= 0 && len(r6) <= 0 {
		return nil, errors.Join(errNoAns, err4, err6)
	} else if err4 != nil && err6 != nil {
		return nil, errors.Join(err4, err6)
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

func (m *ipmapper) determineTransport() (tr dnsx.Transport, err error) {
	dtr, derr := m.r.Get(dnsx.Default)
	if derr == nil && dtr.ID() != dnsx.BlockAll {
		tr = dtr
	} else {
		str, serr := m.r.Get(dnsx.System)
		if serr != nil {
			return nil, errors.Join(serr, derr)
		}
		tr = str
	}
	return
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
