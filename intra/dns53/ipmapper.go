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
	"strings"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

const battl = 5 * time.Second

var (
	errNoHost = errors.New("no hostname")
	errNoAns  = errors.New("no answer")
	errNoNet  = errors.New("unknown network")

	loopback4 = netip.AddrFrom4([4]byte{127, 0, 0, 1})
	loopback6 = netip.IPv6Loopback()
)

type ipmapper struct {
	id string
	r  dnsx.Resolver
	ba core.Barrier
}

func AddIPMapper(r dnsx.Resolver) {
	m := &ipmapper{dnsx.IpMapper, r, *core.NewBarrier(battl)}
	dialers.Mapper(m)
}

func str2ip(host string) (netip.Addr, error) {
	return netip.ParseAddr(host)
}

func (m *ipmapper) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if len(host) <= 0 {
		return nil, errNoHost
	}
	if host == protect.UidSelf { // represents system resolver with seeded ips
		return nil, nil
	}
	if host == "localhost" || host == "localhost." {
		return []netip.Addr{loopback4, loopback6}, nil
	}
	// no lookups when host is already an IP
	if ip, err := str2ip(host); err == nil {
		log.V("ipmapper: lookup: no-op; host %s is ipaddr", host)
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
		errs := errors.Join(err4, err6)
		log.E("ipmapper: lookup: query err %v", errs)
		return nil, errs
	}

	val4, _ := m.ba.Do(key(host, "ip4"), func() (any, error) {
		return m.r.LocalLookup(q4)
	})
	val6, _ := m.ba.Do(key(host, "ip6"), func() (any, error) {
		return m.r.LocalLookup(q6)
	})

	r4, _ := val4.Val.([]byte)
	r6, _ := val6.Val.([]byte)

	lerr4 := val4.Err
	lerr6 := val6.Err

	if len(r4) <= 0 && len(r6) <= 0 {
		errs := errors.Join(errNoAns, lerr4, lerr6)
		log.E("ipmapper: lookup: no answers for %s, err %v", host, errs)
		return nil, errs
	} else if lerr4 != nil && lerr6 != nil {
		errs := errors.Join(lerr4, lerr6)
		log.E("ipmapper: lookup: %s: err %v", host, errs)
		return nil, errs
	}

	ips := make([]netip.Addr, 0, len(r4)+len(r6))
	ip4 := m.undoAlg(addrs(r4))
	ip6 := m.undoAlg(addrs(r6))
	ips = append(ips, ip4...)
	ips = append(ips, ip6...)

	log.D("ipmapper: host %s => ips %s; err4: %v, err6: %v", host, ips, lerr4, lerr6)
	return ips, nil
}

func (m *ipmapper) undoAlg(ip64 []netip.Addr) []netip.Addr {
	realips := make([]string, 0, len(ip64))
	ips := make([]netip.Addr, 0, len(ip64))
	for _, x := range ip64 {
		var csv string
		if gw := m.r.Gateway(); x.IsValid() && gw != nil {
			if csv = gw.X(x.AsSlice()); len(csv) > 0 {
				realips = append(realips, strings.Split(csv, ",")...)
				continue
			}
		}
		log.W("ipmapper: undoAlg: no algip => realip? (%s => %s)", x, csv)
	}
	for _, x := range realips {
		if ip, err := str2ip(x); err == nil {
			ips = append(ips, ip)
		} else {
			log.W("ipmapper: undoAlg: str2ip %s err: %v", x, err)
		}
	}
	log.D("ipmapper: undoAlg: %v => %v", ip64, ips)
	return ips
}

func key(name string, typ string) string {
	return name + ":" + typ
}

func addrs(a []byte) []netip.Addr {
	msg := xdns.AsMsg(a)
	if msg == nil {
		return nil
	}
	ips := make([]netip.Addr, 0, len(msg.Answer))
	for _, a := range msg.Answer {
		switch rr := a.(type) {
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
