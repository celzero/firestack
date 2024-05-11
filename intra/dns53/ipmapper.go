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
	"strconv"
	"strings"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/protect/ipmap"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

const battl = 10 * time.Second

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
	ba *core.Barrier[[]byte]
}

var _ ipmap.IPMapper = (*ipmapper)(nil)

// AddIPMapper adds or removes the IPMapper.
func AddIPMapper(r dnsx.Resolver, protos string, clear bool) {
	var m ipmap.IPMapper
	ok := r != nil
	if ok {
		m = &ipmapper{dnsx.IpMapper, r, core.NewBarrier[[]byte](battl)}
	} // else remove; m is nil
	if clear {
		dialers.Clear()
	}
	dialers.Mapper(m)
	dialers.IPProtos(protos)
}

func str2ip(host string) (netip.Addr, error) {
	return netip.ParseAddr(host)
}

// Implements IPMapper.
func (m *ipmapper) Lookup(q []byte) ([]byte, error) {
	msg := xdns.AsMsg(q)
	if msg == nil {
		log.W("ipmapper: not a dns query sz(%d)", len(q))
		return nil, errQueryParse
	}
	qname := xdns.QName(msg)
	if len(qname) <= 0 {
		log.W("ipmapper: query: no qname")
		return nil, errNoHost
	}
	qtype := xdns.QType(msg)

	v, _ := m.ba.Do(key(qname, strconv.Itoa(int(qtype))), resolve(m.r, q))

	if v.Err != nil || v == nil {
		log.W("ipmapper: query: noans? %t [err %v] for %s / typ %d", v == nil, v.Err, qname, qtype)
		return nil, errors.Join(v.Err, errNoAns)
	} else {
		return v.Val, nil
	}
}

// Implements IPMapper.
func (m *ipmapper) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if len(host) <= 0 {
		return nil, errNoHost
	}
	if protect.NeverResolve(host) {
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

	log.V("ipmapper: lookup: host %s on network %s", host, network)

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
		log.E("ipmapper: lookup: unkown net %s query %s", network, host)
		return nil, errNoNet
	}

	if err4 != nil || err6 != nil {
		errs := errors.Join(err4, err6)
		log.E("ipmapper: lookup: query %s err %v", host, errs)
		return nil, errs
	}

	val4, _ := m.ba.Do(key(host, "ip4"), resolve(m.r, q4))
	val6, _ := m.ba.Do(key(host, "ip6"), resolve(m.r, q6))

	var noval4, noval6 bool
	var r4, r6 []byte
	var lerr4, lerr6 error
	if val4 == nil {
		noval4 = true
	} else {
		r4 = val4.Val
		lerr4 = val4.Err // may be nil
	}
	if val6 == nil {
		noval6 = true
	} else {
		r6 = val6.Val
		lerr6 = val6.Err // may be nil
	}

	if lerr4 != nil && lerr6 != nil { // all errors
		errs := errors.Join(lerr4, lerr6)
		log.E("ipmapper: lookup: %s: err %v", host, errs)
		return nil, errs
	} else if noval4 && noval6 { // typecast failed or no answer
		log.E("ipmapper: lookup: no answers for %s; len(4)? %d len(6)? %d", host, len(r4), len(r6))
		return nil, errNoAns
	} else if len(r4) <= 0 && len(r6) <= 0 { // empty answer
		errs := errors.Join(errNoAns, lerr4, lerr6)
		log.E("ipmapper: lookup: no answers for %s, err %v", host, errs)
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
	gw := m.r.Gateway()
	if gw == nil {
		log.D("ipmapper: undoAlg: no-op; no gateway")
		return ip64
	}
	ips := make([]netip.Addr, 0, len(ip64))
	realips := make([]string, 0, len(ip64))
	for _, addr := range ip64 {
		var csv string
		if addr.IsValid() {
			if csv = gw.X(addr); len(csv) > 0 {
				// may contain duplicates due to how alg maps domains and ips
				realips = append(realips, strings.Split(csv, ",")...)
				continue // skip log.W below
			}
		}
		log.W("ipmapper: undoAlg: no algip => realip? (%s => %s)", addr, csv)
	}
	dups := 0
	seen := make(map[string]bool) // track duplicates
	for _, x := range realips {
		if y, ok := seen[x]; y && ok {
			dups++
			continue
		}
		seen[x] = true
		if ip, err := str2ip(x); err == nil {
			ips = append(ips, ip)
		} else {
			log.W("ipmapper: undoAlg: str2ip %s err: %v", x, err)
		}
	}
	log.D("ipmapper: undoAlg(%d): %v => %v", dups, ip64, ips)
	return ips
}

func key(name string, typ string) string {
	return name + ":" + typ
}

func resolve(r dnsx.Resolver, q []byte) core.Work[[]byte] {
	return func() ([]byte, error) {
		return r.LocalLookup(q)
	}
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
