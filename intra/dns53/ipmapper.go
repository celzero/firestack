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

type answer struct {
	a   []byte
	tid string
}

type ipmapper struct {
	id string
	r  dnsx.Resolver
	ba *core.Barrier[answer, string]
}

var _ ipmap.IPMapper = (*ipmapper)(nil)

// AddIPMapper adds or removes the IPMapper.
func AddIPMapper(r dnsx.Resolver, protos string, clear bool) {
	var m ipmap.IPMapper
	ok := r != nil
	if ok {
		m = &ipmapper{
			id: dnsx.IpMapper,
			r:  r,
			ba: core.NewBarrier[answer](battl),
		}
	} // else remove; m is nil
	if clear {
		dialers.Clear() // note: clears ipset async
	}
	dialers.Mapper(m)
	dialers.IPProtos(protos)
}

func str2ip(host string) (netip.Addr, error) {
	return netip.ParseAddr(host)
}

// Implements IPMapper.
func (m *ipmapper) Lookup(q []byte) ([]byte, error) {
	return m.queryAny(q)
}

// Implements IPMapper.
func (m *ipmapper) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return m.queryIP(ctx, network, host, core.UNKNOWN_UID_STR)
}

// Implements IPMapper.
func (m *ipmapper) LookupNetIPFor(ctx context.Context, network, host, uid string) ([]netip.Addr, error) {
	return m.queryIP(ctx, network, host, uid)
}

func (m *ipmapper) queryIP(_ context.Context, network, host string, uid string) ([]netip.Addr, error) {
	return m.queryIP2(context.Background(), network, host, uid)
}

func (m *ipmapper) queryAny(q []byte) ([]byte, error) {
	return m.queryAny2(q, core.UNKNOWN_UID_STR)
}

// todo: use context
func (m *ipmapper) queryIP2(_ context.Context, network, host, uid string) ([]netip.Addr, error) {
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

	log.V("ipmapper: lookup: host %s:%s for %s", network, host, uid)

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
		log.E("ipmapper: lookup: unknown net %s query %s", network, host)
		return nil, errNoNet
	}

	if err4 != nil || err6 != nil {
		errs := errors.Join(err4, err6)
		log.E("ipmapper: lookup: query %s err %v", host, errs)
		return nil, errs
	}

	var val4, val6 *core.V[answer, string]
	if uid != core.UNKNOWN_UID_STR {
		val4, _ = m.ba.Do(key(host, "ip4", uid), m.lookupfor(q4, uid))
		val6, _ = m.ba.Do(key(host, "ip6", uid), m.lookupfor(q6, uid))
	} else {
		val4, _ = m.ba.Do(key(host, "ip4"), m.locallookup(q4))
		val6, _ = m.ba.Do(key(host, "ip6"), m.locallookup(q6))
	}

	var noval4, noval6 bool
	var r4, r6 []byte
	var tid4, tid6 string
	var lerr4, lerr6 error
	if val4 == nil {
		noval4 = true
	} else {
		noval4 = len(val4.Val.a) <= 0
		r4 = val4.Val.a     // may be nil
		lerr4 = val4.Err    // may be nil
		tid4 = val4.Val.tid // may be empty
	}
	if val6 == nil {
		noval6 = true
	} else {
		noval4 = len(val4.Val.a) <= 0
		r6 = val6.Val.a     // may be nil
		lerr6 = val6.Err    // may be nil
		tid6 = val4.Val.tid // may be empty
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
	ip4 := m.undoAlg(addrs(r4), tid4)
	ip6 := m.undoAlg(addrs(r6), tid6)
	ips = append(ips, ip4...)
	ips = append(ips, ip6...)

	log.D("ipmapper: host %s => ips %s; err4: %v, err6: %v", host, ips, lerr4, lerr6)
	return ips, nil
}

func (m *ipmapper) queryAny2(q []byte, uid string) ([]byte, error) {
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
	qtype := int(xdns.QType(msg))

	log.V("ipmapper: lookup: host %s, uid: %v", qname, uid)

	var v *core.V[answer, string]
	if uid != core.UNKNOWN_UID_STR {
		v, _ = m.ba.Do(key(qname, strconv.Itoa(qtype)), m.lookupfor(q, uid))
	} else {
		v, _ = m.ba.Do(key(qname, strconv.Itoa(qtype)), m.locallookup(q))
	}

	if v == nil || len(v.Val.a) <= 0 || v.Err != nil {
		log.W("ipmapper: query: noans? %t [err %v] for %s / typ %d; for: %s",
			v == nil, v.Err, qname, qtype, uid)
		return nil, core.OneErr(v.Err, errNoAns)
	} else {
		return v.Val.a, nil
	}
}

func (m *ipmapper) lookupfor(q []byte, uid string) func() (answer, error) {
	return func() (answer, error) {
		a, tid, err := m.r.LookupFor(q, uid)
		return answer{a, tid}, err
	}
}

func (m *ipmapper) locallookup(q []byte) func() (answer, error) {
	return func() (answer, error) {
		a, tid, err := m.r.LocalLookup(q)
		return answer{a, tid}, err
	}
}

func (m *ipmapper) undoAlg(ip64 []netip.Addr, tid string) []netip.Addr {
	// unlike common.go:undoAlg, we do not filter out ipaddrs
	// based on dialers.Use4/Use6. This is because the ipmapper
	// is used for DNS queries, and the dialers are used for
	// actual connections. The dialers will filter out ipaddrs
	// based on the dialers.Use4/Use6 settings.
	gw := m.r.Gateway()
	if gw == nil {
		log.D("ipmapper: undoAlg: no-op; no gateway")
		return ip64
	}
	realips := make([]netip.Addr, 0, len(ip64))
	for _, addr := range ip64 {
		var xips []netip.Addr
		if xips, _ = gw.X(addr, tid); len(xips) > 0 {
			// may contain duplicates due to how alg maps domains and ips
			realips = append(realips, xips...)
			continue // skip log.W below
		}
		log.W("ipmapper: undoAlg: no algip => realip? (%s => %v)", addr, xips)
	}
	return realips // no dups
}

func key(name string, oth ...string) string {
	if len(oth) <= 0 {
		return name
	}
	return name + ":" + strings.Join(oth, ":")
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
	return xdns.Question(host, qtype)
}
