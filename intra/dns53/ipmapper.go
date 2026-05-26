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
	"github.com/celzero/firestack/intra/settings"
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
	a        []byte
	tid, uid string
}

type ipmapper struct {
	id string
	r  dnsx.ResolverSelf
	g  dnsx.Gateway
	ba *core.Barrier[answer, string]
}

var _ ipmap.IPMapper = (*ipmapper)(nil)

// AddIPMapper adds or removes the IPMapper.
func AddIPMapper(r dnsx.Resolver, protos string, clear bool) {
	var m ipmap.IPMapper // nil
	ok := r != nil
	if ok {
		m = &ipmapper{
			id: dnsx.IpMapper,
			r:  r,
			g:  r.Gateway(),
			ba: core.NewBarrier[answer]("ipm.bar", battl),
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
func (m *ipmapper) LocalLookup(q []byte) ([]byte, error) {
	return m.Lookup(q, protect.UidSelf, dnsx.Default)
}

// Implements IPMapper.
func (m *ipmapper) Lookup(q []byte, uid string, tids ...string) ([]byte, error) {
	return m.queryAny2(q, uid, tids...)
}

// Implements IPMapper.
func (m *ipmapper) LookupFor(q []byte, uid string) ([]byte, error) {
	return m.queryAny2(q, uid)
}

// Implements IPMapper.
func (m *ipmapper) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return m.queryIP(ctx, network, host, core.UNKNOWN_UID_STR)
}

// Implements IPMapper.
func (m *ipmapper) LookupNetIPFor(ctx context.Context, network, host, uid string) ([]netip.Addr, error) {
	return m.queryIP(ctx, network, host, uid)
}

// Implements IPMapper.
func (m *ipmapper) LookupNetIPOn(ctx context.Context, network, host string, tid ...string) ([]netip.Addr, error) {
	return m.queryIP2(ctx, network, host, protect.UidSelf, tid...)
}

func (m *ipmapper) queryIP(ctx context.Context, network, host string, uid string) ([]netip.Addr, error) {
	return m.queryIP2(ctx, network, host, uid)
}

// todo: use context
func (m *ipmapper) queryIP2(_ context.Context, network, host, uid string, tid ...string) ([]netip.Addr, error) {
	if len(host) <= 0 {
		return nil, errNoHost
	}
	if protect.NeverResolve(host) {
		return nil, nil
	}
	if host == protect.Localhost || host == "localhost." {
		return []netip.Addr{loopback4, loopback6}, nil
	}
	// no lookups when host is already an IP
	if ip, err := str2ip(host); err == nil {
		log.V("ipmapper: lookup: no-op; host %s is ipaddr", host)
		return []netip.Addr{ip}, nil
	}

	if settings.Debug {
		log.V("ipmapper: lookup: host %s:%s for %s on %v", network, host, uid, tid)
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
		log.E("ipmapper: lookup: unknown net %s query %s", network, host)
		return nil, errNoNet
	}

	if err4 != nil || err6 != nil {
		errs := core.JoinErr(err4, err6)
		log.E("ipmapper: lookup: query %s err %v", host, errs)
		return nil, errs
	}

	var val4, val6 *core.V[answer, string]
	if len(tid) > 0 { // always choose one among these tids
		val4, _ = m.ba.Do(key4(host, tid...), m.lookupon(q4, uid, tid...))
		val6, _ = m.ba.Do(key6(host, tid...), m.lookupon(q6, uid, tid...))
	} else if uid != core.UNKNOWN_UID_STR { // client code chooses a tid depending on uid & "origin"
		val4, _ = m.ba.Do(key4(host, uid), m.lookupfor(q4, uid))
		val6, _ = m.ba.Do(key6(host, uid), m.lookupfor(q6, uid))
	} else { // either Default or System/Goos
		val4, _ = m.ba.Do(key4(host, dnsx.Default), m.locallookup(q4))
		val6, _ = m.ba.Do(key6(host, dnsx.Default), m.locallookup(q6))
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
		noval6 = len(val6.Val.a) <= 0
		r6 = val6.Val.a     // may be nil
		lerr6 = val6.Err    // may be nil
		tid6 = val6.Val.tid // may be empty
	}

	if lerr4 != nil && lerr6 != nil { // all errors
		errs := core.JoinErr(lerr4, lerr6)
		log.E("ipmapper: lookup: %s: err %v", host, errs)
		return nil, errs
	} else if noval4 && noval6 { // typecast failed or no answer
		log.E("ipmapper: lookup: no answers for %s; len(4)? %d len(6)? %d", host, len(r4), len(r6))
		return nil, errNoAns
	} else if len(r4) <= 0 && len(r6) <= 0 { // empty answer
		errs := core.JoinErr(errNoAns, lerr4, lerr6)
		log.E("ipmapper: lookup: no answers for %s (by: %s+%s), err %v", host, tid4, tid6, errs)
		return nil, errs
	}

	_, ip4 := addrs(r4)
	_, ip6 := addrs(r6)
	ip4 = m.undoAlgAndOrNat64(ip4, tid4, uid)
	ip6 = m.undoAlgAndOrNat64(ip6, tid6, uid) // nat64 cannot really be "undone" for ip6!
	ips := append(ip4, ip6...)

	if settings.Debug {
		log.D("ipmapper: host %s => ips (out: %v / in: %d+%d); uid: %s, tids: %s+%s; err4: %v, err6: %v",
			host, ips, len(r4), len(r6), uid, tid4, tid6, lerr4, lerr6)
	}
	return ips, nil
}

func (m *ipmapper) queryAny2(q []byte, uid string, tids ...string) ([]byte, error) {
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
	qtypestr := strconv.Itoa(qtype)

	if settings.Debug {
		log.V("ipmapper: lookup: host %s, uid: %v", qname, uid)
	}

	var v *core.V[answer, string]
	if len(tids) > 0 {
		v, _ = m.ba.Do(key(qname, qtypestr, tids...), m.lookupon(q, uid, tids...))
	} else if uid != core.UNKNOWN_UID_STR {
		v, _ = m.ba.Do(key(qname, qtypestr, uid), m.lookupfor(q, uid))
	} else {
		v, _ = m.ba.Do(key(qname, qtypestr, dnsx.Default), m.locallookup(q))
	}

	if v == nil || len(v.Val.a) <= 0 || v.Err != nil {
		log.W("ipmapper: query: noans? %t [err %v] for %s / typ %d; for: %s [on %v]",
			v == nil, v.Err, qname, qtype, uid, tids)
		return nil, core.OneErr(v.Err, errNoAns)
	}

	return m.undoAlg(v.Val.a, v.Val.tid, uid)
}

// lookupfor resolves q given a uid. If uid is protect.SelfUid, the client
// code (via DNSListener.OnQuery) may or may not choose dnsx.Default. If uid
// is any other "integer" including "-1" (core.UNKNOWN_UID_STR), the client
// code is free to choose a transport as it sees fit.
func (m *ipmapper) lookupfor(q []byte, uid string) func() (answer, error) {
	return func() (answer, error) {
		a, tid, err := m.r.LookupFor(q, uid)
		return answer{a, tid, uid}, err
	}
}

// lookupon always resolves on one of the chosen tids
// (if empty, it may or may not use dnsx.Default;
// see: dnsx.transport.go:determineTransport)
// uid may be protect.UidSelf or unknown
func (m *ipmapper) lookupon(q []byte, uid string, tids ...string) func() (answer, error) {
	return func() (answer, error) {
		a, tid, err := m.r.LookupFor2(q, uid, tids...)
		return answer{a, tid, uid}, err
	}
}

// locallookup resolves on dnsx.Default and then on dnsx.System or dnsx.Goos
// if dnsx.Default fails.
func (m *ipmapper) locallookup(q []byte) func() (answer, error) {
	return func() (answer, error) {
		a, tid, err := m.r.LocalLookup(q)
		return answer{a, tid, protect.UidSelf}, err
	}
}

func (m *ipmapper) undoAlg(ans []byte, tid, uid string) ([]byte, error) {
	gw := m.g
	if gw == nil {
		if settings.Debug {
			log.V("ipmapper: undoAlg: no-op for %s[%s]; no gateway", tid, uid)
		}
		return ans, nil
	}

	msg := &dns.Msg{}
	if err := msg.Unpack(ans); err != nil {
		log.W("ipmapper: undoAlg: unpack err %v", err)
		return ans, nil
	}

	qname, possiblyalgips := addrs(ans) // usually only 1 if alg'd

	noips := len(possiblyalgips) <= 0
	is4 := xdns.HasAAnswer(msg)
	is6 := !is4 && xdns.HasAAAAQuestion(msg)

	if !is4 && !is6 || noips {
		if settings.Debug {
			log.VV("ipmapper: undoAlg: no a? (%t), aaaa? (%t), ans? (%t); no-op",
				!is4, !is6, noips)
		}
		return ans, nil
	}

	var realips []netip.Addr
	var undidAlg bool
	for _, maybealgip := range possiblyalgips {
		if ips, undid := gw.X(maybealgip, uid, tid); undid {
			// expecting homogeneous addr family; ie, all realips
			// to be either v4 or v6
			realips = append(realips, ips...)
			undidAlg = true
		}
	}

	if len(realips) <= 0 {
		logwif(undidAlg)("ipmapper: undoAlg: no algip => realip; return orig (qname: %s / ips: %d / undidAlg? %t); tid? %s[%s]",
			qname, len(possiblyalgips), undidAlg, tid, uid)
		// TODO: return error if undidAlg == true?
		return ans, nil
	}

	var msgout *dns.Msg
	var didTranslate bool
	if is4 {
		msgout, didTranslate = xdns.TranslateRecords(msg, dns.TypeA, func(r dns.RR) (rx []dns.RR, done bool) {
			for _, ip4 := range realips {
				if x := xdns.CloneA(r, ip4); x != nil {
					rx = append(rx, x)
				}
			}
			return rx, len(rx) > 0 // a single translated rrs is enough
		})
	} else if is6 {
		msgout, didTranslate = xdns.TranslateRecords(msg, dns.TypeAAAA, func(r dns.RR) (rx []dns.RR, done bool) {
			for _, ip6 := range realips {
				if x := xdns.CloneAAAA(r, ip6); x != nil {
					rx = append(rx, x)
				}
			}
			return rx, len(rx) > 0 // a single translated rrs is enough
		})
	} // else: msgout is nil

	logwif(!didTranslate || msgout == nil)("ipmapper: undoAlg: %s => ips (out: %v / in: %d); tids: %s[%s]",
		qname, realips, xdns.Len(msgout), tid, uid)

	if msgout != nil {
		return msgout.Pack()
	}
	return ans, nil
}

func (m *ipmapper) undoAlgAndOrNat64(ip64 []netip.Addr, tid, uid string) []netip.Addr {
	// unlike common.go:undoAlg, we do not filter out ipaddrs
	// based on dialers.Use4/Use6. This is because the ipmapper
	// is used for DNS queries, and the dialers are used for
	// actual connections. The dialers will filter out ipaddrs
	// based on the dialers.Use4/Use6 settings.
	gw := m.g
	if gw == nil {
		if settings.Debug {
			log.V("ipmapper: undoAlg: no-op for %v on %s[%s]; no gateway", ip64, tid, uid)
		}
		return ip64
	}
	realips := make([]netip.Addr, 0, len(ip64))
	for _, addr := range ip64 {
		if xips, undidAlg := gw.X(addr, uid, tid); len(xips) > 0 {
			// may contain duplicates due to how alg maps domains and ips
			realips = append(realips, xips...)
			continue // skip log.W below
		} else {
			log.W("ipmapper: undoAlg: no algip => realip? (%s => %v); undidAlg? %t; tid? %s[%s]",
				addr, xips, undidAlg, tid, uid)
		}
	}
	if len(realips) <= 0 {
		log.W("ipmapper: undoAlg: no algip => realip; return orig (%v); tid? %s[%s]",
			ip64, tid, uid)
		return core.CopyUniq(ip64)
	}
	return realips // no dups
}

func key(name string, typ string, oth ...string) string {
	if len(oth) <= 0 {
		return name
	}
	return name + ":" + typ + ":" + strings.Join(oth, ":")
}

func key4(name string, oth ...string) string {
	return key(name, "ip4", oth...)
}

func key6(name string, oth ...string) string {
	return key(name, "ip6", oth...)
}

// TODO: handle HTTPS/SVCB
func addrs(a []byte) (qname string, ips []netip.Addr) {
	msg := xdns.AsMsg(a)
	if msg == nil {
		return
	}
	ips = make([]netip.Addr, 0, len(msg.Answer))
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
		case *dns.CNAME:
			log.V("ipmapper: cname %s => %s", rr.Hdr.Name, rr.Target)
		default:
			log.V("ipmapper: unexpected ans type: %v... skip", rr)
		}
	}
	return xdns.QName(msg), ips
}

func dnsmsg(host string, qtype uint16) ([]byte, error) {
	return xdns.Question(host, qtype)
}
