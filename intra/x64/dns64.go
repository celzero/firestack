// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//    ISC License
//
//    Copyright (c) 2018-2022
//    Frank Denis <j at pureftpd dot org>

// adopted from: github.com/DNSCrypt/dnscrypt-proxy/blob/df3fb0c9/dnscrypt-proxy/plugin_dns64.go
package x64

import (
	"context"
	"errors"
	"maps"
	"net"
	"sync"
	"sync/atomic"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

var (
	rfc7050WKA1 = net.IPv4(192, 0, 0, 170)
	rfc7050WKA2 = net.IPv4(192, 0, 0, 171)

	// nslookup ipv4only.arpa 2606:4700:4700::64
	// Non-authoritative answer:
	// Address: 192.0.0.171
	// Address: 192.0.0.170
	// Address: 64:ff9b::c000:aa
	// Address: 64:ff9b::c000:ab
	// _, rfc6052WKP, _ = net.ParseCIDR("64:ff9b::/96")
	// _, rfc8215WKP, _ = net.ParseCIDR("64:ff9b:1:fffe::/96")

	ipv6bits = 8 * net.IPv6len

	errQuery        = errors.New("invalid dns64 query")
	errAns          = errors.New("invalid dns64 answer")
	errEmpty        = errors.New("missing dns64 IPv6 prefixes")
	errNotFound     = errors.New("resolver did not send dns64 ipv6 prefixes")
	errNoSuchServer = errors.New("resolver not registered")

	emptyStruct = struct{}{}

	arpa64 = questionArpa64()
)

type dns64 struct {
	sync.RWMutex

	ctx context.Context
	// dns-resolver -> nat64-ips (never contains zero net.IPNet)
	ip64 map[string][]net.IPNet
	// dns-resolver -> unique nat64-ips
	uniqIP64 map[string]map[string]struct{}

	paused atomic.Bool
}

func newDns64(ctx context.Context) *dns64 {
	d := &dns64{
		ctx:      ctx,
		ip64:     make(map[string][]net.IPNet),
		uniqIP64: make(map[string]map[string]struct{}),
	}
	settings.PtMode.On(ctx, func(_ int32) {
		d.pauseOrResume()
	})
	dialers.IPChanges().On(ctx, func(_ string) {
		d.pauseOrResume()
	})
	core.Gx("dns64.init", d.init)
	return d
}

func (d *dns64) pauseOrResume() {
	pt := settings.PtMode.Load()
	has6 := dialers.Use6()
	if pt == settings.PtModeNone {
		if d.paused.CompareAndSwap(false, true) {
			log.I("dns64: flow: disabled; pausing...")
		}
	} else if pt == settings.PtModeAuto && !has6 {
		// in auto mode, but no v6; pause 6to4 translations
		// in force 4 via 6 mode; 6to4 does not make sense
		if d.paused.CompareAndSwap(false, true) {
			log.I("dns64: flow: auto; no ipv6; pausing...")
		}
	} else {
		if d.paused.CompareAndSwap(true, false) {
			dormant := d.allIP64s()
			log.I("dns64: flow: forced or have ipv6? %t; resuming %d resolver(s)...", has6, len(dormant))
			for id := range dormant {
				readded := !d.AddResolver(id)
				logwif(!readded)("dns64: re-add resolver(%s); ok? %t", id, readded)
			}
		}
	}
}

func (d *dns64) init() {
	if err := d.ofLocal464(); err != nil { // unlikely
		log.W("dns64: err reg local(%v)", err)
	}
}

func (d *dns64) allIP64s() map[string][]net.IPNet {
	d.RLock()
	defer d.RUnlock()
	return maps.Clone(d.ip64)
}

func questionArpa64() *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dnsx.Rfc7050WKN, dns.TypeAAAA)
	return msg
}

// register adds a new dns resolver to the dns64 map; thread-safe.
func (d *dns64) register(id string) (paused bool) {
	d.Lock()
	if l, ok := d.ip64[id]; ok {
		log.W("dns64: overwrite existing ip64(%v) for resolver(%s)", l, id)
	}
	d.ip64[id] = make([]net.IPNet, 0)
	d.uniqIP64[id] = make(map[string]struct{})
	d.Unlock()

	return d.isPaused()
}

func (d *dns64) isPaused() bool {
	return d.paused.Load()
}

func (d *dns64) AddResolver(r string) (ok bool) {
	id := id64(r)
	switch id {
	case dnsx.Local464Resolver:
		return d.ofLocal464() == nil
	case dnsx.StdlibResolver:
		return d.ofStdlib() == nil
	case dnsx.UnderlayResolver:
		// stdlib must be re-calc on network changes; addition of a new
		// dnsx.System resolver is a proxy for a network change, so re-calc stdlib
		d.ofStdlib()
	}

	if !d.register(id) { // re-register to start with a clean slate
		log.VV("dns64: skipping query phase for resolver(%s); paused...", r)
		return
	}

	defer func() {
		if !ok {
			// remove previous id-related values on all errors, regardless.
			d.RemoveResolver(id)
		}
	}()

	ans, err := dialers.Query(arpa64, r)

	if err != nil || ans == nil || !xdns.HasAnyAnswer(ans) {
		log.W("dns64: udp: could not query %s[%s] or empty ans; err %v", r, id, err)
		return
	}

	if ans.Truncated { // should never be the case for DOH, ODOH, DOT
		// else if: returned response is truncated dns ans, retry over tcp
		ans, err = dialers.Query(arpa64, r)
		if err != nil {
			log.W("dns64: tcp: could not query resolver %s[%s]; err %v", r, id, err)
			return
		}
		if !xdns.HasAnyAnswer(ans) {
			log.W("dns64: tcp: invalid response from resolver %s[%s]", r, id)
			return
		}
	}

	ips := make([]net.IP, 0)
	for _, answer := range ans.Answer {
		if answer.Header().Rrtype == dns.TypeAAAA {
			if ipv6, ok := answer.(*dns.AAAA); ok {
				ips = append(ips, ipv6.AAAA)
			}
		}
	}

	err = d.add(id, ips)

	ok = err == nil

	logwif(!ok)("dns64: failed to add %s[%s] ips(%v); err %v", r, id, ips, err)
	return
}

func (d *dns64) RemoveResolver(id string) bool {
	id = id64(id)
	d.Lock()
	defer d.Unlock()
	delete(d.ip64, id)
	delete(d.uniqIP64, id)
	return true
}

// TODO: handle svcb/https ipv4hint/ipv6hint
// datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-10#section-7.4
func (d *dns64) eval(network string, force64 bool, ansin *dns.Msg, r, uid string) *dns.Msg {
	qname := xdns.QName(ansin)
	// if question is AAAA, then answer must have AAAA; for example CNAME,
	// records pointing no where must not be considered as AAAA answers
	// but instead must be sent to DNS64 for translation
	// q: www.skysports.com AAAA
	// ans: www.skysports.com CNAME www.skysports.akadns.net;
	// www.skysports.akadns.net CNAME www.skysports.com.edgekey.net;
	// www.skysports.com.edgekey.net CNAME e16115.j.akamaiedge.net
	// hasaaaq(true) hasans(true) rgood(true) ans0000(false)
	hasq6 := xdns.HasAAAAQuestion(ansin)
	hasans6 := xdns.HasAAAAAnswer(ansin)
	ans00006 := xdns.AQuadAUnspecified(ansin)
	hasauth := xdns.IsDNSSECAnswerAuthenticated(ansin)
	// treat as if v6 answer missing if enforcing 6to4
	if !hasq6 || ((hasauth || hasans6) && !force64) || ans00006 {
		// nb: has-aaaa-answer should cover for cases where
		// the response is blocked by dnsx.RDNS
		log.D("dns64: for(%s %s), no-op q(%s), q6(%t), ans6(%t), force64(%t), ans0000(%t)",
			network, uid, qname, hasq6, hasans6, force64, ans00006)
		return nil
	}

	id := id64(r)
	ip64 := d.get(id)
	if len(ip64) <= 0 {
		if ip64 = d.get(dnsx.UnderlayResolver); len(ip64) <= 0 {
			if ip64 = d.get(dnsx.StdlibResolver); len(ip64) <= 0 {
				// 64 prefix from Local646Resolver to be removed before egressing tunnel
				// see: natpt.go:X64 and alg.go:maybeUndoLocalNat64Locked
				ip64 = d.get(dnsx.Local464Resolver)
			}
		}
		log.D("dns64: attempt underlay/local464 resolver [%s@%s] ip64 (ad? %t) w len(%d)", r, uid, hasauth, len(ip64))
	}

	ans4, err := d.query64(network, ansin, r, uid)
	rgood := xdns.HasRcodeSuccess(ans4)
	hasans := xdns.HasAnyAnswer(ans4)
	ans0000 := xdns.AQuadAUnspecified(ans4)
	if err != nil || ans4 == nil || !hasans || ans0000 {
		log.W("dns64: skip: for %s, query(n:%s / a? %t) on resolver(%s[%s]/%s), code(good? %t / blocked? %t), err(%v)",
			uid, qname, hasans, r, id, network, rgood, ans0000, err)
		return nil
	}

	ans64, didTranslate := xdns.TranslateRecords(ans4, dns.TypeA, func(r dns.RR) (rx []dns.RR, stop bool) {
		if len(ip64) <= 0 { // can never be the case, see Local464Resolver
			return nil, false
		}
		for _, ipnet := range ip64 {
			if x := xdns.MaybeToQuadA(r, ipnet); x != nil {
				rx = append(rx, x)
			}
		}
		return
	})

	logwif(!didTranslate)("dns64: %s for %s: translated on %s[%s] response(%d)",
		qname, uid, r, id, xdns.Len(ans64))

	if !didTranslate {
		// may be there were no A records in ans4; or,
		// xdns.MaybeToQuadA failed for every A ans4 record
		return nil
	}
	return ans64
}

// query64 answers IPv4 query from the given IPv6 query.
func (d *dns64) query64(network string, msg6 *dns.Msg, r, uid string) (*dns.Msg, error) {
	msg4 := xdns.Request4FromResponse6(msg6) // may be nil
	if msg4 == nil || !xdns.HasAnyQuestion(msg4) {
		return nil, errQuery
	}

	proto, _ := xdns.Net2ProxyID(network)

	q4 := xdns.QName(msg4)

	// uid may be UNKNOWN_UID_STR if alg has "split" disabled.
	res, err := dialers.QueryFor(msg4, uid, r)

	hasAns := xdns.HasAnyAnswer(res)
	log.D("dns64: for %s over %s: %s q(%s) / a(%t) / e(%v) / e-not-nil(%t)",
		uid, proto, r, q4, hasAns, err, err != nil)
	if err != nil {
		return nil, err
	}
	if !hasAns {
		return nil, errAns
	}
	// res.Truncated never likely happens w/ DOH, ODOH, DOT?
	if res.Truncated && proto != dnsx.NetTypeTCP {
		// else if: returned response is truncated dns ans, retry over tcp
		res, err = dialers.QueryFor(msg4, uid, r)

		hasAns = xdns.HasAnyAnswer(res)
		log.D("dns64: tcp: for %s over %s: q(%s) / a(%d) / e(%v) / e-not-nil(%t)",
			uid, r, q4, hasAns, err, err != nil)
		if err != nil {
			return nil, err
		} else if !hasAns {
			return nil, errAns
		}
	}
	return res, err
}

func (d *dns64) ofStdlib() error {
	if d.register(dnsx.StdlibResolver) {
		log.VV("dns64: skipping query phase for stdlib; paused...")
		return nil
	}
	// in loopback mode, net.DefaultResolver will be routed back into
	// the tunnel and not in fact sent out to the default gateway
	if settings.Loopingback.Load() {
		log.I("dns64: skipping query phase for stdlib; looping back...")
		return nil
	}

	// AAAA query for ipv4only.arpa to stdlib resolver
	ips, err := net.DefaultResolver.LookupIP(d.ctx, "ip6", dnsx.Rfc7050WKN)
	log.I("dns64: ipv4only.arpa w stdlib network resolver")

	if err != nil {
		return err
	}

	if len(ips) <= 0 {
		return errNotFound
	}

	return d.add(dnsx.StdlibResolver, ips)
}

func (d *dns64) ofLocal464() error {
	d.register(dnsx.Local464Resolver)
	// send a copy of localip64 as d.add mutates its entries in-place
	// this addr64, hopefully, isn't used by any other dns world-wide
	localip64 := []net.IP{
		net.ParseIP("64:ff9b:1:fffe::192.0.0.170"),
	}
	return d.add(dnsx.Local464Resolver, localip64)
}

// add adds the nat64 prefixes to the dns64 map; thread-safe.
func (d *dns64) add(serverid string, nat64 []net.IP) error {
	if len(nat64) <= 0 {
		log.W("dns64: no nat64 ips for %s", serverid)
		return errEmpty
	}

	for _, ipv6 := range nat64 {
		log.D("dns64: id(%s); add? nat64 ip(%s / %d)", serverid, ipv6, len(ipv6))
		if len(ipv6) != net.IPv6len {
			continue
		}

		endByte := 0
		if wka := net.IPv4(ipv6[12], ipv6[13], ipv6[14], ipv6[15]); wka.Equal(rfc7050WKA1) || wka.Equal(rfc7050WKA2) { //96
			endByte = 12
		} else if wka := net.IPv4(ipv6[9], ipv6[10], ipv6[11], ipv6[12]); wka.Equal(rfc7050WKA1) || wka.Equal(rfc7050WKA2) { //64
			endByte = 8
		} else if wka := net.IPv4(ipv6[7], ipv6[9], ipv6[10], ipv6[11]); wka.Equal(rfc7050WKA1) || wka.Equal(rfc7050WKA2) { //56
			endByte = 7
		} else if wka := net.IPv4(ipv6[6], ipv6[7], ipv6[9], ipv6[10]); wka.Equal(rfc7050WKA1) || wka.Equal(rfc7050WKA2) { //48
			endByte = 6
		} else if wka := net.IPv4(ipv6[5], ipv6[6], ipv6[7], ipv6[9]); wka.Equal(rfc7050WKA1) || wka.Equal(rfc7050WKA2) { //40
			endByte = 5
		} else if wka := net.IPv4(ipv6[4], ipv6[5], ipv6[6], ipv6[7]); wka.Equal(rfc7050WKA1) || wka.Equal(rfc7050WKA2) { //32
			endByte = 4
		}

		if endByte <= 0 {
			log.I("dns64: id(%s), e(%d); no valid ipv4only.arpa in ans6(%v)", serverid, endByte, ipv6)
			continue
		}

		endBit := endByte * 8
		ipxx := net.IPNet{}
		// prefix ipv6 until the endByte, followed by all-zeros
		// 64:ff9b:1::WKA -> 64:ff9b:1::
		ipxx.IP = append(ipv6[:endByte], net.IPv6zero[endByte:]...)
		ipxx.Mask = net.CIDRMask(endBit, ipv6bits)

		if err := d.addNat64Prefix(serverid, ipxx); err != nil {
			return err
		}
	}

	ip64 := d.get(serverid)

	if len(ip64) == 0 {
		log.I("dns64: id(%s) has zero nat64 prefixes", serverid)
		return errEmpty
	} else {
		return nil
	}
}

func (d *dns64) get(serverid string) []net.IPNet {
	d.RLock()
	defer d.RUnlock()
	return d.ip64[serverid]
}

func (d *dns64) addNat64Prefix(id string, ipxx net.IPNet) error {
	if xdns.IsZeroPrefix(ipxx) {
		log.W("dns64: id(%s) has zero nat64 prefix", id)
		return errEmpty
	}

	d.Lock()
	defer d.Unlock()

	ip64, ok1 := d.ip64[id]
	uniq, ok2 := d.uniqIP64[id]
	if !ok1 || !ok2 {
		log.W("dns64: no server found server(%s)", id)
		return errNoSuchServer
	}

	// ipxx.String -> 64:ff9b:1::/mask
	ipxxstr := ipxx.String()
	_, exists := uniq[ipxxstr]
	if !exists {
		ip64 = append(ip64, ipxx)
		uniq[ipxxstr] = emptyStruct
		log.I("dns64: add ipnet [%s] for server(%s)", ipxxstr, id)
	} else {
		log.D("dns64: prefix6(%v) for server(%s) exists!", ipxxstr, id)
	}
	// nil / empty lists are valid values in map[string][]*net.IP
	d.ip64[id] = ip64

	return nil
}

func logwif(cond bool) log.LogFn {
	if cond {
		return log.W
	}
	return log.V
}
