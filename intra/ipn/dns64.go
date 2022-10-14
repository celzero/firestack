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
package ipn

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

// ref: datatracker.ietf.org/doc/html/rfc8880
const Rfc7050WKN = "ipv4only.arpa."
const UnderlayResolver = "__underlay"
const OverlayResolver = "__overlay"
const Local464Resolver = "__local464"

var (
	rfc7050WKA1 = net.IPv4(192, 0, 0, 170)
	rfc7050WKA2 = net.IPv4(192, 0, 0, 171)

	// nslookup ipv4only.arpa 2606:4700:4700::64
	// Non-authoritative answer:
	// Address: 192.0.0.171
	// Address: 192.0.0.170
	// Address: 64:ff9b::c000:aa
	// Address: 64:ff9b::c000:ab
	_, rfc6052WKP, _ = net.ParseCIDR("64:ff9b::/96")
	_, rfc8215WKP, _ = net.ParseCIDR("64:ff9b:1:fffe::/96")

	ipv6bits = 8 * net.IPv6len

	errEmpty        = errors.New("missing DNS64 IPv6 prefixes")
	errNotFound     = errors.New("resolver did not send DNS64 IPv6 prefixes")
	errNoSuchServer = errors.New("resolver not registered")

	emptyStruct = struct{}{}

	arpa64 = question()
)

type Resolver interface {
	Exchange([]byte) ([]byte, error)
}

type DNS64 interface {
	AddResolver(id string, f Resolver) bool
	ResetNat64Prefix(ip6prefix string) bool
	D64(id string, ans6 []byte, f Resolver) []byte
}

type dns64 struct {
	sync.RWMutex
	// dns-resolver -> nat64-ips
	ip64 map[string][]*net.IPNet
	// dns-resolver -> unique nat64-ips
	uniqIP64 map[string]map[string]struct{}
}

func newDns64() *dns64 {
	x := &dns64{
		ip64:     make(map[string][]*net.IPNet),
		uniqIP64: make(map[string]map[string]struct{}),
	}
	go x.init()
	return x
}

func (d *dns64) init() {
	err1 := d.ofOverlay()
	err2 := d.ofLocal464()
	if err1 != nil || err2 != nil {
		log.Warnf("dns64: err reg underlay(%v) / local(%v)", err1, err2)
	}
}

func question() (b []byte) {
	msg := new(dns.Msg)
	msg.SetQuestion(Rfc7050WKN, dns.TypeAAAA)
	b, _ = msg.Pack()
	return
}

func (d *dns64) register(id string) {
	d.Lock()
	defer d.Unlock()
	if l, ok := d.ip64[id]; ok {
		log.Warnf("dns64: overwrite existing ip64(%v) for resolver(%s)", l, id)
	}
	d.ip64[id] = make([]*net.IPNet, 0)
	d.uniqIP64[id] = make(map[string]struct{})
}

func (d *dns64) AddResolver(id string, r Resolver) bool {

	d.register(id)

	b, err := r.Exchange(arpa64)
	if err != nil {
		log.Warnf("dns64: could not query resolver %s", id)
		return false
	}

	ans := &dns.Msg{}
	err = ans.Unpack(b)
	if err != nil {
		log.Warnf("dns64: invalid response from resolver %s", id)
	}

	ips := make([]net.IP, 0)
	for _, answer := range ans.Answer {
		if answer.Header().Rrtype == dns.TypeAAAA {
			ipv6 := answer.(*dns.AAAA).AAAA
			ips = append(ips, ipv6)
		}
	}

	if err := d.add(id, ips); err != nil {
		return false
	}
	return true
}

func (d *dns64) RemoveResolver(id string) {
	d.Lock()
	defer d.Unlock()
	delete(d.ip64, id)
	delete(d.uniqIP64, id)
}

// TODO: handle svcb/https ipv4hint/ipv6hint
// datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-10#section-7.4
func (d *dns64) eval(id string, force64 bool, og []byte, r Resolver) []byte {
	d.RLock()
	ip64, ok := d.ip64[id]
	d.RUnlock()

	if !ok {
		log.Debugf("dns64: no resolver id(%s) registered", id)
	}

	if len(ip64) <= 0 {
		if ip64 = d.ip64[UnderlayResolver]; len(ip64) <= 0 {
			if ip64 = d.ip64[OverlayResolver]; len(ip64) <= 0 {
				ip64 = d.ip64[Local464Resolver]
			}
		}
		log.Debugf("dns64: attempt underlay/local464 resolver ip64 w len(%d)", len(ip64))
	}

	ansin := &dns.Msg{}
	err := ansin.Unpack(og)

	qname := xdns.QName(ansin)
	hasq6 := xdns.HasAAAAQuestion(ansin)
	hasans6 := xdns.HasAAAAAnswer(ansin)
	// treat as if v6 answer missing if enforcing 6to4
	if err != nil || !hasq6 || (hasans6 && !force64) {
		// nb: has-aaaa-answer should cover for cases where
		// the response is blocked by dnsx.BraveDNS
		log.Debugf("dns64: no-op q(%s), err(%v), q6(%t), ans6(%t), force64(%t)", qname, err, hasq6, hasans6, force64)
		return og
	}

	ans4, err := d.query64(ansin, r)
	rgood := xdns.HasRcodeSuccess(ans4)
	if err != nil || ans4 == nil || len(ans4.Answer) <= 0 || xdns.AQuadAUnspecified(ans4) {
		log.Warnf("dns64: query(n:%s / a:%d) to resolver(%s) rgood(%t), err(%v)", qname, len(ans4.Answer), id, rgood, err)
		return og
	}

	rr64 := make([]dns.RR, 0)
	for _, answer := range ans4.Answer {
		if len(ip64) <= 0 { // can never be the case, see Local464Resolver
			continue
		} else {
			for _, ipnet := range ip64 {
				if rec := xdns.MaybeToQuadA(answer, ipnet); rec != nil {
					rr64 = append(rr64, rec)
				}
			}
		}
	}
	log.Debugf("dns64: translated response(%v)", rr64)

	if len(rr64) <= 0 {
		// may be there were no A records in ans4; or,
		// xdns.ToQuadA failed for every A ans4 record
		log.Warnf("dns64: no rr64 translations done")
		return og
	}

	ans64 := xdns.EmptyResponseFromMessage(ansin)
	ans64.Answer = append(ans64.Answer, rr64...)
	if r, err := ans64.Pack(); err == nil {
		return r
	} else {
		log.Warnf("dns64: unpacking ans64 err(%v)", err)
		return og
	}
}

func (d *dns64) query64(msg6 *dns.Msg, r Resolver) (*dns.Msg, error) {
	msg4 := xdns.Request4FromResponse6(msg6)
	q4, err := msg4.Pack()
	if err != nil {
		return nil, err
	}

	a4, err := r.Exchange(q4)
	log.Debugf("dns64: upstream q(%s) / a(%d) / e(%v) / e-not-nil(%t)", xdns.QName(msg4), len(a4), err, err != nil)
	if len(a4) <= 0 {
		return nil, err
	}

	res := &dns.Msg{}
	if err := res.Unpack(a4); err != nil {
		return nil, err
	}

	return res, nil
}

func (d *dns64) ofOverlay() error {
	ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip6", Rfc7050WKN)
	log.Infof("dns64: ipv4only.arpa w underlying network resolver")

	if err != nil {
		return err
	}

	if len(ips) <= 0 {
		return errNotFound
	}

	d.register(OverlayResolver)
	return d.add(OverlayResolver, ips)
}

func (d *dns64) ofLocal464() error {
	d.register(Local464Resolver)
	// send a copy of localip64 as d.add mutates its entries in-place
	// this addr64, hopefully, isn't used by any other dns world-wide
	localip64 := []net.IP{
		net.ParseIP("64:ff9b:1:fffe::192.0.0.170"),
	}
	return d.add(Local464Resolver, localip64)
}

func (d *dns64) add(serverid string, nat64 []net.IP) error {

	if len(nat64) <= 0 {
		log.Warnf("dns64: no nat64 ips for %s", serverid)
		return errEmpty
	}

	for _, ipv6 := range nat64 {
		log.Debugf("dns64: id(%s); add? nat64 ip(%s / %d)", serverid, ipv6, len(ipv6))
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
			log.Infof("dns64: id(%s), e(%d); no valid ipv4only.arpa in ans6(%v)", serverid, endByte, ipv6)
			continue
		}

		endBit := endByte * 8
		ipxx := new(net.IPNet)
		// prefix ipv6 until the endByte, followed by all-zeros
		// 64:ff9b:1::WKA -> 64:ff9b:1::
		ipxx.IP = append(ipv6[:endByte], net.IPv6zero[endByte:]...)
		ipxx.Mask = net.CIDRMask(endBit, ipv6bits)

		if err := d.addNat64Prefix(serverid, ipxx); err != nil {
			return err
		}
	}

	d.RLock()
	ip64 := d.ip64[serverid]
	d.RUnlock()

	if len(ip64) == 0 {
		log.Infof("dns64: id(%s) has zero nat64 prefixes", serverid)
		return errEmpty
	} else {
		return nil
	}
}

func (d *dns64) addNat64Prefix(id string, ipxx *net.IPNet) error {
	d.Lock()
	defer d.Unlock()

	ip64, ok1 := d.ip64[id]
	uniq, ok2 := d.uniqIP64[id]
	if !ok1 || !ok2 {
		log.Warnf("dns64: no server found server(%s)", id)
		return errNoSuchServer
	}

	// ipxx.String -> 64:ff9b:1::/mask
	_, exists := uniq[ipxx.String()]
	if !exists {
		ip64 = append(ip64, ipxx)
		uniq[ipxx.String()] = emptyStruct
		log.Infof("dns64: add ipnet [%s] for server(%s)", ipxx, id)
	} else {
		log.Debugf("dns64: prefix6(%v) for server(%s) exists!", id, ipxx)
	}
	// nil / empty lists are valid values in map[string][]*net.IP
	d.ip64[id] = ip64

	return nil
}
