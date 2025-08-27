// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package multihost

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/celzero/firestack/intra/dialers"
	ilog "github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

type fakeResolver struct {
	*net.Resolver
}

func (r fakeResolver) Lookup(q []byte, _ ...string) ([]byte, error) {
	// return nil, errors.New("lookup: not implemented")
	msg := xdns.AsMsg(q)
	if msg == nil {
		return nil, errors.New("fakeresolver: nil dns msg")
	}
	if !xdns.HasAQuadAQuestion(msg) {
		return nil, errors.New("fakeresolver: A/AAAA only")
	}
	qname := xdns.QName(msg)
	network := "ip4"
	if xdns.HasAAAAQuestion(msg) {
		network = "ip6"
	}
	addrs, err := r.Resolver.LookupNetIP(context.TODO(), network, qname)
	if err != nil {
		return nil, err
	}
	// make a dns answer for addrs
	ans := xdns.EmptyResponseFromMessage(msg)
	if ans == nil {
		return nil, errors.New("fakeresolver: nil pkt")
	}
	rrs := make([]dns.RR, 0)
	for _, a := range addrs {
		if network == "ip4" {
			rr := xdns.MakeARecord(qname, a.String(), 30)
			rrs = append(rrs, rr)
		} else {
			rr := xdns.MakeAAAARecord(qname, a.String(), 30)
			rrs = append(rrs, rr)
		}
	}
	ans.Answer = rrs

	return ans.Pack()
}

func (r fakeResolver) LookupFor(q []byte, _ string) ([]byte, error) {
	return r.Lookup(q)
}

func (r fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return r.Resolver.LookupNetIP(ctx, network, host)
}

func (r fakeResolver) LookupNetIPFor(ctx context.Context, network, host, uid string) ([]netip.Addr, error) {
	return r.Resolver.LookupNetIP(ctx, network, host)
}

func (r fakeResolver) LookupNetIPOn(ctx context.Context, network, host string, tid ...string) ([]netip.Addr, error) {
	return r.Resolver.LookupNetIP(ctx, network, host)
}

func TestMultihostMap(t *testing.T) {
	ilog.SetLevel(0)
	settings.Debug = true

	dialers.Mapper(&fakeResolver{})

	h0 := New("h0")
	h0domains := []string{
		"one.one.one.one:53",
		"dns.google:443",
	}
	h0.Add(h0domains)

	h1 := New("h1")
	h1ips := []string{
		"1.1.1.1:53",
		"2.2.2.2:23",
		"3.3.3.3:33",
	}
	h1.Add(h1ips)

	h2 := New("h2")
	h2ips := []string{
		"[2000:b:0::5:0]:53",
		"[2000:d:e::a:d]:23",
		"[2000:b:e::e:f]:33",
	}
	h2.Add(h2ips)

	m := NewMap("testmap")

	if !m.Put(h0) {
		t.Fatal("expected to put h0")
	}

	_, xperr0 := m.Get("one.one.one.one:443") // empty; wrong port
	_, unerr0 := m.Get("dns.google:443")
	if xperr0 == nil {
		t.Errorf("expected error, got nil")
		t.Fail()
	}
	if unerr0 != nil {
		t.Errorf("expected no error, got %v", unerr0)
		t.Fail()
	}

	if !m.Put(h1) {
		t.Fatal("expected to put h1")
	}
	_, xperr1 := m.Get("1.1.1.1") // empty
	_, unerr1 := m.Get("1.1.1.1:53")
	if xperr1 == nil {
		t.Errorf("expected error, got nil")
		t.Fail()
	}
	if unerr1 != nil {
		t.Errorf("expected no error, got %v", unerr1)
		t.Fail()
	}
	_, xperr2 := m.Get("[2000:d:e::a:d]:23") // empty
	if !m.Put(h2) {
		t.Fatal("expected to put h2")
	}
	_, unerr2 := m.Get("[2000:d:e::a:d]:23") // empty
	if xperr2 == nil {
		t.Errorf("expected error, got nil")
		t.Fail()
	}
	if unerr2 != nil {
		t.Errorf("expected no error, got %v", unerr2)
		t.Fail()
	}
	// ilog.D(m.String()) // only prints ips
}
