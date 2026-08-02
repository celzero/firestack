// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package xdns

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestBustAndroidCacheIfNeededZeroesTTLForCloudflareRecords(t *testing.T) {
	const (
		domain = "cloudflare.com"
		ttl    = uint32(3600)
	)

	tests := []struct {
		name   string
		qtype  uint16
		lookup func(t *testing.T) *dns.Msg
	}{
		{
			name:  "A",
			qtype: dns.TypeA,
			lookup: func(t *testing.T) *dns.Msg {
				t.Helper()
				resolver := &net.Resolver{PreferGo: true}
				addrs, err := resolver.LookupNetIP(context.Background(), "ip4", domain)
				if err != nil {
					t.Skipf("lookup A records: %v", err)
				}
				msg := newTestMsg(domain, dns.TypeA)
				for _, addr := range addrs {
					msg.Answer = append(msg.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
						A:   addr.AsSlice(),
					})
				}
				return msg
			},
		},
		{
			name:  "AAAA",
			qtype: dns.TypeAAAA,
			lookup: func(t *testing.T) *dns.Msg {
				t.Helper()
				resolver := &net.Resolver{PreferGo: true}
				addrs, err := resolver.LookupNetIP(context.Background(), "ip6", domain)
				if err != nil {
					t.Skipf("lookup AAAA records: %v", err)
				}
				msg := newTestMsg(domain, dns.TypeAAAA)
				for _, addr := range addrs {
					msg.Answer = append(msg.Answer, &dns.AAAA{
						Hdr:  dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
						AAAA: addr.AsSlice(),
					})
				}
				return msg
			},
		},
		{
			name:  "HTTPS",
			qtype: dns.TypeHTTPS,
			lookup: func(t *testing.T) *dns.Msg {
				t.Helper()
				msg := queryDNS(t, domain, dns.TypeHTTPS)
				if len(msg.Answer) == 0 {
					t.Skip("no HTTPS answers returned")
				}
				setTTL(msg, ttl)
				return msg
			},
		},
		{
			name:  "SVCB",
			qtype: dns.TypeSVCB,
			lookup: func(t *testing.T) *dns.Msg {
				t.Helper()
				msg := queryDNS(t, domain, dns.TypeSVCB)
				if len(msg.Answer) == 0 {
					t.Skip("no SVCB answers returned")
				}
				setTTL(msg, ttl)
				return msg
			},
		},
		{
			name:  "TXT",
			qtype: dns.TypeTXT,
			lookup: func(t *testing.T) *dns.Msg {
				t.Helper()
				resolver := &net.Resolver{PreferGo: true}
				texts, err := resolver.LookupTXT(context.Background(), domain)
				if err != nil {
					t.Skipf("lookup TXT records: %v", err)
				}
				msg := newTestMsg(domain, dns.TypeTXT)
				for _, text := range texts {
					msg.Answer = append(msg.Answer, &dns.TXT{
						Hdr: dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
						Txt: []string{text},
					})
				}
				return msg
			},
		},
		{
			name:  "MX",
			qtype: dns.TypeMX,
			lookup: func(t *testing.T) *dns.Msg {
				t.Helper()
				resolver := &net.Resolver{PreferGo: true}
				mxs, err := resolver.LookupMX(context.Background(), domain)
				if err != nil {
					t.Skipf("lookup MX records: %v", err)
				}
				msg := newTestMsg(domain, dns.TypeMX)
				for _, mx := range mxs {
					msg.Answer = append(msg.Answer, &dns.MX{
						Hdr:        dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: ttl},
						Mx:         mx.Host,
						Preference: uint16(mx.Pref),
					})
				}
				return msg
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.lookup(t)
			if len(msg.Answer) == 0 {
				t.Skip("no answers returned")
			}
			if !BustAndroidCacheIfNeeded(msg) {
				t.Fatalf("expected cache bust for %s answers", dns.TypeToString[tc.qtype])
			}
			for _, rr := range msg.Answer {
				if rr.Header().Rrtype != tc.qtype {
					continue
				}
				if rr.Header().Ttl != ZeroTTL {
					t.Fatalf("expected TTL 0 for %s answer, got %d", dns.TypeToString[tc.qtype], rr.Header().Ttl)
				}
			}
		})
	}
}

func newTestMsg(name string, qtype uint16) *dns.Msg {
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = true
	return msg
}

func queryDNS(t *testing.T, name string, qtype uint16) *dns.Msg {
	t.Helper()
	client := &dns.Client{Net: "udp"}
	msg := newTestMsg(name, qtype)
	resp, _, err := client.Exchange(msg, "1.1.1.1:53")
	if err != nil {
		t.Skipf("query %s for %s: %v", name, dns.TypeToString[qtype], err)
	}
	if resp == nil {
		t.Skipf("empty response for %s %s", name, dns.TypeToString[qtype])
	}
	return resp
}

func setTTL(msg *dns.Msg, ttl uint32) {
	for _, rr := range msg.Answer {
		rr.Header().Ttl = ttl
	}
}
