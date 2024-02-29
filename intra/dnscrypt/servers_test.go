// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnscrypt

import (
	"log"
	"net"
	"testing"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/ipn"
	ilog "github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

type fakeCtl struct {
	protect.Controller
}

func (*fakeCtl) Bind4(_ string, _ int)   {}
func (*fakeCtl) Bind6(_ string, _ int)   {}
func (*fakeCtl) Protect(_ string, _ int) {}

/*
type fakeBdg struct {
	protect.Controller
	intra.Bridge
}

var (
	baseNsOpts = &dnsx.NsOpts{PID: ipn.Base, IPCSV: "", TIDCSV: ""}
	baseMark   = &intra.Mark{PID: ipn.Base, CID: "testcid", UID: protect.UidSelf}
	baseTab    = &rnet.Tab{CID: "testcid", Block: false}
)

func (*fakeBdg) Flow(_ int32, _ int, a, b, c, d, e, f string) *intra.Mark { return baseMark }
func (*fakeBdg) OnSocketClosed(*intra.SocketSummary)                      {}

func (*fakeBdg) OnQuery(_ string, _ int) *dnsx.NsOpts { return baseNsOpts }
func (*fakeBdg) OnResponse(*dnsx.Summary)             {}

func (*fakeBdg) Route(a, b, c, d, e string) *rnet.Tab { return baseTab }
func (*fakeBdg) OnComplete(*rnet.ServerSummary)       {}
*/

func TestOne(t *testing.T) {
	resolver := &net.Resolver{}
	// create a struct that implements protect.Controller interface
	ctl := &fakeCtl{}
	// bdg := &fakeBdg{Controller: ctl}
	pxr := ipn.NewProxifier(ctl)
	ilog.SetLevel(0)
	dialers.Mapper(resolver)
	settings.Debug = true
	p := NewDcMult(pxr, ctl)
	// csromania fetches certs, but not answers
	// csromania := "sdns://AQIAAAAAAAAADTE0Ni43MC42Ni4yMjcgMTNyrVlWMsJBa4cvCY-FG925ZShMbL6aTxkJZDDbqVoeMi5kbnNjcnlwdC1jZXJ0LmNyeXB0b3N0b3JtLmlz"
	// dctnl does not fetch certs
	// dctnl := "sdns://AQcAAAAAAAAAEzIzLjEzNy4yNDkuMTE2Ojg0NDMgEWD0g0vsKFqwslGBKql8eTiu1RvK2dzZIxLfR7ctlAwXMi5kbnNjcnlwdC1jZXJ0LmRjdC1ubDE"
	// pl fetches certs, but not answers
	// pl := "sdns://AQcAAAAAAAAAFDE3OC4yMTYuMjAxLjEyODoyMDUzIH9hfLgepVPSNMSbwnnHT3tUmAUNHb8RGv7mmWPGR6FpGzIuZG5zY3J5cHQtY2VydC5kbnNjcnlwdC5wbA"
	// swfr := "sdns://AQcAAAAAAAAADjIxMi40Ny4yMjguMTM2IOgBuE6mBr-wusDOQ0RbsV66ZLAvo8SqMa4QY2oHkDJNHzIuZG5zY3J5cHQtY2VydC5mci5kbnNjcnlwdC5vcmc"
	// swams := "sdns://AQcAAAAAAAAADTUxLjE1LjEyMi4yNTAg6Q3ZfapcbHgiHKLF7QFoli0Ty1Vsz3RXs1RUbxUrwZAcMi5kbnNjcnlwdC1jZXJ0LnNjYWxld2F5LWFtcw"
	// dnsbe is down
	// dnsbe := "sdns://AQcAAAAAAAAADzE5My4xOTEuMTg3LjEwNyAzWmXOT_I8k2BKJzxIJ_iYoXRQRWcR0Q1FFyrJWtvogxsyLmRuc2NyeXB0LWNlcnQuZG5zY3J5cHQuYmU"
	// adguard family does not fetch certs
	// agfam := "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"
	// adguard does not fetch certs
	// adguard := "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"
	// cb := "sdns://AQMAAAAAAAAAEzE4NS4yMjguMTY4LjEwOjg0NDMgvKwy-tVDaRcfCDLWB1AnwyCM7vDo6Z-UGNx3YGXUjykRY2xlYW5icm93c2luZy5vcmc"
	q912 := "sdns://AQYAAAAAAAAAEzE0OS4xMTIuMTEyLjEyOjg0NDMgZ8hHuMh1jNEgJFVDvnVnRt803x2EwAuMRwNo34Idhj4ZMi5kbnNjcnlwdC1jZXJ0LnF1YWQ5Lm5ldA"
	tr, err := NewTransport(p, "test", q912)
	if err != nil {
		t.Fatal(err)
	}
	q := aquery("google.com")
	smm := &x.DNSSummary{}
	netw := xdns.NetAndProxyID("udp", ipn.Base)
	// FIXME: querying always fails with EOF
	r, err := tr.Query(netw, q, smm)
	if err != nil {
		log.Output(2, smm.Str())
		t.Fatal(err)
	}
	if len(r) == 0 {
		t.Fatal("empty response")
	}
	ans := xdns.AsMsg(r)
	log.Output(10, ans.Answer[0].String())
}

func aquery(d string) []byte {
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(d), dns.TypeA)
	msg.Id = 1234
	b, _ := msg.Pack()
	return b
}
