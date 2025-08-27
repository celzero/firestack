// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build ignore
// +build ignore

// cyclic imports

package ipn

import (
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"testing"
	"time"

	// Removed cyclic import
	// x "github.com/celzero/firestack/intra/backend"
	// 	"github.com/celzero/firestack/intra/dns53"
	// 	"github.com/celzero/firestack/intra/rnet"

	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/dns53"
	"github.com/celzero/firestack/intra/dnsx"
	ilog "github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/rnet"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/x64"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

type fakeResolver struct{ *net.Resolver }

func (r fakeResolver) Lookup([]byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (r fakeResolver) LookupOn([]byte, ...string) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (r fakeResolver) LookupNetIPFor(ctx context.Context, network, host, uid string) ([]netip.Addr, error) {
	return nil, errors.New("not implemented")
}

type fakeCtl struct {
	protect.Controller
}

func (*fakeCtl) Bind4(_, _ string, _ int) {}
func (*fakeCtl) Bind6(_, _ string, _ int) {}
func (*fakeCtl) Protect(_ string, _ int)  {}

type fakeObs struct {
	x.ProxyListener
}

func (*fakeObs) OnProxyAdded(string)   {}
func (*fakeObs) OnProxyRemoved(string) {}
func (*fakeObs) OnProxiesStopped()     {}

type fakeBdg struct {
	protect.Controller
	x.DNSListener
}

var (
	baseNsOpts = &x.DNSOpts{PIDCSV: dnsx.NetNoProxy, IPCSV: "", TIDCSV: x.CT + "test0"}
	baseTab    = &rnet.Tab{CID: "testcid", Block: false}
)

func (*fakeBdg) OnQuery(_, _ string, _ int) *x.DNSOpts { return baseNsOpts }
func (*fakeBdg) OnResponse(*x.DNSSummary)              {}
func (*fakeBdg) OnDNSAdded(string)                     {}
func (*fakeBdg) OnDNSRemoved(string)                   {}
func (*fakeBdg) OnDNSStopped()                         {}

func (*fakeBdg) Route(a, b, c, d, e string) *rnet.Tab { return baseTab }
func (*fakeBdg) OnComplete(*rnet.ServerSummary)       {}

func TestDot(t *testing.T) {
	netr := &fakeResolver{}
	ctx := context.TODO()
	ctl := &fakeCtl{}
	obs := &fakeObs{}
	bdg := &fakeBdg{Controller: ctl}
	pxr := NewProxifier(ctx, ctl, obs)
	ilog.SetLevel(0)
	settings.Debug = true
	dialers.Mapper(netr)

	q := aquery("skysports.com")
	q6 := aaaaquery("skysports.com")
	q2 := aquery("yahoo.com")
	q26 := aaaaquery("yahoo.com")

	b4, _ := q.Pack()
	b6, _ := q6.Pack()
	b24, _ := q2.Pack()
	b26, _ := q26.Pack()
	// smm := &x.DNSSummary{}
	// smm6 := &x.DNSSummary{}
	_ = xdns.NetAndProxyID("tcp", Base)
	tm := settings.NewTunMode(
		settings.DNSModePort,
		settings.BlockModeNone,
		settings.PtModeAuto,
	)

	// tr, _ := NewTLSTransport(ctx, "test0", "max.rethinkdns.com", []string{"213.188.216.9"}, pxr, ctl)
	dtr, _ := dns53.NewTransport(ctx, x.Default, "1.1.1.1", "53", pxr)
	tr, _ := dns53.NewTransport(ctx, "test0", "1.0.0.2", "53", pxr)

	natpt := x64.NewNatPt(tm, bdg)
	resolv := dnsx.NewResolver(ctx, "10.111.222.3:53", tm, dtr, bdg, natpt)
	resolv.Add(tr)
	r4, _, err := resolv.Forward(b4)
	r6, _, err6 := resolv.Forward(b6)
	_, _, _ = resolv.Forward(b24)
	_, _, _ = resolv.Forward(b26)
	time.Sleep(1 * time.Second)
	_, _, _ = resolv.Forward(b6)
	if err != nil {
		// log.Output(2, smm.Str())
		t.Fatal(err)
	}
	if err6 != nil {
		// log.Output(2, smm6.Str())
		t.Fatal(err6)
	}
	ans := xdns.AsMsg(r4)
	ans6 := xdns.AsMsg(r6)
	if xdns.Len(ans) == 0 && xdns.Len(ans6) == 0 {
		t.Fatal("no ans")
	}
	log.Output(10, xdns.Ans(ans))
	log.Output(10, xdns.Ans(ans6))
}

func TestSEProxy(t *testing.T) {
	netr := &fakeResolver{}
	ctx := context.TODO()
	ctl := &fakeCtl{}
	obs := &fakeObs{}
	bdg := &fakeBdg{Controller: ctl}
	pxr := NewProxifier(ctx, ctl, obs)
	ilog.SetLevel(0)
	settings.Debug = true
	dialers.Mapper(netr)

	_ = xdns.NetAndProxyID("tcp", Base)
	tm := settings.NewTunMode(
		settings.DNSModePort,
		settings.BlockModeNone,
		settings.PtModeAuto,
	)

	tr, _ := dns53.NewTLSTransport(ctx, "test0", "1.1.1.1", nil, pxr)
	dtr, _ := dns53.NewTransport(ctx, x.Default, "1.1.1.1", "53", pxr)

	natpt := x64.NewNatPt(tm, bdg)
	resolv := dnsx.NewResolver(ctx, "10.111.222.3", tm, dtr, bdg, natpt)
	resolv.Add(tr)

	if err := pxr.RegisterSE(); err != nil {
		t.Fatal(err)
	}
	if ips, err := pxr.TestSE(); err != nil {
		t.Fatal(err)
	} else {
		ilog.D("se: %v", ips)
	}

	se, _ := pxr.ProxyFor(RpnSE)
	if ok := Reaches(se, "google.com", "tcp"); !ok {
		t.Fail()
	}
	t.Log("proxy reaches")
}

func TestProxyReaches(t *testing.T) {
	netr := &fakeResolver{}
	ctx := context.TODO()
	ctl := &fakeCtl{}
	obs := &fakeObs{}
	bdg := &fakeBdg{Controller: ctl}
	pxr := NewProxifier(ctx, ctl, obs)
	ilog.SetLevel(0)
	settings.Debug = true
	dialers.Mapper(netr)

	_ = xdns.NetAndProxyID("tcp", Base)
	tm := settings.NewTunMode(
		settings.DNSModePort,
		settings.BlockModeNone,
		settings.PtModeAuto,
	)

	tr, _ := dns53.NewTLSTransport(ctx, "test0", "1.1.1.1", nil, pxr)
	dtr, _ := dns53.NewTransport(ctx, x.Default, "1.1.1.1", "53", pxr)

	natpt := x64.NewNatPt(tm, bdg)
	resolv := dnsx.NewResolver(ctx, "10.111.222.3", tm, dtr, bdg, natpt)
	resolv.Add(tr)

	var projson []byte
	var err error
	if projson, err = pxr.RegisterWin(nil); err != nil {
		t.Fatal(err)
	}
	if ips, err := pxr.TestWin(); err != nil {
		t.Fatal(err)
	} else {
		ilog.D("se: %v", ips)
	}

	pxr.AddProxy(RpnWin)

	se, _ := pxr.ProxyFor(RpnWin)
	if ok := Reaches(se, "google.com", "tcp"); !ok {
		t.Fail()
	}
	t.Log("proxy reaches")
}

func TestWindscribeReaches(t *testing.T) {
	netr := &fakeResolver{}
	ctx := context.TODO()
	ctl := &fakeCtl{}
	obs := &fakeObs{}
	bdg := &fakeBdg{Controller: ctl}
	pxr := NewProxifier(ctx, ctl, obs)
	ilog.SetLevel(0)
	settings.Debug = true
	dialers.Mapper(netr)

	_ = xdns.NetAndProxyID("tcp", Base)
	tm := settings.NewTunMode(
		settings.DNSModePort,
		settings.BlockModeNone,
		settings.PtModeAuto,
	)

	tr, _ := dns53.NewTLSTransport(ctx, "test0", "1.1.1.1", nil, pxr)
	dtr, _ := dns53.NewTransport(ctx, x.Default, "1.1.1.1", "53", pxr)

	natpt := x64.NewNatPt(tm, bdg)
	resolv := dnsx.NewResolver(ctx, "10.111.222.3", tm, dtr, bdg, natpt)
	resolv.Add(tr)

	exit, _ := pxr.ProxyFor(Exit)
	if ok := Reaches(exit, "1.1.1.1:153"); !ok {
		t.Fail()
	}
	t.Log("proxy reaches")
}

func aquery(d string) *dns.Msg {
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(d), dns.TypeA)
	msg.Id = 1234
	return msg
}

func aaaaquery(d string) *dns.Msg {
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(d), dns.TypeAAAA)
	msg.Id = 3456
	return msg
}
