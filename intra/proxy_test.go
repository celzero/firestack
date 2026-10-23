// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build ignore

package intra

import (
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	// Removed cyclic import
	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/dns53"
	"github.com/celzero/firestack/intra/ipn"

	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/dnsx"
	ilog "github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/x64"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

type fakeResolver struct {
	*net.Resolver
}

func (r fakeResolver) Lookup(msg *dns.Msg, _ ...string) (*dns.Msg, error) {
	// return nil, errors.New("lookup: not implemented")
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

	return ans, nil
}

func (r fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	// return nil, errors.New("lookup net ip: not implemented")
	return r.Resolver.LookupNetIP(ctx, network, host)
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
	baseNsOpts = &x.DNSOpts{IPCSV: "", TIDCSV: x.CT + "test0"}
	baseTab    = &x.Tab{CID: "testcid", Block: false}
	baseRoutes = settings.IP46
	baseMtu    = 1500
)

func (*fakeBdg) OnQuery(_, _ string, _ int) *x.DNSOpts { return baseNsOpts }
func (*fakeBdg) OnResponse(*x.DNSSummary)              {}
func (*fakeBdg) OnDNSAdded(string)                     {}
func (*fakeBdg) OnDNSRemoved(string)                   {}
func (*fakeBdg) OnDNSStopped()                         {}

func (*fakeBdg) Route(a, b, c, d, e string) *x.Tab { return baseTab }
func (*fakeBdg) OnComplete(*x.ServerSummary)       {}

func TestDot(t *testing.T) {
	netr := &fakeResolver{}
	ctx := context.TODO()
	ctl := &fakeCtl{}
	obs := &fakeObs{}
	bdg := &fakeBdg{Controller: ctl}
	pxr := ipn.NewProxifier(ctx, baseRoutes, baseMtu, ctl, obs)
	ilog.SetLevel(0)
	settings.Debug = true
	dialers.Mapper(netr)

	q := aquery("skysports.com")
	q6 := aaaaquery("skysports.com")
	q2 := aquery("yahoo.com")
	q26 := aaaaquery("yahoo.com")

	// smm := &x.DNSSummary{}
	// smm6 := &x.DNSSummary{}
	_ = xdns.NetAndProxyID("tcp", ipn.Base)
	settings.SetTunMode(
		settings.DNSModePort,
		settings.BlockModeNone,
		settings.PtModeAuto,
	)

	// tr, _ := NewTLSTransport(ctx, "test0", "max.rethinkdns.com", []string{"213.188.216.9"}, pxr, ctl)
	dtr, _ := dns53.NewTransport(ctx, x.Default, "1.1.1.1", "53", pxr)
	tr, _ := dns53.NewTransport(ctx, "test0", "1.0.0.2", "53", pxr)

	natpt := x64.NewNatPt2(ctx)
	natpt.Kickstart(netr)
	resolv := dnsx.NewResolver(ctx, "10.111.222.3:53", dtr, bdg, natpt, pxr)
	resolv.Add(tr)
	r4, err := resolv.Lookup(q)
	r6, err6 := resolv.Lookup(q6)
	_, err = resolv.Lookup(q2)
	_, err = resolv.Lookup(q26)
	time.Sleep(1 * time.Second)
	_, err = resolv.Lookup(q6)
	if err != nil {
		// log.Output(2, smm.Str())
		t.Fatal(err)
	}
	if err6 != nil {
		// log.Output(2, smm6.Str())
		t.Fatal(err6)
	}
	ans := r4
	ans6 := r6
	if xdns.Len(ans) == 0 && xdns.Len(ans6) == 0 {
		t.Fatal("no ans")
	}
	log.Output(10, xdns.Ans(ans))
	log.Output(10, xdns.Ans(ans6))
}

func TestRpnReaches(t *testing.T) {
	netr := &fakeResolver{}
	ctx := context.TODO()
	ctl := &fakeCtl{}
	obs := &fakeObs{}
	bdg := &fakeBdg{Controller: ctl}
	pxr := ipn.NewProxifier(ctx, baseRoutes, baseMtu, ctl, obs)
	ilog.SetLevel(0)
	settings.Debug = true
	dialers.Mapper(netr)

	_ = xdns.NetAndProxyID("tcp", ipn.Base)
	settings.SetTunMode(
		settings.DNSModePort,
		settings.BlockModeNone,
		settings.PtModeAuto,
	)

	tr, _ := dns53.NewTLSTransport(ctx, "test0", "1.1.1.1", nil, pxr)
	dtr, _ := dns53.NewTransport(ctx, x.Default, "1.1.1.1", "53", pxr)

	natpt := x64.NewNatPt2(ctx)
	natpt.Kickstart(netr)
	resolv := dnsx.NewResolver(ctx, "10.111.222.3", dtr, bdg, natpt, pxr)
	resolv.Add(tr)

	if projson, err := os.ReadFile("win.json"); err != nil || len(projson) <= 0 {
		ilog.D("win: read file: err %v", err)
		if projson, err = pxr.RegisterWin(nil, nil, "", nil); err != nil {
			t.Fatal(err)
		} else {
			_ = os.WriteFile("windscribe.json", projson, 0644)
			ilog.D("win: setup %d", len(projson))
		}
	}

	if ips, err := pxr.TestWin(); err != nil {
		t.Fatal(err)
	} else {
		ilog.D("se: %v", ips)
	}

	pro, _ := pxr.ProxyFor(x.RpnWin)
	if ok := ipn.Reaches(pro, "google.com", "tcp"); !ok {
		t.Fail()
	}
	if ok := ipn.Reaches(pro, "9.9.9.10", "tcp"); !ok {
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
