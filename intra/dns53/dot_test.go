// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dns53

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/netip"
	"testing"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/doh"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/ipn/warp"
	ilog "github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/rnet"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/x64"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

type fakeResolver struct {
	*net.Resolver
}

func (r fakeResolver) Lookup(q []byte) ([]byte, error) {
	// return nil, errors.New("lookup: not implemented")
	msg := xdns.AsMsg(q)
	if msg == nil {
		return nil, errors.New("fakeresolver: nil dns msg")
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

func (r fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	// return nil, errors.New("lookup net ip: not implemented")
	return r.Resolver.LookupNetIP(ctx, network, host)
}

func (r fakeResolver) LookupNetIPFor(ctx context.Context, network, host, uid string) ([]netip.Addr, error) {
	// return nil, errors.New("lookup net ip for: not implemented")
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
	// baseNsOpts = &x.DNSOpts{PIDCSV: dnsx.NetBaseProxy, IPCSV: "", TIDCSV: x.CT + "test0"}
	baseTab  = &rnet.Tab{CID: "testcid", Block: false}
	seNsOpts = &x.DNSOpts{PIDCSV: ipn.RpnSE, IPCSV: "", TIDCSV: x.CT + "test0"}
)

func (*fakeBdg) OnQuery(_, _ string, _ int) *x.DNSOpts { return seNsOpts }
func (*fakeBdg) OnResponse(*x.DNSSummary)              {}
func (*fakeBdg) OnDNSAdded(string)                     {}
func (*fakeBdg) OnDNSRemoved(string)                   {}
func (*fakeBdg) OnDNSStopped()                         {}

func (*fakeBdg) Route(a, b, c, d, e string) *rnet.Tab { return baseTab }
func (*fakeBdg) OnComplete(*rnet.ServerSummary)       {}

const minmtu = 1280
const dualstack = settings.IP46

func TestDot(t *testing.T) {
	netr := &fakeResolver{}
	ctx := context.TODO()
	ctl := &fakeCtl{}
	obs := &fakeObs{}
	bdg := &fakeBdg{Controller: ctl}
	pxr := ipn.NewProxifier(ctx, dualstack, minmtu, ctl, obs)
	if pxr == nil {
		t.Fatal("nil proxifier")
	}
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
	_ = xdns.NetAndProxyID("tcp", dnsx.NetBaseProxy)
	tm := settings.NewTunMode(
		settings.DNSModePort,
		settings.BlockModeNone,
		settings.PtModeAuto,
	)

	// tr, _ := NewTLSTransport(ctx, "test0", "max.rethinkdns.com", []string{"213.188.216.9"}, pxr, ctl)
	dtr, _ := NewTransport(ctx, x.Default, "1.1.1.1", "53", pxr)
	tr, _ := NewTransport(ctx, "test0", "1.0.0.2", "53", pxr)

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

func TestProxyReaches(t *testing.T) {
	netr := &fakeResolver{}
	ctx := context.TODO()
	ctl := &fakeCtl{}
	obs := &fakeObs{}
	bdg := &fakeBdg{Controller: ctl}
	pxr := ipn.NewProxifier(ctx, dualstack, minmtu, ctl, obs)
	ilog.SetLevel(0)
	settings.Debug = true
	dialers.Mapper(netr)

	_ = xdns.NetAndProxyID("tcp", dnsx.NetBaseProxy)
	tm := settings.NewTunMode(
		settings.DNSModePort,
		settings.BlockModeNone,
		settings.PtModeAuto,
	)

	tr, _ := NewTLSTransport(ctx, "test0", "1.1.1.1", nil, pxr)
	dtr, _ := NewTransport(ctx, x.Default, "1.1.1.1", "53", pxr)

	natpt := x64.NewNatPt(tm, bdg)
	resolv := dnsx.NewResolver(ctx, "10.111.222.3", tm, dtr, bdg, natpt)
	resolv.Add(tr)

	exit, _ := pxr.ProxyFor(ipn.Exit)
	c, cerr := exit.Dial("tcp", "34.245.245.138:443")
	core.Close(c)
	if cerr != nil {
		t.Fatal(cerr)
	}
	if ok, err := ipn.IcmpReaches(exit, netip.MustParseAddrPort("34.245.245.138:153")); !ok {
		t.Fatal(err)
	}
	t.Log("proxy reaches")
}

func TestSEProxy(t *testing.T) {
	netr := &fakeResolver{}
	ctx := context.TODO()
	ctl := &fakeCtl{}
	obs := &fakeObs{}
	bdg := &fakeBdg{Controller: ctl}
	pxr := ipn.NewProxifier(ctx, dualstack, minmtu, ctl, obs)
	ilog.SetLevel(0)
	settings.Debug = true
	dialers.Mapper(netr)

	_ = xdns.NetAndProxyID("tcp", dnsx.NetBaseProxy)
	tm := settings.NewTunMode(
		settings.DNSModePort,
		settings.BlockModeNone,
		settings.PtModeAuto,
	)

	tr, _ := doh.NewTransport(ctx, "test0", "http://zero.rethinkdns.com/dns-query/", []string{"104.21.83.62"}, pxr)
	dtr, _ := doh.NewTransport(ctx, x.Default, "http://zero.rethinkdns.com/dns-query/", []string{"172.67.214.246"}, pxr)

	natpt := x64.NewNatPt(tm, bdg)
	resolv := dnsx.NewResolver(ctx, "10.111.222.3", tm, dtr, bdg, natpt)
	resolv.Add(tr)

	if err := pxr.RegisterSE(); err != nil {
		t.Fatal(err)
	}
	/*if ips, err := pxr.TestSE(); err != nil {
		t.Fatal(err)
	} else {
		ilog.D("se: %v", ips)
	}*/

	se, _ := pxr.ProxyFor(ipn.RpnSE)
	if ok := ipn.Reaches(se, "google.com", "tcp"); !ok {
		t.Fail()
	}
	t.Log("proxy reaches")

	q := aquery("skysports.com")
	q6 := aaaaquery("skysports.com")

	b4, _ := q.Pack()
	b6, _ := q6.Pack()

	r4, _, err := resolv.Forward(b4)
	r6, _, err6 := resolv.Forward(b6)
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

func TestProtonReaches(t *testing.T) {
	netr := &fakeResolver{}
	ctx := context.TODO()
	ctl := &fakeCtl{}
	obs := &fakeObs{}
	bdg := &fakeBdg{Controller: ctl}
	pxr := ipn.NewProxifier(ctx, dualstack, minmtu, ctl, obs)
	ilog.SetLevel(0)
	settings.Debug = true
	dialers.Mapper(netr)

	_ = xdns.NetAndProxyID("tcp", ipn.Base)
	tm := settings.NewTunMode(
		settings.DNSModePort,
		settings.BlockModeNone,
		settings.PtModeAuto,
	)

	tr, _ := NewTLSTransport(ctx, "test0", "1.1.1.1", nil, pxr)
	dtr, _ := NewTransport(ctx, x.Default, "1.1.1.1", "53", pxr)

	natpt := x64.NewNatPt(tm, bdg)
	resolv := dnsx.NewResolver(ctx, "10.111.222.3", tm, dtr, bdg, natpt)
	resolv.Add(tr)

	var projson []byte
	var err error
	if projson, err = pxr.RegisterProton(nil); err != nil {
		t.Fatal(err)
	}
	if ips, err := pxr.TestProton(); err != nil {
		t.Fatal(err)
	} else {
		ilog.D("se: %v", ips)
	}

	var pro warp.ProtonWgConfig
	if err = json.Unmarshal(projson, &pro); err != nil {
		t.Fatal(err)
	}

	const maxVisited = 6
	once := false
	visited := make(map[string]struct{}, 0)
	for _, c := range pro.RegionalWgConfs {
		if _, ok := visited[c.CC]; !ok {
			ilog.I("adding proxy %s %s", c.CC, c.Name)
			_, _ = pxr.AddProxy(ipn.RpnPro+c.CC, c.UapiConfig())
			visited[c.CC] = struct{}{}
		}
		if !once {
			ilog.I("adding default proxy %s", ipn.RpnPro, c.Name)
			pxr.AddProxy(ipn.RpnPro, c.UapiConfig())
			once = true
		}
		if len(visited) >= maxVisited {
			break
		}
	}

	propx, _ := pxr.ProxyFor(ipn.RpnPro)
	propx2, _ := pxr.ProxyFor(ipn.RpnPro + "MX")
	ilog.I("proxies 1: %t; 2: %t", propx != nil, propx2 != nil)
	if ok := ipn.Reaches(propx, "google.com:443", "tcp"); !ok {
		t.Fail()
	}
	if ok := ipn.Reaches(propx2, "cloudflare.com:443", "tcp"); !ok {
		t.Fail()
	}
	t.Log("proxy reaches")
}

func TestPinger(t *testing.T) {
	netr := &fakeResolver{}
	ctx := context.TODO()
	ctl := &fakeCtl{}
	obs := &fakeObs{}
	_ = &fakeBdg{Controller: ctl}
	pxr := ipn.NewProxifier(ctx, dualstack, minmtu, ctl, obs)
	ilog.SetLevel(0)
	settings.Debug = true
	dialers.Mapper(netr)

	p, err := pxr.ProxyFor(ipn.Exit)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := p.Probe("udp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	ok, rtt, err := core.Ping(pc, netip.MustParseAddrPort("1.1.1.1:53"))
	if !ok {
		t.Fatalf("ping failed %v", err)
	}
	t.Log("ping rtt", rtt)
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
