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
	"os"
	"testing"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/doh"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/ipn/rpn"
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

func (r fakeResolver) LocalLookup(q []byte) ([]byte, error) {
	return r.Lookup(q, protect.UidSelf)
}

func (r fakeResolver) Lookup(q []byte, _ string, _ ...string) ([]byte, error) {
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
	return r.LocalLookup(q)
}

func (r fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	// return nil, errors.New("lookup net ip: not implemented")
	return r.Resolver.LookupNetIP(ctx, network, host)
}

func (r fakeResolver) LookupNetIPFor(ctx context.Context, network, host, uid string) ([]netip.Addr, error) {
	// return nil, errors.New("lookup net ip for: not implemented")
	return r.Resolver.LookupNetIP(ctx, network, host)
}

func (r fakeResolver) LookupNetIPOn(ctx context.Context, network, host string, tid ...string) ([]netip.Addr, error) {
	return nil, errors.New("fakeResolver: lookup net ip on not implemented")
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
	baseTab    = &x.Tab{CID: "testcid", Block: false}
	autoNsOpts = &x.DNSOpts{PIDCSV: x.RpnWin, IPCSV: "", TIDCSV: x.CT + "test0"}
)

func (*fakeBdg) OnQuery(_, _, _ string, _ int) *x.DNSOpts              { return autoNsOpts }
func (*fakeBdg) OnUpstreamAnswer(_ *x.DNSSummary, _ string) *x.DNSOpts { return nil }
func (*fakeBdg) OnResponse(*x.DNSSummary)                              {}
func (*fakeBdg) OnDNSAdded(string)                                     {}
func (*fakeBdg) OnDNSRemoved(string)                                   {}
func (*fakeBdg) OnDNSStopped()                                         {}

func (*fakeBdg) Route(a, b, c, d, e string) *x.Tab { return baseTab }
func (*fakeBdg) OnComplete(*x.ServerSummary)       {}

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
	// tr, _ := NewTLSTransport(ctx, "test0", "max.rethinkdns.com", []string{"213.188.216.9"}, pxr, ctl)
	dtr, _ := NewTransport(ctx, x.Default, "1.1.1.1", "53", pxr)
	tr, _ := NewTransport(ctx, "test0", "1.0.0.2", "53", pxr)
	if tr == nil || dtr == nil {
		t.Fatal("nil dns transports")
	}

	natpt := x64.NewNatPt()
	resolv := dnsx.NewResolver(ctx, "10.111.222.3:53", dtr, bdg, natpt)
	resolv.Add(tr)
	r4, _, err := resolv.LocalLookup(b4)
	r6, _, err6 := resolv.LocalLookup(b6)
	_, _, _ = resolv.LocalLookup(b24)
	_, _, _ = resolv.LocalLookup(b26)
	time.Sleep(1 * time.Second)
	_, _, _ = resolv.LocalLookup(b6)
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
	if pxr == nil {
		t.Fatal("nil proxifier")
	}
	ilog.SetLevel(0)
	settings.Debug = true
	dialers.Mapper(netr)

	_ = xdns.NetAndProxyID("tcp", dnsx.NetBaseProxy)
	tr, _ := NewTLSTransport(ctx, "test0", "1.1.1.1", nil, pxr)
	dtr, _ := NewTransport(ctx, x.Default, "1.1.1.1", "53", pxr)
	if tr == nil || dtr == nil {
		t.Fatal("nil dns transports")
	}

	natpt := x64.NewNatPt()
	resolv := dnsx.NewResolver(ctx, "10.111.222.3", dtr, bdg, natpt)
	resolv.Add(tr)

	exit, _ := pxr.ProxyFor(ipn.Exit)
	if exit == nil {
		t.Fatal("proxy: exit proxy nil")
	}

	c1, _ := exit.Dial("tcp", "google.com:443")
	c2, _ := exit.Dial("tcp", "cloudflare.com:443")
	c3, _ := exit.Dial("tcp", "microsoft.com:443")
	core.Close(c1, c2, c3)
	if ok := ipn.Reaches(exit, "auto:https"); !ok {
		t.Fatal("does not reach auto:https (google/cloudflare/microsoft)")
	}
	if ok, err := ipn.IcmpReaches(exit, netip.MustParseAddrPort("34.245.245.138:153")); !ok {
		t.Fatal(err) // always fails
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
	if pxr == nil {
		t.Fatal("nil proxifier")
	}
	ilog.SetLevel(0)
	settings.Debug = true
	dialers.Mapper(netr)

	_ = xdns.NetAndProxyID("tcp", dnsx.NetBaseProxy)

	tr, _ := doh.NewTransport(ctx, "test0", "http://zero.rethinkdns.com/dns-query/", []string{"104.21.83.62"}, pxr)
	dtr, _ := doh.NewTransport(ctx, x.Default, "http://zero.rethinkdns.com/dns-query/", []string{"172.67.214.246"}, pxr)
	if tr == nil || dtr == nil {
		t.Fatal("nil dns transports")
	}

	natpt := x64.NewNatPt()
	resolv := dnsx.NewResolver(ctx, "10.111.222.3:53", dtr, bdg, natpt)
	resolv.Add(tr)

	if err := pxr.RegisterSE(); err != nil {
		t.Fatal(err)
	}
	/*if ips, err := pxr.TestSE(); err != nil {
		t.Fatal(err)
	} else {
		ilog.D("se: %v", ips)
	}*/

	autoNsOpts.PIDCSV = ipn.RpnSE
	se, _ := pxr.ProxyFor(ipn.RpnSE)
	if se == nil {
		t.Fatal("proxy: se proxy nil")
	}

	if ok := ipn.Reaches(se, "google.com", "tcp"); !ok {
		t.Fail()
	}
	t.Log("proxy reaches")

	q := aquery("skysports.com")
	q6 := aaaaquery("skysports.com")

	b4, _ := q.Pack()
	b6, _ := q6.Pack()

	r4, _, err := resolv.LocalLookup(b4)
	r6, _, err6 := resolv.LocalLookup(b6)
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

func TestWgReaches(t *testing.T) {
	netr := &fakeResolver{}
	ctx := context.TODO()
	ctl := &fakeCtl{}
	obs := &fakeObs{}
	bdg := &fakeBdg{Controller: ctl}
	pxr := ipn.NewProxifier(ctx, dualstack, minmtu, ctl, obs)
	if pxr == nil {
		t.Fatal("testwg: nil proxifier")
	}
	ilog.SetLevel(0)
	settings.Debug = true
	dialers.Mapper(netr)

	wgid := x.WG + "1111"
	autoNsOpts.PIDCSV = wgid

	_ = xdns.NetAndProxyID("tcp", wgid)

	tr, _ := NewTLSTransport(ctx, "test0", "8.8.8.8", nil, pxr)
	dtr, _ := NewTransport(ctx, x.Default, "1.1.1.1", "53", pxr)
	if tr == nil || dtr == nil {
		t.Fatal("nil dns transports")
	}

	natpt := x64.NewNatPt()
	resolv := dnsx.NewResolver(ctx, "10.111.222.3:53", dtr, bdg, natpt)
	resolv.Add(tr)

	wgconf, err := os.ReadFile("wg.conf")
	if err != nil {
		t.Fatal(err)
	}

	// read wgconf json into regionalwgconf

	rwg := &rpn.RegionalWgConf{}
	if err := json.Unmarshal(wgconf, rwg); err != nil {
		t.Fatal(err)
	}

	ilog.D("testwg: read wg: %s: %d", rwg.Name, len(wgconf))

	confok := rwg.GenUapiConfig()
	if !confok {
		t.Fatal("testwg: gen uapi conf failed")
	}

	win, err := pxr.AddProxy(wgid, rwg.UapiWgConf)
	ko(t, err)

	ilog.D("testwg: setup %s: %d", rwg.Name, len(rwg.UapiWgConf))

	if win == nil {
		t.Fatal("testwg: nil main ws proxy")
	}

	settings.SetAutoDialsParallel(false)
	settings.SetAutoMode(settings.AutoModeRemote)

	propx, _ := pxr.ProxyFor(wgid)
	if propx == nil {
		t.Fatal("testwg: nil proxies")
	}

	/*ilog.VV("-----------------------MAIN--------------------------")
	ilog.I("proxies 1: %t; 2: %t, 3: %t", propx != nil, propx2 != nil, auto != nil)
	if ok := ipn.Reaches(propx, "google.com:443", "tcp"); !ok {
		t.Fail()
	}
	ilog.VV("-----------------------MXCO--------------------------")
	if ok := ipn.Reaches(propx2, "cloudflare.com:443", "tcp"); !ok {
		t.Fail()
	}
	ilog.VV("-----------------------AUTO--------------------------")
	if ok := ipn.Reaches(auto, "x.com:443", "tcp"); !ok {
		t.Fail()
	}*/
	ilog.VV("-----------------------DNSX--------------------------")
	b4, _ := aquery("skysports.com").Pack()
	r4, _, err := resolv.LocalLookup(b4) // must use "test0"

	ilog.D("testwg: %v", win.Router().Stat())
	time.Sleep(2 * time.Second)

	ko(t, err)

	ans := xdns.AsMsg(r4)
	if xdns.Len(ans) <= 0 {
		t.Fatal("testwg: no ans")
	}
	ilog.D("dns %s", xdns.Ans(ans))
	ilog.VV("-----------------------END0--------------------------")

	t.Log("testwg: proxy reaches")
}

func TestWinReaches(t *testing.T) {
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

	_ = xdns.NetAndProxyID("tcp", ipn.Auto)

	tr, _ := NewTLSTransport(ctx, "test0", "8.8.8.8", nil, pxr)
	dtr, _ := NewTransport(ctx, x.Default, "1.1.1.1", "53", pxr)
	if tr == nil || dtr == nil {
		t.Fatal("nil dns transports")
	}

	natpt := x64.NewNatPt()
	resolv := dnsx.NewResolver(ctx, "10.111.222.3:53", dtr, bdg, natpt)
	resolv.Add(tr)

	readWinJson := true
	entjson, err := os.ReadFile("win.json")
	if err != nil {
		readWinJson = false
		entjson, err = os.ReadFile("ent.json")
	}
	ko(t, err)

	const did = "deadbeefdeadbeefdeadbeefdeadbeef" // some device id
	ilog.D("ws: read ent (sess? %t): %d", readWinJson, len(entjson))
	if wreg, err := pxr.RegisterWin(entjson, did); err != nil {
		t.Fatal(err)
	} else {
		entjson = wreg
		_ = os.WriteFile("win.json", entjson, 0644) // same as sess.json
		ilog.D("ws: setup %d", len(entjson))
	}

	win, err := pxr.Win()
	ko(t, err)
	if win == nil {
		t.Fatal("nil main ws proxy")
	}

	const maxVisited = 10
	visited := make(map[string]struct{}, 0)
	locs, err := win.Locations()
	ko(t, err)
	if locs == nil {
		t.Fatalf("expected locations for %s", win.Who())
	}
	for i := 0; i < locs.Len(); i++ {
		c, err := locs.Get(i)
		if err != nil {
			continue
		}
		if _, ok := visited[c.CC]; !ok {
			// _, _ = pxr.AddProxy(ipn.RpnPro+c.CC, c.UapiConfig())
			visited[c.CC] = struct{}{}
		}
		if len(visited) >= maxVisited {
			break
		}
	}
	ilog.I("available proxy CCs (limited to 10): %v", visited)

	_, err = win.Fork("US")
	ko(t, err)
	_, err = win.Fork("GT")
	ko(t, err)

	settings.SetAutoDialsParallel(false)
	settings.SetAutoMode(settings.AutoModeRemote)

	propx, _ := pxr.ProxyFor(ipn.RpnWin)
	propx2, _ := pxr.ProxyFor(ipn.RpnWin + "GT")
	auto, _ := pxr.ProxyFor(ipn.Auto)
	if propx == nil || propx2 == nil || auto == nil {
		t.Fatal("nil US/GT/Auto proxies")
	}

	sess, err := win.State()
	ko(t, err)
	err = os.WriteFile("sess.json", sess, 0644) // same as win.json
	ko(t, err)

	autoNsOpts.PIDCSV = ipn.RpnWin
	/*ilog.VV("-----------------------MAIN--------------------------")
	ilog.I("proxies 1: %t; 2: %t, 3: %t", propx != nil, propx2 != nil, auto != nil)
	if ok := ipn.Reaches(propx, "google.com:443", "tcp"); !ok {
		t.Fail()
	}
	ilog.VV("-----------------------MXCO--------------------------")
	if ok := ipn.Reaches(propx2, "cloudflare.com:443", "tcp"); !ok {
		t.Fail()
	}
	ilog.VV("-----------------------AUTO--------------------------")
	if ok := ipn.Reaches(auto, "x.com:443", "tcp"); !ok {
		t.Fail()
	}*/
	ilog.VV("-----------------------DNSX--------------------------")
	b4, _ := aquery("skysports.com").Pack()
	r4, _, err := resolv.LocalLookup(b4) // must use "test0"

	ilog.D("%v", propx2.Router().Stat())
	time.Sleep(2 * time.Second)

	if err != nil {
		t.Fatal(err)
	}

	ans := xdns.AsMsg(r4)
	if xdns.Len(ans) <= 0 {
		t.Fatal("no ans")
	}
	ilog.D("dns", xdns.Ans(ans))
	ilog.VV("-----------------------END0--------------------------")

	t.Log("proxy reaches")
}

func TestPinger(t *testing.T) {
	netr := &fakeResolver{}
	ctx := context.TODO()
	ctl := &fakeCtl{}
	obs := &fakeObs{}
	_ = &fakeBdg{Controller: ctl}
	pxr := ipn.NewProxifier(ctx, dualstack, minmtu, ctl, obs)
	if pxr == nil {
		t.Fatal("nil proxifier")
	}
	ilog.SetLevel(0)
	settings.Debug = true
	dialers.Mapper(netr)

	p, err := pxr.ProxyFor(ipn.Exit)
	if err != nil || p == nil {
		t.Fatal(err)
	}
	pc, err := p.Probe("udp", "0.0.0.0:0")
	if err != nil || pc == nil {
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

func ko(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}
