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
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"net/url"
	"os"
	"runtime/trace"
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
	"github.com/showwin/speedtest-go/speedtest"
)

type fakeResolver struct {
	*net.Resolver
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
	if r.Resolver == nil {
		r.Resolver = net.DefaultResolver
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

func (r fakeResolver) LookupNetIP(ctx context.Context, network, host, uid string, tids ...string) ([]netip.Addr, error) {
	if r.Resolver == nil {
		r.Resolver = net.DefaultResolver
	}
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

func (*fakeObs) OnProxyAdded(string, string)   {}
func (*fakeObs) OnProxyRemoved(string, string) {}
func (*fakeObs) OnProxyUpdated(string, string) {}
func (*fakeObs) OnProxiesStopped()             {}

type fakeBdg struct {
	protect.Controller
	x.DNSListener
}

var (
	// baseNsOpts = &x.DNSOpts{PIDCSV: dnsx.NetBaseProxy, IPCSV: "", TIDCSV: x.CT + "test0"}
	baseTab    = &x.Tab{CID: "testcid", Block: false}
	autoNsOpts = &x.DNSOpts{IPCSV: "", TIDCSV: x.CT + "test0:" + x.RpnWin}
)

func (*fakeBdg) OnQuery(_, _, _ string, _ int) *x.DNSOpts { return autoNsOpts }
func (*fakeBdg) OnUpstreamAnswer(_ string, _ *x.DNSSummary, _ *x.DNSOpts, _ string) *x.DNSOpts {
	return nil
}
func (*fakeBdg) OnResponse(*x.DNSSummary) {}
func (*fakeBdg) OnDNSAdded(string)        {}
func (*fakeBdg) OnDNSRemoved(string)      {}
func (*fakeBdg) OnDNSStopped()            {}

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
	r4, err := resolv.Lookup(b4, protect.MyUid)
	ko(t, err)
	r6, err6 := resolv.Lookup(b6, protect.MyUid)
	ko(t, err6)
	_, err = resolv.Lookup(b24, protect.MyUid)
	ko(t, err)
	_, err = resolv.Lookup(b26, protect.MyUid)
	ko(t, err)
	time.Sleep(1 * time.Second)
	_, err = resolv.Lookup(b6, protect.MyUid)
	ko(t, err)
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

	/*if err := pxr.RegisterSE(); err != nil {
		t.Fatal(err)
	}
	if ips, err := pxr.TestSE(); err != nil {
		t.Fatal(err)
	} else {
		ilog.D("se: %v", ips)
	}

	autoNsOpts.PIDCSV = ipn.RpnSE
	se, _ := pxr.ProxyFor(ipn.RpnSE)
	if se == nil {
		t.Fatal("proxy: se proxy nil")
	}

	if ok := ipn.Reaches(se, "google.com", "tcp"); !ok {
		t.Fail()
	}
	t.Log("proxy reaches")*/

	q := aquery("skysports.com")
	q6 := aaaaquery("skysports.com")

	b4, _ := q.Pack()
	b6, _ := q6.Pack()

	r4, err := resolv.Lookup(b4, protect.MyUid)
	r6, err6 := resolv.Lookup(b6, protect.MyUid)
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
	autoNsOpts.TIDCSV = x.CT + "test0:" + wgid

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
	r4, err := resolv.Lookup(b4, protect.MyUid) // must use "test0"

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

	ilog.D("ws: read ent (sess? %t): %d", readWinJson, len(entjson))

	ent, err := pxr.EntitlementFrom(entjson, x.RpnWin, "")
	ko(t, err)

	if ent == nil {
		t.Fatal("nil entitlement")
		return
	}

	// const did = "deadbeefdeadbeefdeadbeefdeadbeef" // some device id

	if wreg, err := pxr.RegisterWin(entjson, ent.DID(), nil); err != nil {
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
		return
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

	p1, err := win.Fork("US")
	ko(t, err)
	p2, err := win.Fork("CA")
	ko(t, err)

	if p1 == nil || p2 == nil {
		t.Fatal("nil US/CA proxies")
	}

	settings.SetAutoDialsParallel(false)
	settings.SetAutoMode(settings.AutoModeRemote)

	propx, _ := pxr.ProxyFor(ipn.RpnWin)
	propx2, _ := pxr.ProxyFor(p2.ID())
	auto, _ := pxr.ProxyFor(ipn.Auto)
	if propx == nil || propx2 == nil || auto == nil {
		t.Fatal("nil US/CA/Auto proxies")
	}

	ilog.VV("win proxies Auto >> %s / CA >> %s", p1.ID(), p2.ID())

	sess, err := win.State()
	ko(t, err)
	err = os.WriteFile("sess.json", sess, 0644) // same as win.json
	ko(t, err)

	autoNsOpts.TIDCSV = x.CT + "test0:" + ipn.RpnWin
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
	ilog.VV("\n-----------------------DNSX--------------------------\n")
	b4, _ := aquery("skysports.com").Pack()
	r4, err := resolv.Lookup(b4, protect.MyUid) // must use "test0"
	ko(t, err)

	ilog.D("%v", propx2.Router().Stat())
	time.Sleep(2 * time.Second)

	ilog.VV("\n-----------------------DIAL--------------------------\n")
	u, _ := url.Parse("https://tnreginet.gov.in/")
	c1 := ipn.HttpClient(propx, "tcp", 20*time.Second)
	r, err := c1.Get(u.String())
	ko(t, err)

	if r == nil {
		t.Fatalf("nil response from %s", u.String())
	}
	if body := r.Body; body != nil {
		defer body.Close()
	}

	b, err := io.ReadAll(r.Body)
	if len(b) <= 0 || b == nil || err != nil {
		t.Fatal("failed to read body", err)
	}
	l := min(len(b), 800)
	ilog.VV(string(b[:l]))
	if r.StatusCode != 200 {
		t.Fatal("unexpected status code", r.StatusCode)
	}

	ko(t, err)
	ilog.VV("\n-----------------------DEND--------------------------\n")

	if err != nil {
		t.Fatal(err)
	}

	ans := xdns.AsMsg(r4)
	if xdns.Len(ans) <= 0 {
		t.Fatal("no ans")
	}
	ilog.D("dns %v", xdns.Ans(ans))
	ilog.VV("\n-----------------------END0--------------------------\n")

	t.Log("proxy reaches")
}

func TestWinDownloadSpeed(t *testing.T) {
	// start flight recorder; captures a moving window of trace data
	fr := trace.NewFlightRecorder(trace.FlightRecorderConfig{
		MinAge: 65 * time.Second, // slightly longer than the test timeout
	})
	if err := fr.Start(); err != nil {
		t.Fatalf("flight recorder start: %v", err)
	}
	defer fr.Stop()

	netr := &fakeResolver{}
	ctx := context.TODO()
	ctl := &fakeCtl{}
	obs := &fakeObs{}
	bdg := &fakeBdg{Controller: ctl}
	pxr := ipn.NewProxifier(ctx, dualstack, minmtu, ctl, obs)
	if pxr == nil {
		t.Fatal("nil proxifier")
	}
	ilog.SetLevel(ilog.INFO)
	settings.Debug = false
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

	ilog.D("ws: read ent (sess? %t): %d", readWinJson, len(entjson))

	ent, err := pxr.EntitlementFrom(entjson, x.RpnWin, "")
	ko(t, err)

	if ent == nil {
		t.Fatal("nil entitlement")
		return
	}

	if wreg, err := pxr.RegisterWin(entjson, ent.DID(), nil); err != nil {
		t.Fatal(err)
	} else {
		entjson = wreg
		_ = os.WriteFile("win.json", entjson, 0644)
		ilog.D("ws: setup %d", len(entjson))
	}

	win, err := pxr.Win()
	ko(t, err)
	if win == nil {
		t.Fatal("nil main ws proxy")
	}

	settings.SetAutoDialsParallel(false)
	settings.SetAutoMode(settings.AutoModeRemote)

	propx, _ := pxr.ProxyFor(ipn.RpnWin)
	if propx == nil {
		t.Fatal("nil RpnWin proxy")
	}

	// create an HTTP client that dials through the RPN proxy
	proxyClient := ipn.HttpClient(propx, "tcp", 60*time.Second)

	// create a speedtest client with the proxy-routed HTTP client
	st := speedtest.New(speedtest.WithDoer(proxyClient))

	serverList, err := st.FetchServers()
	ko(t, err)

	targets, err := serverList.FindServer([]int{})
	ko(t, err)

	if len(targets) == 0 {
		t.Fatal("no speedtest servers found via RPN")
	}

	s := targets[0]
	ilog.I("speedtest: server [%s] %s (%s) by %s", s.ID, s.Name, s.Country, s.Sponsor)

	ko(t, s.PingTest(nil))
	ilog.I("speedtest: latency: %s, jitter: %s", s.Latency, s.Jitter)

	ko(t, s.DownloadTest())
	ilog.I("speedtest: download: %s (%.2f Mbps)", s.DLSpeed, float64(s.DLSpeed)*8/1e6)

	ko(t, s.UploadTest())
	ilog.I("speedtest: upload: %s (%.2f Mbps)", s.ULSpeed, float64(s.ULSpeed)*8/1e6)

	t.Logf("speedtest via RPN: server [%s] %s, latency: %s, jitter: %s, download: %s, upload: %s",
		s.ID, s.Name, s.Latency, s.Jitter, s.DLSpeed, s.ULSpeed)

	// snapshot the flight recorder's moving window to disk
	tracefile := fmt.Sprintf("speed_%d.fr", time.Now().Unix())
	f, err := os.Create(tracefile)
	if err != nil {
		t.Fatalf("create trace file %s: %v", tracefile, err)
	}
	defer f.Close()
	n, err := fr.WriteTo(f)
	if err != nil {
		t.Fatalf("write trace to %s: %v", tracefile, err)
	}
	ilog.I("speedtest: trace written to %s (%d bytes)", tracefile, n)
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
