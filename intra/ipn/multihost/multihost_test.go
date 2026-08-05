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
	"sync/atomic"
	"testing"
	"time"

	"github.com/celzero/firestack/intra/dialers"
	ilog "github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

type fakeResolver struct {
	*net.Resolver
}

func (r fakeResolver) Lookup(msg *dns.Msg, _ string, _ ...string) (*dns.Msg, error) {
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

func (r fakeResolver) LookupNetIP(ctx context.Context, network, host, uid string, tids ...string) ([]netip.Addr, error) {
	return r.Resolver.LookupNetIP(ctx, network, host)
}

// gatedResolver blocks LookupNetIP until the gate is closed, so tests can hold
// a resolution in-flight deterministically. started counts resolutions begun.
type gatedResolver struct {
	*fakeResolver
	gate    chan struct{}
	started *atomic.Int32
}

func (r *gatedResolver) LookupNetIP(ctx context.Context, network, host, uid string, tids ...string) ([]netip.Addr, error) {
	r.started.Add(1)
	<-r.gate // block until released
	return r.fakeResolver.LookupNetIP(ctx, network, host, uid, tids...)
}

// countingResolver counts resolutions begun, so tests can wait for a
// background resolution to start deterministically.
type countingResolver struct {
	*fakeResolver
	started *atomic.Int32
}

func (r *countingResolver) LookupNetIP(ctx context.Context, network, host, uid string, tids ...string) ([]netip.Addr, error) {
	r.started.Add(1)
	return r.fakeResolver.LookupNetIP(ctx, network, host, uid, tids...)
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within %v", d)
}

func TestMultihostResolveSerialized(t *testing.T) {
	ilog.SetLevel(0)
	settings.Debug = true

	var started atomic.Int32
	gate := make(chan struct{})
	dialers.Mapper(&gatedResolver{fakeResolver: &fakeResolver{}, gate: gate, started: &started})

	h := New("h-serial")
	h.Add([]string{"localhost:53"}) // parse-only; no addrs yet

	// kick off a background resolution that blocks on the gate
	h.resolveAsync([]string{"localhost:53"})

	// wait until the first resolution is in-flight (blocked on the gate)
	waitFor(t, 2*time.Second, func() bool { return started.Load() == 1 })

	// a resolve issued while another is in-flight waits on the mutex;
	// it must not be dropped
	h.resolveAsync([]string{"localhost:80"})

	// release the gate; the first resolution finishes, then the second runs
	close(gate)

	// both resolutions must run to completion
	waitFor(t, 5*time.Second, func() bool { return started.Load() == 2 })

	waitFor(t, 5*time.Second, func() bool {
		for _, a := range h.Addrs() {
			if a.Port() == 80 {
				return true
			}
		}
		return false
	})

	// wait for the background goroutines to finish so they do not race with
	// the next test's global log.SetLevel
	h.resolvMu.Lock() // blocks until the last resolution completes
	n := h.Len()      // sanity: both resolutions appended addrs
	h.resolvMu.Unlock()
	if n < 2 {
		t.Fatalf("expected both resolutions to run; addrs %v", h.Addrs())
	}
}

func TestMultihostRefreshSerialized(t *testing.T) {
	ilog.SetLevel(0)
	settings.Debug = true

	var started atomic.Int32
	gate := make(chan struct{})
	dialers.Mapper(&gatedResolver{fakeResolver: &fakeResolver{}, gate: gate, started: &started})

	h := New("h-refresh-serial")
	h.Add([]string{"localhost:53"}) // parse-only; no addrs yet

	// background resolution holds resolvMu (blocked on the gate)
	h.resolveAsync([]string{"localhost:53"})
	waitFor(t, 2*time.Second, func() bool { return started.Load() == 1 })

	// a synchronous Refresh must wait for the in-flight background resolution
	// (all resolutions serialize on resolvMu)
	done := make(chan int)
	go func() {
		done <- h.Refresh()
	}()

	// refresh must not complete while the background resolution is blocked
	select {
	case n := <-done:
		t.Fatalf("refresh should wait for the in-flight resolution; got %d", n)
	case <-time.After(100 * time.Millisecond):
	}

	// release the gate: background finishes, then refresh runs
	close(gate)

	waitFor(t, 5*time.Second, func() bool { return started.Load() == 2 })
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("refresh did not complete after the gate was released")
	}
}

func TestMultihostEqualAddrs(t *testing.T) {
	ilog.SetLevel(0)
	settings.Debug = true
	dialers.Mapper(&fakeResolver{})

	// unresolved: same names + pre-resolved ips => equal
	h1 := New("eq1")
	h1.Add([]string{"one.one.one.one:53", "1.1.1.1:53"})
	h2 := New("eq2")
	h2.Add([]string{"one.one.one.one:53", "1.1.1.1:53"})
	if !h1.EqualAddrs(h2) {
		t.Fatalf("expected equal (same names + pre); %v != %v", h1.Addrs(), h2.Addrs())
	}

	// unresolved: different names => not equal
	h3 := New("eq3")
	h3.Add([]string{"dns.google:53", "1.1.1.1:53"})
	if h1.EqualAddrs(h3) {
		t.Fatalf("expected not equal (names differ)")
	}

	// unresolved: different pre-resolved ips => not equal
	h4 := New("eq4")
	h4.Add([]string{"one.one.one.one:53", "2.2.2.2:53"})
	if h1.EqualAddrs(h4) {
		t.Fatalf("expected not equal (pre differ)")
	}

	// unresolved: same hostnames in a different order => equal (set semantics)
	h7 := New("eq7")
	h7.Add([]string{"b.com:53", "a.com:53"})
	h8 := New("eq8")
	h8.Add([]string{"a.com:53", "b.com:53"})
	if !h7.EqualAddrs(h8) {
		t.Fatalf("expected equal (order-insensitive names); %v != %v", h7.Names(), h8.Names())
	}

	// resolved: same names resolve to same addrs => equal
	h5 := New("eq5")
	h5.Add([]string{"localhost:53"})
	h5.Build() // sync resolve since no addrs
	h6 := New("eq6")
	h6.Add([]string{"localhost:53"})
	h6.Build()
	if !h5.EqualAddrs(h6) {
		t.Fatalf("expected equal after resolution; %v != %v", h5.Addrs(), h6.Addrs())
	}
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

func TestMultihostBuild(t *testing.T) {
	ilog.SetLevel(0)
	settings.Debug = true

	var started atomic.Int32
	dialers.Mapper(&countingResolver{fakeResolver: &fakeResolver{}, started: &started})

	// Add is parse-only: hostnames are stored, but not resolved
	h := New("h-build")
	h.Add([]string{"localhost:53"})
	if n := len(h.Names()); n != 1 {
		t.Fatalf("expected 1 name, got %d", n)
	}
	if n := len(h.Addrs()); n != 0 {
		t.Fatalf("expected 0 addrs before build, got %d", n)
	}

	// no addrs yet: build resolves synchronously
	if n := h.Build(); n <= 0 {
		t.Fatalf("expected > 0 addrs after build, got %d", n)
	}

	// addrs already exist: build is non-blocking; background resolution appends
	h2 := New("h-build2")
	h2.Add([]string{"localhost:53", "127.0.0.1:53"})
	if n := len(h2.Addrs()); n != 1 { // only the pre-resolved ip
		t.Fatalf("expected 1 pre-resolved addr, got %d", n)
	}
	if n := h2.Build(); n != 1 { // returns immediately with existing addrs
		t.Fatalf("expected 1 addr after non-blocking build, got %d", n)
	}
	// wait for the background goroutine to finish so it does not race with the
	// next test's global log.SetLevel. The sync Build above counts 1, so a
	// count of 2 means the background resolution has begun (and holds
	// resolvMu); acquiring resolvMu then blocks until it fully completes.
	waitFor(t, 3*time.Second, func() bool { return started.Load() >= 2 })
	h2.resolvMu.Lock()     // blocks until the background resolution completes
	got := len(h2.Addrs()) // addrs are final once resolution has completed
	h2.resolvMu.Unlock()
	if got < 2 {
		t.Fatalf("expected background resolution to append addrs, got %d", got)
	}

	// refresh re-resolves names but keeps pre-resolved literal ips
	h3 := New("h-refresh")
	h3.Add([]string{"localhost:53", "127.0.0.1:53"})
	if n := h3.Refresh(); n < 2 {
		t.Fatalf("expected addrs (resolved + pre-resolved) after refresh, got %d", n)
	}
	has := false
	for _, a := range h3.Addrs() {
		if a == netip.MustParseAddrPort("127.0.0.1:53") {
			has = true
			break
		}
	}
	if !has {
		t.Fatalf("expected pre-resolved 127.0.0.1:53 to survive refresh; got %v", h3.Addrs())
	}
}
