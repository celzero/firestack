// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

import (
	"context"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"
)

func mustAddr(s string) netip.Addr {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return ip
}

// newTestGateway returns a dnsgateway with caches enabled (chash) for tests.
func newTestGateway() *dnsgateway {
	return NewDNSGateway(context.Background(), nil, nil, nil)
}

// TestRegisterLockedTTLClamp asserts that the xips and alg-answer ttls are
// floored at ttl8s but otherwise carry the upstream answer's ttl (no cap).
func TestRegisterLockedTTLClamp(t *testing.T) {
	cases := []struct {
		name    string
		ttlIn   time.Duration
		wantTTL time.Duration // expected ttl for both ansttl and xipsttl
	}{
		{
			name:    "sub-min ttl raised to 8s",
			ttlIn:   1 * time.Second,
			wantTTL: 8 * time.Second,
		},
		{
			name:    "mid ttl kept as-is",
			ttlIn:   30 * time.Second,
			wantTTL: 30 * time.Second,
		},
		{
			name:    "long ttl kept as-is (no 2m cap)",
			ttlIn:   1 * time.Hour,
			wantTTL: 1 * time.Hour,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newTestGateway()
			q := "ttlclamp.example.com"
			tid := "tid0"
			algip4 := gen4Locked(q+key4+"0", 0)
			sec := secans{}
			sec.initIfNeeded()

			g.Lock()
			ok := g.registerLocked(q, tid, "uid0", "fid0", algip4, netip.Addr{},
				[]netip.Addr{mustAddr("1.1.1.1")}, tc.ttlIn, nil, sec)
			g.Unlock()
			if !ok {
				t.Fatalf("registerLocked failed")
			}

			now := time.Now()
			k := q + key4 + "0"
			g.RLock()
			ans := g.alg[k]
			g.RUnlock()
			if ans == nil {
				t.Fatalf("no alg entry for %s", k)
			}

			gotAnsTTL := ans.ttl.Sub(now)
			gotXipTTL := ans.ips.pri[tid].ttl.Sub(now)

			for name, got := range map[string]time.Duration{
				"ansttl":  gotAnsTTL,
				"xipsttl": gotXipTTL,
			} {
				if got < tc.wantTTL-time.Second || got > tc.wantTTL+time.Second {
					t.Errorf("%s: got %s, want ~%s", name, got, tc.wantTTL)
				}
				if got < ttl8s-time.Second {
					t.Errorf("%s: %s below 8s floor", name, got)
				}
			}
		})
	}
}

func TestNewXipsEmptyTid(t *testing.T) {
	if x := NewXips("", "u", nil, nil, time.Now()); x != nil {
		t.Fatalf("NewXips with empty tid should return nil, got %v", x)
	}
}

func TestXipsRelegateKeepsYoungestDob(t *testing.T) {
	now := time.Now()
	old := now.Add(-2 * time.Hour)
	young := now.Add(-1 * time.Hour)

	p := &xips{
		pmu:  sync.RWMutex{},
		pri:  make(map[string]expaddr),
		aux:  make(map[string]expaddr),
		past: make(map[string]expaddr),
	}
	p.past["k"] = expaddr{ips: []netip.Addr{mustAddr("1.1.1.1")}, ttl: now.Add(time.Hour), dob: old}

	p.pmu.Lock()
	p.relegateLocked("k", expaddr{ips: []netip.Addr{mustAddr("2.2.2.2")}, ttl: now.Add(time.Hour), dob: young})
	p.pmu.Unlock()

	p.pmu.RLock()
	got := p.past["k"]
	p.pmu.RUnlock()

	if len(got.ips) != 2 {
		t.Fatalf("expected merged ips (2), got %v", got.ips)
	}
	// the youngest dob must be retained to extend the 24h retention window
	if !got.dob.Equal(young) {
		t.Errorf("dob: got %s, want %s (youngest)", got.dob, young)
	}
}

func TestXipsRelegateFreshInsert(t *testing.T) {
	now := time.Now()
	p := &xips{
		pmu:  sync.RWMutex{},
		pri:  make(map[string]expaddr),
		aux:  make(map[string]expaddr),
		past: make(map[string]expaddr),
	}
	v := expaddr{ips: []netip.Addr{mustAddr("3.3.3.3")}, ttl: now.Add(time.Hour), dob: now.Add(-time.Hour)}

	p.pmu.Lock()
	p.relegateLocked("newkey", v)
	p.pmu.Unlock()

	p.pmu.RLock()
	got, ok := p.past["newkey"]
	p.pmu.RUnlock()
	if !ok {
		t.Fatalf("expected new past entry")
	}
	if !got.dob.Equal(v.dob) {
		t.Errorf("dob: got %s, want %s", got.dob, v.dob)
	}
}

func TestXdomainsRelegateKeepsYoungestDob(t *testing.T) {
	now := time.Now()
	old := now.Add(-2 * time.Hour)
	young := now.Add(-1 * time.Hour)

	p := &xdomains{
		pmu:  new(sync.RWMutex),
		pri:  make(map[string]expdomains),
		past: make(map[string]expdomains),
	}
	p.past["k"] = expdomains{domains: []string{"old.example.com"}, ttl: now.Add(time.Hour), dob: old}

	p.pmu.Lock()
	p.relegateLocked("k", expdomains{domains: []string{"young.example.com"}, ttl: now.Add(time.Hour), dob: young})
	p.pmu.Unlock()

	p.pmu.RLock()
	got := p.past["k"]
	p.pmu.RUnlock()

	if len(got.domains) != 2 {
		t.Fatalf("expected merged domains (2), got %v", got.domains)
	}
	// mirror xips.relegateLocked: retain the youngest dob to extend retention
	if !got.dob.Equal(young) {
		t.Errorf("dob: got %s, want %s (youngest)", got.dob, young)
	}
}

func TestXipsMergeFresh(t *testing.T) {
	now := time.Now()
	ipA := mustAddr("1.1.1.1")
	ipB := mustAddr("2.2.2.2")
	secA := mustAddr("3.3.3.3")
	secB := mustAddr("4.4.4.4")

	p := NewXips("t1", "u1", []netip.Addr{ipA}, []netip.Addr{secA}, now.Add(10*time.Second))
	time.Sleep(10 * time.Millisecond) // ensure q.dob > p.dob
	q := NewXips("t1", "u1", []netip.Addr{ipB}, []netip.Addr{secB}, now.Add(20*time.Second))

	aliv, tot, secaliv, sec := p.merge(q)
	if tot < 0 || sec < 0 {
		t.Fatalf("merge should have touched pri/aux, got pri(%d/%d) sec(%d/%d)", aliv, tot, secaliv, sec)
	}

	p.pmu.RLock()
	merged := p.pri["t1"]
	mergedSec := p.aux["t1"+"u1"]
	p.pmu.RUnlock()

	if len(merged.ips) != 2 {
		t.Fatalf("expected 2 merged ips, got %v", merged.ips)
	}
	// youngest first ordering: qv's ip (ipB) must come first
	if merged.ips[0] != ipB || merged.ips[1] != ipA {
		t.Errorf("ips: got %v, want [%s %s] (youngest first)", merged.ips, ipB, ipA)
	}
	if !merged.dob.Equal(q.pri["t1"].dob) {
		t.Errorf("dob: got %s, want q's dob %s", merged.dob, q.pri["t1"].dob)
	}
	if len(mergedSec.ips) != 2 || mergedSec.ips[0] != secB || mergedSec.ips[1] != secA {
		t.Errorf("aux: got %v, want [%s %s] (youngest first)", mergedSec.ips, secB, secA)
	}
}

func TestXipsMergeCapturesStaleIntoPast(t *testing.T) {
	now := time.Now()
	ipOld := mustAddr("9.9.9.9")
	ipNew := mustAddr("8.8.8.8")

	// p's entry is expired (ttl in the past) but dob within stale threshold
	p := NewXips("t1", "u1", []netip.Addr{ipOld}, nil, now.Add(-time.Hour))
	q := NewXips("t1", "u1", []netip.Addr{ipNew}, nil, now.Add(time.Hour))

	aliv, tot, _, _ := p.merge(q)
	if tot < 0 {
		t.Fatalf("merge should have touched pri")
	}
	_ = aliv

	p.pmu.RLock()
	gotPri := p.pri["t1"]
	gotPast, hasPast := p.past["t1"]
	p.pmu.RUnlock()

	if len(gotPri.ips) != 1 || gotPri.ips[0] != ipNew {
		t.Errorf("pri: got %v, want [%s]", gotPri.ips, ipNew)
	}
	if !hasPast {
		t.Fatalf("expected stale ips to be relegated into past")
	}
	if len(gotPast.ips) != 1 || gotPast.ips[0] != ipOld {
		t.Errorf("past: got %v, want [%s]", gotPast.ips, ipOld)
	}
}

func TestXipsMergeNoChange(t *testing.T) {
	now := time.Now()
	p := NewXips("t1", "u1", []netip.Addr{mustAddr("1.1.1.1")}, nil, now.Add(time.Hour))
	q := NewXips("t1", "u1", nil, nil, now.Add(time.Hour))

	aliv, tot, secaliv, sec := p.merge(q)
	if tot != -1 || sec != -1 {
		t.Errorf("expected -1 (no change) for untouched maps, got pri(%d/%d) sec(%d/%d)", aliv, tot, secaliv, sec)
	}
}

func TestXipsVaccumRemovesStale(t *testing.T) {
	now := time.Now()
	p := &xips{
		pmu:  sync.RWMutex{},
		pri:  make(map[string]expaddr),
		aux:  make(map[string]expaddr),
		past: make(map[string]expaddr),
	}
	// dob older than staleXipsThres (24h) => eligible for removal
	p.past["stale"] = expaddr{ips: []netip.Addr{mustAddr("1.1.1.1")}, ttl: now.Add(-time.Hour), dob: now.Add(-48 * time.Hour)}
	p.past["fresh"] = expaddr{ips: []netip.Addr{mustAddr("2.2.2.2")}, ttl: now.Add(-time.Hour), dob: now.Add(-time.Hour)}

	p.pmu.Lock()
	p.vaccumLocked()
	p.pmu.Unlock()

	p.pmu.RLock()
	_, hasStale := p.past["stale"]
	_, hasFresh := p.past["fresh"]
	p.pmu.RUnlock()

	if hasStale {
		t.Errorf("stale entry (dob 48h ago) should have been vaccumed")
	}
	if !hasFresh {
		t.Errorf("fresh entry (dob 1h ago) should have been retained")
	}
}

func TestXipsRealipsZzUnspecified(t *testing.T) {
	now := time.Now()
	p := NewXips("t1", "u1", []netip.Addr{mustAddr("1.1.1.1")}, nil, now.Add(time.Hour))

	p.pmu.Lock()
	// "block" style response for this uid via the notransport secondary
	p.aux[notransport+"u1"] = expaddr{ips: []netip.Addr{anyaddr4}, ttl: now.Add(time.Hour), dob: now}
	p.pmu.Unlock()

	pri := p.realips("u1", xalive)
	found4 := false
	found6 := false
	for _, ip := range pri {
		if ip == anyaddr4 {
			found4 = true
		}
		if ip == anyaddr6 {
			found6 = true
		}
	}
	if !found4 || !found6 {
		t.Errorf("realips: got %v, want unspecified 0.0.0.0 + :: appended", pri)
	}
}

func TestTake4LockedDeterministicAndRanges(t *testing.T) {
	g := newTestGateway()

	g.Lock()
	ip1, ok1 := g.take4Locked("a.example.com", 0)
	ip2, ok2 := g.take4Locked("a.example.com", 0)
	ip3, ok3 := g.take4Locked("b.example.com", 0)
	g.Unlock()

	if !ok1 || !ok2 || !ok3 {
		t.Fatalf("take4Locked failed: %t %t %t", ok1, ok2, ok3)
	}
	if ip1 != ip2 {
		t.Errorf("same qname must map to same algip: %s vs %s", ip1, ip2)
	}
	if ip1 == ip3 {
		t.Errorf("distinct qnames should map to distinct algips, both %s", ip1)
	}
	b1 := ip1.As4()
	if b1[0] != 100 || b1[1] < 64 || b1[1] > 127 {
		t.Errorf("algip %s outside 100.64.0.0/10", ip1)
	}
}

func TestTake6LockedDeterministicAndPrefix(t *testing.T) {
	g := newTestGateway()

	g.Lock()
	ip1, ok1 := g.take6Locked("a.example.com", 0)
	ip2, ok2 := g.take6Locked("a.example.com", 0)
	g.Unlock()

	if !ok1 || !ok2 {
		t.Fatalf("take6Locked failed: %t %t", ok1, ok2)
	}
	if ip1 != ip2 {
		t.Errorf("same qname must map to same algip6: %s vs %s", ip1, ip2)
	}
	a16 := ip1.As16()
	if uint16(a16[0])<<8|uint16(a16[1]) != rfc8215a[0] ||
		uint16(a16[2])<<8|uint16(a16[3]) != rfc8215a[1] ||
		uint16(a16[4])<<8|uint16(a16[5]) != rfc8215a[2] ||
		uint16(a16[6])<<8|uint16(a16[7]) != rfc8215a[3] ||
		uint16(a16[8])<<8|uint16(a16[9]) != rfc8215a[4] {
		t.Errorf("algip6 %s does not start with rfc8215a prefix", ip1)
	}
}

func TestGen4LockedRange(t *testing.T) {
	for i := range 100 {
		ip := gen4Locked("q"+strconv.Itoa(i), i)
		if !ip.Is4() || !ip.IsValid() {
			t.Fatalf("gen4Locked returned invalid ip %s", ip)
		}
		b := ip.As4()
		if b[0] != 100 || b[1] < 64 || b[1] > 127 {
			t.Errorf("gen4Locked(%d) = %s outside 100.64.0.0/10", i, ip)
		}
	}
}

func TestHashWidths(t *testing.T) {
	for _, s := range []string{"a", "example.com", "example.com:aaaa0", strconv.Itoa(0) + "x"} {
		h22 := hash22(s)
		if h22 >= 1<<22 {
			t.Errorf("hash22(%q) = %d exceeds 22 bits", s, h22)
		}
		h48 := hash48(s)
		if h48 >= 1<<48 {
			t.Errorf("hash48(%q) = %d exceeds 48 bits", s, h48)
		}
		if hash22(s) != h22 || hash48(s) != h48 {
			t.Errorf("hash for %q is not deterministic", s)
		}
	}
}

func TestNetipCsvRoundTrip(t *testing.T) {
	in := []netip.Addr{mustAddr("1.2.3.4"), mustAddr("::1"), mustAddr("2001:db8::1")}
	csv := Netip2Csv(in)
	out := Csv2Netip(csv)
	if len(out) != len(in) {
		t.Fatalf("round trip: got %v, want %v", out, in)
	}
	for i := range in {
		if out[i] != in[i] {
			t.Errorf("round trip: got %v, want %v", out, in)
		}
	}
}

func TestCsv2NetipIgnoresInvalid(t *testing.T) {
	out := Csv2Netip("1.2.3.4,not-an-ip,::1")
	if len(out) != 2 {
		t.Fatalf("expected 2 valid ips, got %v", out)
	}
}
