// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

import (
	"net/netip"
	"testing"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/protect/ipmap"
)

func TestRankMeets(t *testing.T) {
	cases := []struct {
		name  string
		v, th int32
		want  bool
	}{
		{"disabled threshold allows all", -1, 0, true},
		{"disabled threshold allows unknown", 0, -1, true},
		{"within threshold", 113260, 200000, true},
		{"at threshold", 100000, 100000, true},
		{"above threshold blocks", 113261, 113260, false},
		{"unranked blocks", -1, 100000, false},
		{"unknown blocks", 0, 100000, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rankMeets(tc.v, tc.th); got != tc.want {
				t.Errorf("rankMeets(%d, %d) = %t, want %t", tc.v, tc.th, got, tc.want)
			}
		})
	}
}

func TestRankStale(t *testing.T) {
	if !rankStale(0) {
		t.Error("rankStale(0) = false, want true")
	}
	fresh := time.Now().Add(-time.Hour).UnixMilli()
	if rankStale(fresh) {
		t.Error("rankStale(1h ago) = true, want false")
	}
	stale := time.Now().Add(-31 * 24 * time.Hour).UnixMilli()
	if !rankStale(stale) {
		t.Error("rankStale(31d ago) = false, want true")
	}
}

func TestResolveRankEchoAndSkip(t *testing.T) {
	// like NewResolver: undelegated / special-use domains never rank-gated
	r := &resolver{localdomains: ipmap.UndelegatedDomainsTrie}

	// nil dom: no ranks, no block
	if a, b, e, block, _ := r.resolveRank(nil, "example.com"); a != 0 || b != 0 || e != "" || block {
		t.Errorf("nil dom: got (%d,%d,%q,%t), want zeros/false", a, b, e, block)
	}

	// thresholds off: echo client ranks, never block, never fetch
	dom := &x.DomainOpts{Rank: 5, RankBig: 6}
	if a, b, e, block, _ := r.resolveRank(dom, "example.com"); a != 5 || b != 6 || e != "" || block {
		t.Errorf("echo: got (%d,%d,%q,%t), want (5,6,,false)", a, b, e, block)
	}

	// undelegated: zeros, never block, never fetch
	dom = &x.DomainOpts{Rank: 5, RankBig: 6, RankThreshold: 10, RankBigThreshold: 10}
	if a, b, e, block, _ := r.resolveRank(dom, "foo.local"); a != 0 || b != 0 || e != "" || block {
		t.Errorf("undelegated: got (%d,%d,%q,%t), want zeros/false", a, b, e, block)
	}

	// rank host itself: zeros, never block (no recursion)
	if a, b, e, block, _ := r.resolveRank(dom, rankHost); a != 0 || b != 0 || e != "" || block {
		t.Errorf("rankhost: got (%d,%d,%q,%t), want zeros/false", a, b, e, block)
	}

	// fresh client ranks within thresholds: no fetch, no block
	dom = &x.DomainOpts{
		Rank: 113260, RankBig: 113260,
		RankDobUnixMs:    time.Now().UnixMilli(),
		RankThreshold:    200000,
		RankBigThreshold: 200000,
	}
	if a, b, e, block, _ := r.resolveRank(dom, "rethinkdns.com"); a != 113260 || b != 113260 || e != "" || block {
		t.Errorf("fresh: got (%d,%d,%q,%t), want (113260,113260,,false)", a, b, e, block)
	}

	// fresh client ranks above threshold: block, no fetch
	dom.RankThreshold = 100000
	if _, _, _, block, _ := r.resolveRank(dom, "rethinkdns.com"); !block {
		t.Error("above threshold: block = false, want true")
	}

	// unknown ranks with thresholds on: fail closed without proxies
	dom = &x.DomainOpts{RankThreshold: 100000, RankBigThreshold: 100000}
	if a, b, _, block, _ := r.resolveRank(dom, "example.com"); a != 0 || b != 0 || !block {
		t.Errorf("unknown: got (%d,%d,block=%t), want (0,0,true)", a, b, block)
	}
}

func TestSkipRankBlock(t *testing.T) {
	if !skipRankBlock(&x.DNSOpts{NOBLOCK: true}, nil, nil, nil) {
		t.Error("NOBLOCK: want skip")
	}
	if !skipRankBlock(&x.DNSOpts{}, []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil, nil) {
		t.Error("preset ips: want skip")
	}
	if skipRankBlock(&x.DNSOpts{}, nil, nil, nil) {
		t.Error("plain: want no skip")
	}
}
