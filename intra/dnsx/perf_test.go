// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/miekg/dns"
)

// mockTransport is a test transport that returns fixed-latency responses.
type mockTransport struct {
	latency float64 // fixed latency in seconds
	fail    bool    // if true, Query always errors
	count   atomic.Int64
}

func (m *mockTransport) ID() string                                    { return "mock" }
func (m *mockTransport) Type() string                                  { return "mock" }
func (m *mockTransport) P50() int64                                    { return int64(m.latency * 1000) }
func (m *mockTransport) GetAddr() string                               { return "127.0.0.1:53" }
func (m *mockTransport) GetRelay() x.Proxy                             { return nil }
func (m *mockTransport) Measure(string, int32, int32) x.DNSMeasurement { return x.DNSMeasurement{} }
func (m *mockTransport) Status() int32                                 { return Complete }
func (m *mockTransport) IPPorts() []netip.AddrPort                     { return nil }
func (m *mockTransport) Relaying() bool                                { return false }
func (m *mockTransport) Stop() error                                   { return nil }
func (m *mockTransport) Query(_ string, _ *dns.Msg, smm *x.DNSSummary) (*dns.Msg, error) {
	m.count.Add(1)
	if m.fail {
		smm.Status = SendFailed
		smm.Msg = "mock failure"
		return nil, errors.New("mock failure")
	}
	smm.Latency = m.latency
	smm.Status = Complete
	smm.RCode = dns.RcodeSuccess
	return nil, nil
}

var _ Transport = (*mockTransport)(nil)

func TestPerf(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		mt := &mockTransport{latency: 0.05} // 50ms
		m := Perf(mt, "", 5, 10)

		if m.MID == "" {
			t.Fatal("expected non-empty MID")
		}
		if m.Seconds != 10 {
			t.Fatalf("expected 10 seconds, got %d", m.Seconds)
		}
		if m.Success < 99 {
			t.Fatalf("expected >=99%% success, got %d", m.Success)
		}
		if m.Min < 40 || m.Min > 60 {
			t.Fatalf("expected min ~50ms, got %d", m.Min)
		}
		if m.Max < 40 || m.Max > 60 {
			t.Fatalf("expected max ~50ms, got %d", m.Max)
		}
		if m.P50 < 40 || m.P50 > 60 {
			t.Fatalf("expected P50 ~50ms, got %d", m.P50)
		}
		if m.P95 < 40 || m.P95 > 60 {
			t.Fatalf("expected P95 ~50ms, got %d", m.P95)
		}
		if m.Jitter != 0 {
			t.Fatalf("expected 0 jitter for fixed latency, got %d", m.Jitter)
		}
		if m.Domains == "" {
			t.Fatal("expected non-empty Domains")
		}
		if m.Errors != "" {
			t.Fatalf("expected empty Errors, got %q", m.Errors)
		}
		if m.Addrs != "127.0.0.1:53" {
			t.Fatalf("expected Addrs=127.0.0.1:53, got %q", m.Addrs)
		}
		if mt.count.Load() == 0 {
			t.Fatal("expected at least one query")
		}
		t.Logf("Perf: %+v (queries: %d)", m, mt.count.Load())
	})

	t.Run("errors", func(t *testing.T) {
		t.Parallel()
		mt := &mockTransport{fail: true}
		m := Perf(mt, "err-test", 3, 10)

		if m.MID != "err-test" {
			t.Fatalf("expected MID=err-test, got %s", m.MID)
		}
		if m.Success != 0 {
			t.Fatalf("expected 0%% success, got %d", m.Success)
		}
		if m.Errors == "" {
			t.Fatal("expected non-empty Errors")
		}
		if m.Min != 0 {
			t.Fatalf("expected min=0, got %d", m.Min)
		}
		if m.Max != 0 {
			t.Fatalf("expected max=0, got %d", m.Max)
		}
		if m.P50 != 0 {
			t.Fatalf("expected P50=0, got %d", m.P50)
		}
		if mt.count.Load() == 0 {
			t.Fatal("expected at least one query")
		}
		t.Logf("Perf errors: %+v (queries: %d)", m, mt.count.Load())
	})

	t.Run("clamps", func(t *testing.T) {
		t.Parallel()
		mt := &mockTransport{latency: 0.001} // 1ms
		// n=0 clamps to 1, seconds=5 clamps to 10
		m := Perf(mt, "", 0, 5)

		if m.Seconds != 10 {
			t.Fatalf("expected seconds clamped to 10, got %d", m.Seconds)
		}
		if m.MID == "" {
			t.Fatal("expected non-empty MID from Rand64")
		}
		if m.Success < 99 {
			t.Fatalf("expected >=99%% success, got %d", m.Success)
		}
		if m.Min < 0 || m.Min > 5 {
			t.Fatalf("expected min ~1ms, got %d", m.Min)
		}
		t.Logf("Perf clamps: %+v (queries: %d)", m, mt.count.Load())
	})

	t.Run("uniqueMID", func(t *testing.T) {
		t.Parallel()
		mt := &mockTransport{latency: 0.001}
		m1 := Perf(mt, "", 1, 10)
		m2 := Perf(mt, "", 1, 10)
		if m1.MID == m2.MID {
			t.Fatalf("expected unique MIDs, got %s == %s", m1.MID, m2.MID)
		}
	})
}
