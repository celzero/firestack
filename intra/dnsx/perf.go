// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

import (
	"context"
	"maps"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/miekg/dns"
)

var presetDomains = []string{
	"example.com", "mozilla.com", "fsf.org", "ietf.org", "wikipedia.org", "dns.quad9.net", "grapheneos.org",
}

// perfResult captures the outcome of a single DNS query during measurement.
type perfResult struct {
	domain  string
	latency float64 // in seconds; 0 on error
	status  int32
	errmsg  string // non-empty on error
}

// Perf measures DNS transport performance by sending batches of n parallel
// queries for the specified number of seconds. One batch of n queries completes
// before the next batch starts. Returns a DNSMeasurement with latency statistics
// (P50, P95, min, max, jitter) and success rate.
func Perf(t Transport, mid string, n, seconds int32) x.DNSMeasurement {
	start := time.Now()
	if len(mid) == 0 {
		mid = core.Rand64()
	}
	if n < 1 {
		n = 1
	} else if n > 20 {
		n = 20
	}
	if seconds < 10 {
		seconds = 10
	} else if seconds > 60 {
		seconds = 60
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds)*time.Second)
	defer cancel()

	est50 := core.NewP2QuantileEstimator(ctx, 11, 0.5)
	est95 := core.NewP2QuantileEstimator(ctx, 11, 0.95)

	perfDomains4 := dialers.SampleHosts(uint8(n), "v4")
	perfDomains6 := dialers.SampleHosts(uint8(n), "v6")
	// fallback to well-known domains if the mapper has no hosts
	if len(perfDomains4) == 0 {
		perfDomains4 = presetDomains
	}
	if len(perfDomains6) == 0 {
		perfDomains6 = perfDomains4
	}
	network := NetTypeUDP + ":" + ipn.Exit

	var total, okcount int64
	var minMs int64 = math.MaxInt64
	var maxMs int64
	errset := make(map[string]struct{})
	domset := make(map[string]struct{})
	var lats []float64 // latencies in seconds, in completion order

	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}

		fns := make([]core.WorkCtx[perfResult], n)
		for i := int32(0); i < n; i++ {
			idx := i
			fns[i] = func(_ context.Context) (perfResult, error) {
				dom := perfDomains4[int(idx)%len(perfDomains4)]
				qtyp := dns.TypeA
				if idx%2 == 1 {
					dom = perfDomains6[int(idx)%len(perfDomains6)]
					qtyp = dns.TypeAAAA
				}

				q := new(dns.Msg)
				q.SetQuestion(dns.Fqdn(dom), qtyp)

				smm := new(x.DNSSummary)
				smm.FID = mid[:len(mid)-1] + strconv.Itoa(int(idx))
				smm.Origin = x.OriginInternal

				_, err := t.Query(network, q, smm)
				r := perfResult{domain: dom, latency: smm.Latency, status: smm.Status}
				if err != nil {
					r.errmsg = err.Error()
				} else if len(smm.Msg) > 0 && smm.Status != Complete {
					r.errmsg = smm.Msg
				}
				return r, nil // errors captured in perfResult
			}
		}

		results, allerrs := core.All("dnsx.perf."+mid, remaining, fns...)

		for i, r := range results {
			total++
			if allerrs[i] != nil {
				errset[allerrs[i].Error()] = struct{}{}
				continue
			}
			domset[r.domain] = struct{}{}
			if len(r.errmsg) > 0 {
				errset[r.errmsg] = struct{}{}
				continue
			}
			if r.status == Complete {
				okcount++
				sec := r.latency
				ms := int64(sec * 1000)
				if ms < minMs {
					minMs = ms
				}
				if ms > maxMs {
					maxMs = ms
				}
				est50.Add(sec)
				est95.Add(sec)
				lats = append(lats, sec)
			}
		}
	}

	if minMs == math.MaxInt64 {
		minMs = 0
	}

	var pct int32
	if total > 0 {
		pct = int32(okcount * 100 / total)
	}

	// jitter: RMSSD of consecutive latencies (millis)
	var jitter int64
	if len(lats) > 1 {
		var sum float64
		for i := 1; i < len(lats); i++ {
			d := lats[i] - lats[i-1]
			sum += d * d
		}
		jitter = int64(math.Sqrt(sum/float64(len(lats)-1)) * 1000)
	}

	d := time.Since(start)
	return x.DNSMeasurement{
		MID:     mid,
		Max:     maxMs,
		Min:     minMs,
		P50:     est50.Get(),
		P95:     est95.Get(),
		Jitter:  jitter,
		Success: pct,
		Seconds: int32(d.Seconds()),
		Domains: csvmap(domset),
		Errors:  csvmap(errset),
		Addrs:   addrscsv(t),
	}
}

func csvmap(m map[string]struct{}) string {
	if len(m) == 0 {
		return ""
	}
	parts := make([]string, 0, len(m))
	for k := range maps.Keys(m) {
		parts = append(parts, k)
	}
	return strings.Join(parts, ",")
}

func addrscsv(t Transport) string {
	ipps := t.IPPorts()
	if len(ipps) <= 0 {
		return ""
	}
	x := core.Map(ipps, func(ipp netip.AddrPort) string { return ipp.String() })
	return strings.Join(x, ",")
}
