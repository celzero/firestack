// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"fmt"
	"runtime/metrics"
	"strings"
	"sync"
	"time"
)

const (
	// ex: /cgo/go-to-c-calls:calls
	MetCgo = "/cgo"
	// ex: /cpu/classes/gc/mark/assist:cpu-seconds
	MetCPU = "/cpu"
	// ex: /gc/scan/globals:bytes
	MetGC = "/gc"
	// ex: /godebug/non-default-behavior/zipinsecurepath:events
	MetDbg = "/godebug"
	// ex: /memory/classes/total:bytes
	MetMem = "/memory"
	// ex: /sched/threads/total:threads
	MetSched = "/sched"
	// ex: /sync/mutex/wait/total:seconds
	MetSync = "/sync"

	memoizationThreshold = 10 * time.Second
)

var (
	// Get descriptions for all supported metrics.
	descs = metrics.All()

	// Create a sample for each metric.
	allsamples = make([]metrics.Sample, len(descs))

	sb strings.Builder

	mu sync.Mutex // protects allsamples, last, sb

	lastcall time.Time
)

func init() {
	for i := range allsamples {
		allsamples[i].Name = descs[i].Name
	}
	sb.Grow(len(allsamples) * 100)
}

func skipped(s string, skip []string) bool {
	for _, prefix := range skip {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// from pkg.go.dev/runtime/metrics#Read
func Metrics(skip ...string) string {
	if len(skip) > 0 {
		filtered := make([]metrics.Sample, len(descs))
		for i := range filtered {
			if skipped(descs[i].Name, skip) {
				continue
			}
			filtered[i].Name = descs[i].Name
		}
		return readMetrics(filtered)
	}

	if !lastcall.IsZero() && time.Since(lastcall) < memoizationThreshold {
		mu.Lock()
		defer mu.Unlock()
		return sb.String()
	}

	lastcall = time.Now()
	return readMetrics(allsamples)
}

// TODO: read only once every 10s?
func readMetrics(samples []metrics.Sample) string {
	mu.Lock()
	defer mu.Unlock()

	sb.Reset()
	sb.WriteString("\n")

	metrics.Read(samples)

	for _, sample := range samples {
		name, value := sample.Name, sample.Value

		switch value.Kind() {
		case metrics.KindUint64:
			s := fmt.Sprintf("%s: %d\n", name, value.Uint64())
			sb.WriteString(s)
		case metrics.KindFloat64:
			s := fmt.Sprintf("%s: %f\n", name, value.Float64())
			sb.WriteString(s)
		case metrics.KindFloat64Histogram:
			// The histogram may be quite large, so let's just pull out
			// a crude estimate for the median.
			s := fmt.Sprintf("%s: p50(%f)\n", name, medianBucket(value.Float64Histogram()))
			sb.WriteString(s)
		case metrics.KindBad:
			fallthrough
		default:
			// This may happen as new metrics get added.
			s := fmt.Sprintf("%s: Unknown(%v)\n", name, value.Kind())
			sb.WriteString(s)
		}
	}
	return sb.String()
}

func medianBucket(h *metrics.Float64Histogram) float64 {
	total := uint64(0)
	for _, count := range h.Counts {
		total += count
	}
	thresh := total / 2
	total = 0
	for i, count := range h.Counts {
		total += count
		if total >= thresh {
			return h.Buckets[i]
		}
	}
	// should not happen
	return -1.0
}
