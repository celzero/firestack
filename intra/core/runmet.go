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

// from pkg.go.dev/runtime/metrics#Read
func Metrics() string {
	mu.Lock()
	defer mu.Unlock()

	if !lastcall.IsZero() && time.Since(lastcall) < memoizationThreshold {
		return sb.String()
	}

	lastcall = time.Now()

	sb.Reset()
	sb.WriteString("\n")

	metrics.Read(allsamples)

	for _, sample := range allsamples {
		name, value := sample.Name, sample.Value

		switch name {
		case MetCgo, MetDbg: // skip debug
			continue
		}

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
			s := fmt.Sprintf("%s: hist(%s)\n", name, histoCsv(value.Float64Histogram()))
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

func histoCsv(h *metrics.Float64Histogram) string {
	var sb strings.Builder
	sb.Grow(20 * len(h.Buckets))
	for i, b := range h.Buckets {
		s := fmt.Sprintf("%f:%d", b, h.Counts[i])
		sb.WriteString(s)
		if i < len(h.Buckets)-1 {
			sb.WriteString(",")
		}
	}
	return sb.String()
}
