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

// from pkg.go.dev/runtime/metrics#Read

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

type metricUnit = int

const (
	unitUnknown = metricUnit(iota)
	unitSeconds
	unitCount
	unitPercent
	unitBytes
	unitGcTime
)

var (
	descs      = metrics.All()
	allsamples = make([]metrics.Sample, len(descs))

	sb       strings.Builder
	lastcall time.Time
	mu       sync.Mutex // protects allsamples, last, sb
)

func init() {
	for i := range allsamples {
		allsamples[i].Name = descs[i].Name
	}
	sb.Grow(len(allsamples) * 100)
}

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

		unit := ""
		u := unitUnknown
		namesplit := strings.Split(name, ":")
		if len(namesplit) >= 2 {
			name = namesplit[0]
			unit = namesplit[1]
		}

		if unit == "cpu-seconds" || unit == "seconds" {
			u = unitSeconds
		} else if unit == "count" ||
			unit == "cleanups" ||
			unit == "calls" ||
			unit == "gc-cycles" ||
			unit == "finalizers" ||
			unit == "objects" ||
			unit == "events" ||
			unit == "threads" ||
			unit == "goroutines" {
			u = unitCount
		} else if unit == "percent" {
			u = unitPercent
		} else if unit == "bytes" {
			u = unitBytes
		} else if unit == "gc-cycle" {
			u = unitGcTime
		}

		switch value.Kind() {
		case metrics.KindUint64:
			s := fmt.Sprintf("%s: %s\n", name, unit4int(value.Uint64(), u))
			sb.WriteString(s)
		case metrics.KindFloat64:
			s := fmt.Sprintf("%s: %s\n", name, unit4float(value.Float64(), u))
			sb.WriteString(s)
		case metrics.KindFloat64Histogram:
			// The histogram may be quite large, so let's just pull out
			// a crude estimate for the median.
			s := fmt.Sprintf("%s: hist(%s)\n", name, histoCsv(value.Float64Histogram(), u))
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

func histoCsv(h *metrics.Float64Histogram, u metricUnit) string {
	var sb strings.Builder
	sb.Grow(20 * len(h.Buckets))
	for i, b := range h.Buckets {
		if i >= len(h.Buckets)-1 {
			break
		}
		if i > 0 {
			sb.WriteString(",")
		}
		s := fmt.Sprintf("%s:%s", unit4float(b, u), unit4int(h.Counts[i], u))
		sb.WriteString(s)
	}
	return sb.String()
}

func unit4int(v uint64, u metricUnit) string {
	switch u {
	case unitSeconds:
		return FmtSecs(int64(v)) // may wrap?
	case unitPercent:
		return fmt.Sprintf("%d%%", v)
	case unitBytes:
		return FmtBytes(v)
	case unitGcTime:
		return fmt.Sprintf("%d", v)
	case unitCount:
		return FmtWithCommas(v)
	default:
		return fmt.Sprintf("%d", v)
	}
}

// FmtWithCommas formats a uint64 with comma separators every 3 digits (e.g. 1234567 -> "1,234,567").
func FmtWithCommas(v uint64) string {
	s := fmt.Sprintf("%d", v)
	n := len(s)
	if n <= 3 {
		return s
	}
	// pre-allocate exact size: n digits + (n-1)/3 commas
	b := make([]byte, n+(n-1)/3)
	for i, j, k := n-1, len(b)-1, 0; i >= 0; i, k = i-1, k+1 {
		if k > 0 && k%3 == 0 {
			b[j] = ','
			j--
		}
		b[j] = s[i]
		j--
	}
	return string(b)
}

func unit4float(v float64, u metricUnit) string {
	switch u {
	case unitSeconds:
		return FmtSecsFloat(v)
	case unitPercent:
		return fmt.Sprintf("%.2f%%", v)
	case unitBytes:
		return FmtBytes(uint64(v))
	case unitGcTime:
		return fmt.Sprintf("%.2f", v)
	case unitCount:
		return FmtWithCommas(uint64(v))
	default:
		return fmt.Sprintf("%.3g", v)
	}
}
