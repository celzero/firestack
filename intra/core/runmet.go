// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"fmt"
	"math"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

	MetGCPauses = MetGC + "/pauses"
	// prefix
	MetGCHeap = MetGC + "/heap"
	// histogram of scheduler latencies (e.g. time to schedule a goroutine)
	MetSchedLatencies           = MetSched + "/latencies"
	MetSchedPausesStoppingGc    = MetSched + "/pauses/stopping/gc"
	MetSchedPausesStoppingOther = MetSched + "/pauses/stopping/other"
	MetSchedPausesTotalGc       = MetSched + "/pauses/total/gc"
	MetSchedPausesTotalOther    = MetSched + "/pauses/total/other"

	memoizationThreshold = 10 * time.Second

	// format temporal units to nanos?
	fmtTemporal = true
)

type metricUnit = int

const (
	unitUnknown = metricUnit(iota)
	unitTemporal
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

		// skip debug
		if strings.HasPrefix(name, MetCgo) || strings.HasPrefix(name, MetDbg) {
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
			u = unitTemporal
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
			sb.WriteString("-----------\n")
			if strings.HasPrefix(name, MetGC) {
				s := fmt.Sprintf("%s: hist(%s)", name, histo2str(value.Float64Histogram(), u, '\n'))
				sb.WriteString(s)
				if strings.HasPrefix(name, MetGCHeap) {
					s := fmt.Sprintf("\n%s: percentiles(%s)", name, histo2Ps(value.Float64Histogram(), u, '\n'))
					sb.WriteString(s)
					s = fmt.Sprintf("\n%s: dist(%s)", name, histo2Ms(value.Float64Histogram(), u, '\n'))
					sb.WriteString(s)
				}
			} else if strings.HasPrefix(name, MetSched) {
				if strings.HasPrefix(name, MetSchedLatencies) ||
					strings.HasPrefix(name, MetSchedPausesStoppingGc) ||
					strings.HasPrefix(name, MetSchedPausesStoppingOther) ||
					strings.HasPrefix(name, MetSchedPausesTotalGc) ||
					strings.HasPrefix(name, MetSchedPausesTotalOther) {
					s := fmt.Sprintf("%s: percentiles(%s)", name, histo2Ps(value.Float64Histogram(), u, '\n'))
					sb.WriteString(s)
					s = fmt.Sprintf("\n%s: dist(%s)", name, histo2Ms(value.Float64Histogram(), u, '\n'))
					sb.WriteString(s)
				}
			} else {
				s := fmt.Sprintf("%s: hist(%s)", name, histo2str(value.Float64Histogram(), u, '\n'))
				sb.WriteString(s)
			}
			sb.WriteString("-----------\n")
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

func unit4int(v uint64, u metricUnit) string {
	switch u {
	case unitTemporal:
		return FmtSecs(int64(v)) // may wrap?
	case unitPercent:
		return fmt.Sprintf("%d%%", v)
	case unitBytes:
		return FmtBytes(v)
	case unitGcTime:
		return fmt.Sprintf("%d", v)
	case unitCount:
		return FmtWithSep(v, '_')
	default:
		return fmt.Sprintf("%d", v)
	}
}

// FmtWithSep formats a uint64 with one byte separators every 3 digits (e.g. 1234567 -> "1,234,567").
func FmtWithSep(v uint64, sep byte) string {
	s := fmt.Sprintf("%d", v)
	n := len(s)
	if n <= 3 {
		return s
	}
	// pre-allocate exact size: n digits + (n-1)/3 separators
	b := make([]byte, n+(n-1)/3)
	for i, j, k := n-1, len(b)-1, 0; i >= 0; i, k = i-1, k+1 {
		if k > 0 && k%3 == 0 {
			b[j] = sep
			j--
		}
		b[j] = s[i]
		j--
	}
	return string(b)
}

func histo2str(h *metrics.Float64Histogram, u metricUnit, sep byte) string {
	var sb strings.Builder
	sb.Grow(20 * len(h.Buckets))
	for i, b := range h.Buckets {
		if i >= len(h.Buckets)-1 {
			break
		}
		if h.Counts[i] == 0 {
			continue
		}
		sb.WriteByte(sep)
		s := fmt.Sprintf("%s:%s", unit4float(b, u), unit4int(h.Counts[i], unitCount))
		sb.WriteString(s)
	}
	return sb.String()
}

// histo2Ps returns a string of percentiles (p10 ... p99.99) for the histogram,
// considering only buckets with non-zero counts.
func histo2Ps(h *metrics.Float64Histogram, u metricUnit, sep byte) string {
	type bkt struct {
		mid   float64
		count uint64
	}

	var buckets []bkt
	for i := 0; i < len(h.Counts); i++ {
		if h.Counts[i] == 0 {
			continue
		}
		lo, hi := h.Buckets[i], h.Buckets[i+1]
		var mid float64
		switch {
		case math.IsInf(lo, -1):
			mid = hi
		case math.IsInf(hi, 1):
			mid = lo
		default:
			mid = (lo + hi) / 2
		}
		buckets = append(buckets, bkt{mid, h.Counts[i]})
	}
	if len(buckets) == 0 {
		return ""
	}

	var total uint64
	for _, b := range buckets {
		total += b.count
	}

	percentiles := []float64{10, 20, 30, 40, 50, 60, 70, 80, 90, 95, 99, 99.9, 99.99}

	var sb strings.Builder
	sb.Grow(len(percentiles) * 24)

	pi := 0
	var cumulative uint64
	for _, b := range buckets {
		cumulative += b.count
		for pi < len(percentiles) {
			threshold := uint64(math.Ceil(percentiles[pi] / 100.0 * float64(total)))
			if cumulative >= threshold {
				sb.WriteByte(sep)
				fmt.Fprintf(&sb, "p%g=%s", percentiles[pi], unit4float(b.mid, u))
				pi++
			} else {
				break
			}
		}
		if pi >= len(percentiles) {
			break
		}
	}
	// fill any trailing percentiles with the last bucket's midpoint
	last := buckets[len(buckets)-1]
	for ; pi < len(percentiles); pi++ {
		sb.WriteByte(sep)
		fmt.Fprintf(&sb, "p%g=%s", percentiles[pi], unit4float(last.mid, u))
	}
	return sb.String()
}

// histo2Ms returns a string with mean, median, mode, avg, min, max, variance,
// and standard deviation for the histogram, considering only buckets with
// non-zero counts.
//   - mean / avg: weighted arithmetic mean (mid-point weighted by count)
//   - median: mid-point of the bucket that crosses the 50th percentile
//   - mode: mid-point of the bucket with the highest count
//   - min / max: lower / upper boundary of the first / last non-zero bucket
//   - variance / std: population variance and standard deviation (weighted)
func histo2Ms(h *metrics.Float64Histogram, u metricUnit, sepb byte) string {
	type bkt struct {
		lo, hi, mid float64
		count       uint64
	}

	var buckets []bkt
	for i := 0; i < len(h.Counts); i++ {
		if h.Counts[i] == 0 {
			continue
		}
		lo, hi := h.Buckets[i], h.Buckets[i+1]
		var mid float64
		switch {
		case math.IsInf(lo, -1):
			mid = hi
		case math.IsInf(hi, 1):
			mid = lo
		default:
			mid = (lo + hi) / 2
		}
		buckets = append(buckets, bkt{lo, hi, mid, h.Counts[i]})
	}
	if len(buckets) == 0 {
		return ""
	}

	var total uint64
	for _, b := range buckets {
		total += b.count
	}

	// weighted mean (accounts for observation frequency per bucket)
	var weightedSum float64
	for _, b := range buckets {
		weightedSum += b.mid * float64(b.count)
	}
	mean := weightedSum / float64(total)

	// avg: unweighted mean of non-zero bucket midpoints
	var midSum float64
	for _, b := range buckets {
		midSum += b.mid
	}
	avg := midSum / float64(len(buckets))

	// median: midpoint of the bucket crossing the 50th percentile
	median := buckets[len(buckets)-1].mid
	var cumulative uint64
	for _, b := range buckets {
		cumulative += b.count
		if cumulative >= uint64(math.Ceil(0.5*float64(total))) {
			median = b.mid
			break
		}
	}

	// mode: midpoint of the bucket with the highest count
	mode := buckets[0].mid
	maxCount := buckets[0].count
	for _, b := range buckets[1:] {
		if b.count > maxCount {
			maxCount = b.count
			mode = b.mid
		}
	}

	// min: lower bound of first non-zero bucket (use mid if -Inf)
	minVal := buckets[0].lo
	if math.IsInf(minVal, -1) {
		minVal = buckets[0].mid
	}
	// max: upper bound of last non-zero bucket (use mid if +Inf)
	maxVal := buckets[len(buckets)-1].hi
	if math.IsInf(maxVal, 1) {
		maxVal = buckets[len(buckets)-1].mid
	}

	// population variance and standard deviation (weighted)
	var varianceSum float64
	for _, b := range buckets {
		diff := b.mid - mean
		varianceSum += float64(b.count) * diff * diff
	}
	variance := varianceSum / float64(total)
	stddev := math.Sqrt(variance)
	sep := string(sepb)

	return fmt.Sprintf(
		"%smean=%s%smedian=%s%smode=%s%savg=%s%smin=%s%smax=%s%svar=%s%sstd=%s%s",
		sep,
		unit4float(mean, u),
		sep,
		unit4float(median, u),
		sep,
		unit4float(mode, u),
		sep,
		unit4float(avg, u),
		sep,
		unit4float(minVal, u),
		sep,
		unit4float(maxVal, u),
		sep,
		unit4float(variance, u),
		sep,
		unit4float(stddev, u),
		sep,
	)
}

func unit4float(v float64, u metricUnit) string {
	switch u {
	case unitTemporal:
		if fmtTemporal {
			// go.dev/play/p/OroD8WDQyyb
			return FmtSecsFloat(v)
		}
		return fmt.Sprintf("%f", v)
	case unitPercent:
		return fmt.Sprintf("%.2f%%", v)
	case unitBytes:
		return FmtBytes(uint64(v))
	case unitGcTime:
		return fmt.Sprintf("%.2f", v)
	case unitCount:
		return FmtWithSep(uint64(v), '_')
	default:
		return fmt.Sprintf("%.3g", v)
	}
}

// BarrierState is a snapshot of a Barrier's metrics.
type BarrierState struct {
	Typ    string
	ID     string
	Len    int
	Anew   uint64 // calls that owned the request (ran once())
	Shared uint64 // calls that coalesced with an in-flight request
	Dels   uint64 // count of barriers removed by scrubbing
}

// MapState is a snapshot of a map's metrics.
type MapState struct {
	Typ  string
	ID   string
	Len  int
	Puts uint64
	Gets uint64
	Dels uint64
}

// WorkersState is a snapshot of an active goroutine.
type WorkersState struct {
	Typ   string
	ID    string
	Since time.Duration
}

// CoreState is a snapshot of all registered barriers, maps, and active goroutines.
type CoreState struct {
	Workers  []WorkersState
	Barriers []BarrierState
	Maps     []MapState
}

var (
	barmap  sync.Map // string -> func() BarrierState; see registerBarrier
	mapmap  sync.Map // string -> func() MapState; see registerMap
	workmap sync.Map // goroutine key -> time.Time (start time)

	barctr  atomic.Uint64 // monotone counter for unique barrier keys
	mapctr  atomic.Uint64 // monotone counter for unique map keys
	workctr atomic.Uint64 // monotone counter for unique goroutine keys
)

type roent struct {
	dob time.Time
	typ string
}

// trackwork registers a goroutine under the given id and typ, and returns a
// function that removes it from the registry. Callers must defer the returned function.
func trackwork(who, typ string) func() {
	key := who + "#" + strconv.FormatUint(workctr.Add(1), 10)
	workmap.Store(key, roent{dob: time.Now(), typ: typ})
	return func() { workmap.Delete(key) }
}

// trackbar registers snap under id for use in Snapshot().
// Returns a deregister function that removes it from the registry.
func trackbar(id string, snap func() BarrierState) (deregister func()) {
	key := id + "#" + strconv.FormatUint(barctr.Add(1), 10)
	barmap.Store(key, snap)
	return func() { barmap.Delete(key) }
}

// trackmap registers snap under id for use in Snapshot().
// Returns a deregister function that removes it from the registry.
func trackmap(id string, snap func() MapState) (deregister func()) {
	key := id + "#" + strconv.FormatUint(mapctr.Add(1), 10)
	mapmap.Store(key, snap)
	return func() { mapmap.Delete(key) }
}

// TrackMap registers snap under id for use in Snapshot().
// Returns a deregister function that removes it from the registry.
func TrackMap(id string, snap func() MapState) (deregister func()) {
	return trackmap(id, snap)
}

// Snapshot returns a snapshot of all registered barriers, maps, and active
// goroutines managed by this package. Safe to call concurrently.
func Snapshot() string {
	cs := &CoreState{Workers: ActiveWorkers()}
	barmap.Range(func(_, v any) bool {
		cs.Barriers = append(cs.Barriers, v.(func() BarrierState)())
		return true
	})
	mapmap.Range(func(_, v any) bool {
		cs.Maps = append(cs.Maps, v.(func() MapState)())
		return true
	})
	return cs.String()
}

func (c *CoreState) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "\nWorkers: %d\n", len(c.Workers))
	for _, w := range c.Workers {
		fmt.Fprintf(&sb, "   - %s (%s) since %s\n", w.ID, w.Typ, w.Since)
	}
	fmt.Fprintf(&sb, "\nBarriers: %d\n", len(c.Barriers))
	for _, b := range c.Barriers {
		fmt.Fprintf(&sb, "   - %s (%s): len=%d anew=%d shared=%d dels=%d\n ",
			b.ID, b.Typ, b.Len, b.Anew, b.Shared, b.Dels)
	}
	fmt.Fprintf(&sb, "\nMaps: %d\n", len(c.Maps))
	for _, m := range c.Maps {
		fmt.Fprintf(&sb, "   - %s (%s): len=%d puts=%d gets=%d dels=%d\n",
			m.ID, m.Typ, m.Len, m.Puts, m.Gets, m.Dels)
	}
	return sb.String()
}
