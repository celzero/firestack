// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package log

import (
	"fmt"
	"strings"
)

// LogStat holds a snapshot of logger and pool statistics.
type LogStat struct {
	// Logger identity
	Tag string
	// Current levels
	Level        LogLevel
	ConsoleLevel LogLevel
	// Caller depth
	CallerDepth uint8
	// Per-level message counts (indexed by LogLevel)
	Count [NONE + 1]uint64
	// Per-level bytes written to stdout/stderr
	Bytes [NONE + 1]uint64
	// Per-level dropped (spammy) message counts
	Skipped [NONE + 1]uint32
	// Total console drops (backpressure)
	ConsoleDrops uint32
	// Pool statistics
	PoolGets  uint64
	PoolNews  uint64
	PoolPuts  uint64
	PoolDrops uint64
	// Ring buffer size
	RingSize int
	// Spam clock: per-level ticks
	ClockL1 [NONE + 1]uint8
}

func (s LogStat) String() string {
	var sb strings.Builder
	sb.Grow(512)

	lvl := func(l LogLevel) string { return l.s() }

	fmt.Fprintf(&sb, "log[tag=%s level=%s console=%s callerdepth=%d]",
		s.Tag, lvl(s.Level), lvl(s.ConsoleLevel), s.CallerDepth)
	sb.WriteByte('\n')

	// per-level counts
	sb.WriteString("count:")
	for i := LogLevel(0); i <= NONE; i++ {
		if c := s.Count[i]; c > 0 {
			fmt.Fprintf(&sb, " %s= %d", lvl(i), c)
		}
	}
	sb.WriteByte('\n')

	// per-level bytes
	sb.WriteString("bytes:")
	total := uint64(0)
	for i := LogLevel(0); i <= NONE; i++ {
		total += s.Bytes[i]
		if b := s.Bytes[i]; b > 0 {
			fmt.Fprintf(&sb, " %s= %d", lvl(i), b)
		}
	}
	fmt.Fprintf(&sb, " total=%d", total)
	sb.WriteByte('\n')

	// per-level skipped (spammy)
	sb.WriteString("skipped:")
	anySkipped := false
	for i := LogLevel(0); i <= NONE; i++ {
		if c := s.Skipped[i]; c > 0 {
			fmt.Fprintf(&sb, " %s= %d", lvl(i), c)
			anySkipped = true
		}
	}
	if !anySkipped {
		sb.WriteString(" (none)")
	}
	sb.WriteByte('\n')

	// console drops
	fmt.Fprintf(&sb, "console: drops=%d\n", s.ConsoleDrops)

	// pool stats
	fmt.Fprintf(&sb, "pool: gets=%d new=%d puts=%d drops=%d",
		s.PoolGets, s.PoolNews, s.PoolPuts, s.PoolDrops)
	sb.WriteByte('\n')

	// ring buffer
	fmt.Fprintf(&sb, "ring: size=%d", s.RingSize)

	return sb.String()
}
