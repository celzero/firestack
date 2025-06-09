// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"fmt"
	"time"
)

var units = []string{"b", "kb", "mb", "gb"}

// from: github.com/google/gops/blob/35c854fb84/agent/agent.go
func FmtBytes(val uint64) string {
	var i int
	var target uint64
	for i = range units {
		target = 1 << uint(10*(i+1))
		if val < target {
			break
		}
	}
	if i > 0 {
		return fmt.Sprintf("%0.2f%s", float64(val)/(float64(target)/1024), units[i])
	}
	return fmt.Sprintf("%d bytes", val)
}

func FmtTimeNs(ns uint64) string {
	return time.Now().Add(-time.Duration(ns)).Format(time.TimeOnly)
}

func Nano2Sec(ns uint64) int64 {
	return int64((time.Duration(ns) * time.Nanosecond).Seconds())
}

func FmtTimeAsPeriod(t time.Time) string {
	return FmtPeriod(time.Since(t))
}

func FmtPeriod(d time.Duration) string {
	p := ""
	if d < 0 {
		p = "-"
	}
	d = d.Abs()
	if d < time.Second {
		return p + fmt.Sprintf("%dms", d.Milliseconds())
	} else if d < time.Minute {
		return p + fmt.Sprintf("%ds", int64(d.Seconds()))
	} else if d < time.Hour {
		return p + fmt.Sprintf("%dm %ds", int64(d.Minutes()), int64(d.Seconds())%60)
	} else if d < 24*time.Hour {
		return p + fmt.Sprintf("%dh %dm %ds", int64(d.Hours()), int64(d.Minutes())%60, int64(d.Seconds())%60)
	} else {
		return p + fmt.Sprintf("%dd %dh %dm %ds", int64(d.Hours()/24), int64(d.Hours())%24, int64(d.Minutes())%60, int64(d.Seconds())%60)
	}
}

func FmtUnixMillisAsPeriod(ms int64) string {
	return FmtTimeAsPeriod(time.UnixMilli(ms))
}

func FmtSecs(s int64) string {
	return FmtPeriod(time.Duration(s) * time.Second)
}

func FmtUnixMillisAsTimestamp(ms int64) string {
	return time.UnixMilli(ms).Format(time.Stamp)
}

func FmtUnixEpochAsPeriod(secs int64) string {
	return FmtTimeAsPeriod(time.Unix(secs, 0))
}
