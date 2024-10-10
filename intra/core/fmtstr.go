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

func FmtTimeSecs(ns uint64) int64 {
	return int64(time.Duration(ns).Seconds())
}
