// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"strconv"
	"testing"
)

func TestAllocRegionCapacity(t *testing.T) {
	for _, size := range []int{1, B2048, B2048 + 1, B4096, B4096 + 1, B8192 + 1, B16384 + 1, B32768 + 1, B65536 + 1, B524288 + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			region := AllocRegion(size)
			if cap(*region) < size {
				t.Fatalf("AllocRegion(%d) capacity = %d; want at least %d", size, cap(*region), size)
			}
			Recycle(region)
		})
	}
}
