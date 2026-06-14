// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package log

import (
	"math/bits"
	"sync"
	"sync/atomic"
)

// Log buffer pool: pooled []byte slabs used for zero-copy string-to-bytes
// conversions in the logging hot path. Mirrors the slab layout from
// intra/core/buf.go but is local to the log package to avoid a circular
// import (core imports log).

var lslabs [ltotalSlabs]*sync.Pool // read-only after init

const (
	ltotalSlabs      = 2 // total slab types: LB512 and LB1024
	lminSlabExponent = 9 // 2^9 = 512 bytes

	// LB512 is the smallest slab, 512 bytes
	LB512 = 1 << 9
	// LB1024 is a 1k slab; sufficient for any single log line
	// since charsPerLine=800 bounds each formatted line.
	LB1024 = 1 << 10
	// LBMAX is the largest log slab size
	LBMAX = LB1024
)

// poolStats tracks pool operation counters.
type poolStats struct {
	gets  atomic.Uint64 // successful pool retrieves
	news  atomic.Uint64 // new allocations (pool miss or oversized)
	puts  atomic.Uint64 // successful pool returns
	drops atomic.Uint64 // recycle attempts that couldn't pool
}

var pstats poolStats

// logpoolStats returns a snapshot of pool operation counters.
func logpoolStats() (gets, news, puts, drops uint64) {
	return pstats.gets.Load(), pstats.news.Load(), pstats.puts.Load(), pstats.drops.Load()
}

// obtain returns a pointer to a pooled []byte with cap >= size.
func obtain(size int) *[]byte {
	if slab := lslabnearest(size); slab != nil {
		if ptr, _ := slab.Get().(*[]byte); ptr != nil {
			pstats.gets.Add(1)
			return ptr
		}
	}
	// unpooled
	pstats.news.Add(1)
	b := make([]byte, 0, size)
	return &b
}

// recycle returns a []byte pointer to its pool.
func recycle(b *[]byte) {
	if b == nil {
		return
	}
	if slab := lslabfor(b); slab != nil {
		*b = (*b)[:0]
		slab.Put(b)
		pstats.puts.Add(1)
		return
	}
	// unpooled recycle
	pstats.drops.Add(1)
}

// recycleAll returns all []byte pointers to their pools.
func recycleAll(slabs []*[]byte) {
	for _, ptr := range slabs {
		recycle(ptr)
	}
}

func lslabnearest(sz int) *sync.Pool {
	if sz > LBMAX {
		return nil
	} else if sz > LB512 {
		return lslabs[lidx(LB1024)]
	} else {
		return lslabs[lidx(LB512)]
	}
}

func lslabfor(b *[]byte) *sync.Pool {
	return lslabof(cap(*b))
}

func lslabof(sz int) (p *sync.Pool) {
	if sz > LBMAX {
		// do not pool oversized slabs
	} else if sz >= LB1024 {
		p = lslabs[lidx(LB1024)]
	} else {
		p = lslabs[lidx(LB512)]
	}
	return
}

func init() {
	lslabs[lidx(LB512)] = mklslab(LB512)
	lslabs[lidx(LB1024)] = mklslab(LB1024)
}

func mklslab(size int) *sync.Pool {
	return &sync.Pool{
		New: func() any {
			b := make([]byte, 0, size)
			return &b
		},
	}
}

func lidx(i uint32) int {
	slot := bits.TrailingZeros32(i) - lminSlabExponent
	if slot < 0 {
		return 0
	}
	return min(slot, ltotalSlabs-1)
}
