// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

// from: github.com/eycorsican/go-tun2socks/blob/301549c435/core/buffer_pool.go

import (
	"strconv"
	"sync"
)

var slabs map[string]*sync.Pool // read-only after init

const (
	// B524288 is slab of size 512k
	B524288 = 512 * 1024
	// B65536 is slab of size 64k
	B65536 = 64 * 1024
	// B32768 is slab of size 32k
	B32768 = 32 * 1024
	// B16384 is slab of size 16k
	B16384 = 16 * 1024
	// B8192 is slab of size 8k
	B8192 = 8 * 1024
	// B4096 is slab of size 4k
	B4096 = 4 * 1024
	// B2048 is slab of size 2k; also the min
	B2048 = 2 * 1024
	// BMAX is the largest pooled slab size
	BMAX = B524288
)

// pointers to slices: archive.is/BhHuQ
// deal only in pointers to byte-array
// github.com/golang/example/blob/9fd7daa/slog-handler-guide/README.md#speed

// AllocRegion returns a truncated byte slice at least size big
func AllocRegion(size int) *[]byte {
	if slab := slabof(size); slab != nil {
		if ptr, _ := slab.Get().(*[]byte); ptr != nil {
			return ptr
		}
	}
	b := make([]byte, 0, size)
	return &b
}

// Alloc returns a truncated byte slice of size 2048
func Alloc() *[]byte {
	return AllocRegion(B2048)
}

// LOB returns a truncated byte slice of size 524288
func LOB() *[]byte {
	return AllocRegion(B524288)
}

// Recycle returns the byte slices to the pool
func Recycle(b *[]byte) bool {
	// some buffer pool impl extend len until cap (github.com/v2fly/v2ray-core/blob/0c5abc7e53a/common/bytespool/pool.go#L63)
	// arr := *b.slice
	// arr[:cap(arr)]
	// ----
	// Other impls truncate the slice to 0 len (github.com/golang/example/blob/9fd7daa/slog-handler-guide/README.md#speed)
	// (*b.slice) := (*b.slice)[:0]

	// ref: go.dev/play/p/ywM_j-IvVH6
	if slab := slabfor(b); slab != nil {
		*b = (*b)[:0]
		slab.Put(b)
		return true
	}
	return false
}

// github.com/v2fly/v2ray-core/blob/0c5abc7e53a/common/bytespool/pool.go#L63
func init() {
	slabs = make(map[string]*sync.Pool)
	slabs[k(B2048)] = newpool(B2048)
	slabs[k(B4096)] = newpool(B4096)
	slabs[k(B8192)] = newpool(B8192)
	slabs[k(B16384)] = newpool(B16384)
	slabs[k(B32768)] = newpool(B32768)
	slabs[k(B65536)] = newpool(B65536)
	slabs[k(B524288)] = newpool(B524288)
}

// slabfor returns a sync.Pool that byte b can be recycled to.
func slabfor(b *[]byte) *sync.Pool {
	sz := cap(*b)
	return slabof(sz)
}

// slabof returns the sync.Pool that vends byte slices of size sz.
func slabof(sz int) (p *sync.Pool) {
	if sz > BMAX {
		// do not store larger regions
	} else if sz >= B524288 { // min 512k
		p = slabs[k(B524288)]
	} else if sz >= B65536 { // min 64k
		p = slabs[k(B65536)]
	} else if sz >= B32768 { // min 32k
		p = slabs[k(B32768)]
	} else if sz >= B16384 { // min 16k
		p = slabs[k(B16384)]
	} else if sz >= B8192 { // min 8k
		p = slabs[k(B8192)]
	} else if sz >= B4096 { // min 4k
		p = slabs[k(B4096)]
	} else { // min 2k
		p = slabs[k(B2048)]
	}
	return
}

// newpool returns a new sync.Pool of byte slices with minimum capacity, size.
func newpool(size int) *sync.Pool {
	return &sync.Pool{
		New: func() any {
			b := make([]byte, 0, size)
			return &b
		},
	}
}

func k(i int) string {
	return strconv.Itoa(i)
}
