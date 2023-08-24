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

const b16384 = 16 * 1024 // in bytes
const b8192 = 8 * 1024   // in bytes
const b4096 = 4 * 1024   // in bytes
const b2048 = 2 * 1024   // in bytes
const bmax = 32 * 1024   // in bytes

// pointers to slices: archive.is/BhHuQ
// deal only in pointers to byte-array
// github.com/golang/example/blob/9fd7daa/slog-handler-guide/README.md#speed

// AllocRegion returns a truncated byte slice at least size big
func AllocRegion(size int) *[]byte {
	if slab := slabof(size); slab != nil {
		ptr := slab.Get().(*[]byte)
		return ptr
	}
	b := make([]byte, 0, size)
	return &b
}

// Alloc returns a truncated byte slice of size 2048
func Alloc() *[]byte {
	return AllocRegion(b2048)
}

// Recycle returns the byte slices to the pool
func Recycle(b *[]byte) bool {
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
	slabs[k(b2048)] = newpool(b2048)
	slabs[k(b4096)] = newpool(b4096)
	slabs[k(b8192)] = newpool(b8192)
	slabs[k(b16384)] = newpool(b16384)
}

func slabfor(b *[]byte) *sync.Pool {
	sz := cap(*b)
	return slabof(sz)
}

func slabof(sz int) (p *sync.Pool) {
	if sz > bmax {
		// do not store larger regions
	} else if sz >= b16384 {
		p = slabs[k(b16384)]
	} else if sz >= b8192 {
		p = slabs[k(b8192)]
	} else if sz >= b4096 {
		p = slabs[k(b4096)]
	} else {
		p = slabs[k(b2048)]
	}
	return
}

func newpool(size int) *sync.Pool {
	return &sync.Pool{
		New: func() interface{} {
			b := make([]byte, 0, size)
			return &b
		},
	}
}

func k(i int) string {
	return strconv.Itoa(i)
}
