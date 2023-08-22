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

const b4096 = 4 * 1024 // in bytes

func AllocRegion(size int) []byte {
	if size <= b4096 {
		if slab := slabfor(b4096); slab != nil {
			ptr := slab.Get().(*[]byte)
			return *ptr
		}
	}
	return make([]byte, size)
}

func Alloc() []byte {
	return AllocRegion(b4096)
}

// github.com/v2fly/v2ray-core/blob/0c5abc7e53a/common/bytespool/pool.go#L63
func Recycle(b []byte) bool {
	sz := cap(b)
	b = b[0:sz]
	if len(b) >= b4096 {
		if slab := slabfor(b4096); slab != nil {
			slab.Put(&b)
			return true
		}
	}
	return false
}

func init() {
	slabs = make(map[string]*sync.Pool)
	slabs[k(b4096)] = &sync.Pool{
		New: func() any {
			b := make([]byte, b4096)
			return &b
		},
	}
}

func slabfor(size int) *sync.Pool {
	return slabs[k(size)]
}

func k(i int) string {
	return strconv.Itoa(i)
}
