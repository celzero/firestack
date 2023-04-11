// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

// from: github.com/eycorsican/go-tun2socks/blob/301549c435/core/buffer_pool.go

import (
	"sync"
)

var slab *sync.Pool

const BufSize = 4 * 1024 // in bytes

func SetSlabAllocator(p *sync.Pool) {
	slab = p
}

func AllocRegion(size int) []byte {
	if size <= BufSize {
		ptr := slab.Get().(*[]byte)
		return *ptr
	} else {
		return make([]byte, size)
	}
}

func Alloc() []byte {
	return AllocRegion(BufSize)
}

// github.com/v2fly/v2ray-core/blob/0c5abc7e53a/common/bytespool/pool.go#L63
func Recycle(b []byte) bool {
	sz := cap(b)
	b = b[0:sz]
	if len(b) >= BufSize {
		slab.Put(&b)
		return true
	}
	return false
}

func init() {
	SetSlabAllocator(&sync.Pool{
		New: func() any {
			b := make([]byte, BufSize)
			return &b
		},
	})
}
