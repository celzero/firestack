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

const BufSize = 64 * 1024

func SetSlabAllocator(p *sync.Pool) {
	slab = p
}

func NewBytes(size int) []byte {
	if size <= BufSize {
		return slab.Get().([]byte)
	} else {
		return make([]byte, size)
	}
}

func FreeBytes(b []byte) {
	if len(b) >= BufSize {
		slab.Put(b)
	}
}

func init() {
	SetSlabAllocator(&sync.Pool{
		New: func() interface{} {
			return make([]byte, BufSize)
		},
	})
}
