// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import "io"

type ByteWriter struct {
	b *[]byte // pooled byte slice
}

var _ io.WriteCloser = (*ByteWriter)(nil)

func (w *ByteWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	bptr := w.b
	if bptr == nil {
		bptr = AllocRegion(len(p))
		w.b = bptr
	}
	// TODO: copy when cap(*bptr) < len(*bptr)+len(p)?
	// append may grow the slice beyond original capacity
	// and so, it may get recycled to a higher slab on Close
	*bptr = append(*bptr, p...)
	// w.b and bptr point to same slice & contents; *w.b == *bptr
	// go.dev/play/p/RJjoAXBsXy3
	return len(p), nil
}

func (w *ByteWriter) Close() error {
	if bptr := w.b; bptr != nil {
		// may recycle to a higher slab (see: Write)
		Recycle(bptr)
		w.b = nil
	}
	return nil
}

func (w *ByteWriter) Bytes() []byte {
	if bptr := w.b; bptr != nil {
		return *bptr
	}
	return nil
}

func (w *ByteWriter) Copy() []byte {
	if b := w.b; b != nil {
		c := make([]byte, len(*b))
		copy(c, *b)
		return c
	}
	return nil
}

func (w *ByteWriter) Dup() ByteWriter {
	if b := w.b; b != nil {
		b2 := AllocRegion(len(*b))
		copy(*b2, *b)
		return ByteWriter{b: b2}
	}
	return ByteWriter{}
}

func (w *ByteWriter) Len() int {
	if b := w.b; b != nil {
		return len(*b)
	}
	return 0
}

func (w *ByteWriter) Reset() {
	if b := w.b; b != nil {
		*b = (*b)[:0]
	}
}
