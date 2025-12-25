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
	if w.b == nil {
		w.b = AllocRegion(len(p))
	}
	*w.b = append(*w.b, p...)
	return len(p), nil
}

func (w *ByteWriter) Close() error {
	if w.b != nil {
		Recycle(w.b)
		w.b = nil
	}
	return nil
}

func (w *ByteWriter) Bytes() []byte {
	if w.b == nil {
		return nil
	}
	return *w.b
}

func (w *ByteWriter) Len() int {
	if w.b == nil {
		return 0
	}
	return len(*w.b)
}

func (w *ByteWriter) Reset() {
	if w.b != nil {
		*w.b = (*w.b)[:0]
	}
}
