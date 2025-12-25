// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import "io"

type ByteWriter struct {
	b []byte
}

var _ io.WriteCloser = (*ByteWriter)(nil)

func (w *ByteWriter) Write(p []byte) (n int, err error) {
	w.b = append(w.b, p...)
	return len(p), nil
}

func (w *ByteWriter) Close() error {
	w.b = nil
	return nil
}

func (w *ByteWriter) Bytes() []byte {
	return w.b
}

func (w *ByteWriter) Len() int {
	return len(w.b)
}

func (w *ByteWriter) Reset() {
	w.b = w.b[:0]
}
