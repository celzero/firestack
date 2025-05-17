// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"errors"
	"io"
)

var (
	errNoPipe   = errors.New("pipe: src or dst nil")
	errNoStream = errors.New("stream: reader or writer nil")
)

// Pipe copies data from src to dst, and returns the number of bytes copied.
// Prefers src.WriteTo(dst) and dst.ReadFrom(src) if available.
// Otherwise, uses io.CopyBuffer, recycling buffers from global pool.
func Pipe(dst io.Writer, src io.Reader) (int64, error) {
	if IsNil(src) || IsNil(dst) {
		return 0, errNoPipe
	}

	// Prefer WriteTo/ReadFrom if available as they are zero-copy.
	// also: github.com/acln0/zerocopy
	if x, ok := src.(io.WriterTo); ok {
		return x.WriteTo(dst)
	} else if x, ok := dst.(io.ReaderFrom); ok {
		return x.ReadFrom(src)
	}
	return Stream(dst, src)
}

// Stream reads data from src in to dst until error, and returns the no. of bytes read.
// Internally, it uses io.CopyBuffer, recycling buffers from global pool.
func Stream(dst io.Writer, src io.Reader) (int64, error) {
	if IsNil(src) || IsNil(dst) {
		return 0, errNoStream
	}

	bptr := Alloc()
	b := *bptr
	b = b[:cap(b)]
	defer func() {
		*bptr = b
		Recycle(bptr)
	}()
	return io.CopyBuffer(dst, src, b)
}
