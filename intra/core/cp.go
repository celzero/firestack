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
// Otherwise, it uses core.Stream.
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
// Internally, it bypasses io.ReaderFrom and io.WriterTo but uses io.CopyBuffer,
// recycling buffers from a global pool.
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
	return io.CopyBuffer(
		writerNoReadFrom{Writer: dst},
		readerNoWriteTo{Reader: src},
		b,
	)
}

// from: go-review.googlesource.com/c/go/+/472475/20/src/net/net.go

// noReadFrom can be embedded alongside another type to
// hide the ReadFrom method of that other type.
type noReadFrom struct{}

// ReadFrom hides another ReadFrom method.
// It should never be called.
func (noReadFrom) ReadFrom(io.Reader) (int64, error) {
	panic("noReadFrom: hidden func; should not be called")
}

// noWriteTo can be embedded alongside another type to
// hide the WriterTo method of that other type.
type noWriteTo struct{}

func (noWriteTo) WriteTo(io.Writer) (int64, error) {
	panic("noWriteTo: hidden func; should not be called")
}

// writerNoReadFrom implements all the methods of io.Writer other
// than ReadFrom. This is used to permit ReadFrom to call io.Copy
// without leading to a recursive call to ReadFrom.
type writerNoReadFrom struct {
	noReadFrom
	io.Writer
}

// readerNoWriteTo implements all the methods of io.Reader other
// than WriteTo. This is used to permit WriteTo to call io.Copy
// without leading to a recursive call to WriteTo.
type readerNoWriteTo struct {
	noWriteTo
	io.Reader
}
