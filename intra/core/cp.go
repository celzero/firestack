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

	// errInvalidWrite means that a write returned an impossible count.
	errInvalidWrite = errors.New("invalid write result")
)

// Pipe reads data from src to dst, and returns the number of bytes copied.
// Prefers src.WriteTo(dst) and dst.ReadFrom(src) if available.
// Otherwise, it uses core.Stream.
func Pipe(dst io.Writer, src io.Reader) (int64, error) {
	if IsNil(src) || IsNil(dst) {
		return 0, errNoPipe
	}

	// Retrier conns have specific entry-points; make sure those
	// get priority over regular copy.
	if x, ok := src.(WriteRetrierConn); ok {
		return x.WriteTo(dst)
	} else if x, ok := dst.(ReadRetrierConn); ok {
		return x.ReadFrom(src)
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
func Stream(dst io.Writer, src io.Reader) (written int64, err error) {
	if IsNil(src) || IsNil(dst) {
		return 0, errNoStream
	}

	// TODO: writerNoReadFrom and readerNoWriteTo
	bptr := Alloc16() // TLS record size?
	buf := *bptr
	buf = buf[:cap(buf)]
	defer func() {
		*bptr = buf
		Recycle(bptr)
	}()
	// implementation from: io.CopyBuffer
	// laid out here since "hiding" ReadFrom/WriteTo funcs
	// did not work as expected and led to recursive calls.
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = errInvalidWrite
				}
			}
			written += int64(nw)
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}

// ref: github.com/golang/go/issues/58808
// from: go-review.googlesource.com/c/go/+/472475/20/src/net/net.go

// noReadFrom can be embedded alongside another type to
// hide the ReadFrom method of that other type.
// type noReadFrom struct{}

// ReadFrom hides another ReadFrom method.
// It should never be called.
// func (noReadFrom) ReadFrom(io.Reader) (int64, error) {
// 	panic("noReadFrom: hidden func; should not be called")
// }

// noWriteTo can be embedded alongside another type to
// hide the WriterTo method of that other type.
// type noWriteTo struct{}

// func (noWriteTo) WriteTo(io.Writer) (int64, error) {
// 	panic("noWriteTo: hidden func; should not be called")
// }

// noReadFromWriter implements all the methods of io.Writer other
// than ReadFrom. This is used to permit ReadFrom to call io.Copy
// without leading to a recursive call to ReadFrom.
// type noReadFromWriter struct {
// 	noReadFrom
// 	io.Writer
// }

// noWriteToReader implements all the methods of io.Reader other
// than WriteTo. This is used to permit WriteTo to call io.Copy
// without leading to a recursive call to WriteTo.
// type noWriteToReader struct {
// 	noWriteTo
// 	io.Reader
// }
