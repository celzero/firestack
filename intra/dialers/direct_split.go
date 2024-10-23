// Copyright 2019 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dialers

import (
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
)

type splitter struct {
	conn  *net.TCPConn
	strat int32       // settings.Split* constant
	used  atomic.Bool // Initially false.  Becomes true after the first write.
}

var _ core.DuplexConn = (*splitter)(nil)

// Write implements DuplexConn.
func (s *splitter) Write(b []byte) (n int, err error) {
	if s.used.Load() {
		// after the first write, there is no special write behavior.
		return s.conn.Write(b)
	} else if ok := s.used.CompareAndSwap(false, true); ok {
		// setting `used` to true ensures that this code only runs once per socket.
		n, err = s.writeSplit(b)
		return n, err
	} else {
		// if `used` is already swapped or set, then the split has already been done.
		return s.conn.Write(b)
	}
}

func (s *splitter) writeSplit(b []byte) (n int, err error) {
	w := s.conn
	switch s.strat {
	case settings.SplitTCP:
		n, err = writeTCPSplit(w, b)
	case settings.SplitTCPOrTLS:
		n, err = writeTCPOrTLSSplit(w, b)
	default:
		log.W("split: unknown dial strategy: %d", s.strat)
		n, err = w.Write(b)
	}
	return
}

// ReadFrom implements DuplexConn.
func (s *splitter) ReadFrom(reader io.Reader) (bytes int64, err error) {
	if !s.used.Load() {
		// This is the first write on this socket.
		// Use copyOnce(), which calls Write(), to get Write's splitting behavior for
		// the first segment.
		if bytes, err = copyOnce(s, reader); err != nil {
			return
		}
	}

	var b int64
	b, err = s.conn.ReadFrom(reader)
	bytes += b
	return
}

// Read implements DuplexConn.
func (s *splitter) Read(b []byte) (int, error) { return s.conn.Read(b) }

// LocalAddr implements DuplexConn.
func (s *splitter) LocalAddr() net.Addr { return laddr(s.conn) }

// RemoteAddr implements DuplexConn.
func (s *splitter) RemoteAddr() net.Addr { return raddr(s.conn) }

func (s *splitter) SetDeadline(t time.Time) error {
	if c := s.conn; c != nil {
		return c.SetDeadline(t)
	}
	return nil // no-op
}

// SetReadDeadline implements DuplexConn.
func (s *splitter) SetReadDeadline(t time.Time) error {
	if c := s.conn; c != nil {
		return c.SetReadDeadline(t)
	}
	return nil // no-op
}

// SetWriteDeadline implements DuplexConn.
func (s *splitter) SetWriteDeadline(t time.Time) error {
	if c := s.conn; c != nil {
		return c.SetWriteDeadline(t)
	}
	return nil // no-op
}

// Close implements DuplexConn.
func (s *splitter) Close() error { core.CloseTCP(s.conn); return nil }

// CloseRead implements DuplexConn.
func (s *splitter) CloseRead() error { core.CloseTCPRead(s.conn); return nil }

// CloseWrite implements DuplexConn.
func (s *splitter) CloseWrite() error { core.CloseTCPWrite(s.conn); return nil }

// SyscallConn implements syscall.Conn.
func (s *splitter) SyscallConn() (syscall.RawConn, error) {
	if c := s.conn; c != nil {
		return c.SyscallConn()
	}
	return nil, syscall.EINVAL
}
