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

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
)

type splitter struct {
	*net.TCPConn
	strat int32
	used  atomic.Bool // Initially false.  Becomes true after the first write.
}

var _ core.DuplexConn = (*splitter)(nil)

// DialWithSplit returns a TCP connection that always splits the initial upstream segment.
// Like net.Conn, it is intended for two-threaded use, with one thread calling
// Read and CloseRead, and another calling Write, ReadFrom, and CloseWrite.
func DialWithSplit(d *protect.RDial, addr *net.TCPAddr) (*splitter, error) {
	conn, err := d.DialTCP(addr.Network(), nil, addr)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, net.UnknownNetworkError("no conn")
	}
	strat := settings.DialStrategy.Load()
	return &splitter{TCPConn: conn, strat: strat}, nil
}

// Write-related functions
func (s *splitter) Write(b []byte) (n int, err error) {
	conn := s.TCPConn
	strat := s.strat
	if s.used.Load() {
		// after the first write, there is no special write behavior.
		return conn.Write(b)
	} else if ok := s.used.CompareAndSwap(false, true); ok {
		// setting `used` to true ensures that this code only runs once per socket.
		n, _, err = writeSplit(strat, conn, b)
		return n, err
	} else {
		// if `used` is already swapped, then the split has already been done.
		return conn.Write(b)
	}
}

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
	b, err = s.TCPConn.ReadFrom(reader)
	bytes += b
	return
}
