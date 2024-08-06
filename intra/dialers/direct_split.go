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

	"github.com/celzero/firestack/intra/protect"
)

// DuplexConn represents a bidirectional stream socket.
type DuplexConn interface {
	net.Conn
	io.ReaderFrom
	CloseWrite() error
	CloseRead() error
}

type splitter struct {
	*net.TCPConn
	used bool // Initially false.  Becomes true after the first write.
}

var _ DuplexConn = (*splitter)(nil)

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
	return &splitter{TCPConn: conn}, nil
}

// Write-related functions
func (s *splitter) Write(b []byte) (n int, err error) {
	conn := s.TCPConn
	if s.used {
		// After the first write, there is no special write behavior.
		return conn.Write(b)
	}

	// Setting `used` to true ensures that this code only runs once per socket.
	s.used = true
	n, _, err = writeSplit(conn, b)
	return n, err
}

func (s *splitter) ReadFrom(reader io.Reader) (bytes int64, err error) {
	if !s.used {
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
