package dialers

import (
	"io"
	"net"
	"strings"
	"syscall"
)

type WeirdSplitter struct {
	*net.TCPConn
	Used bool
	Size int
}

func (s *WeirdSplitter) Write(b []byte) (int, error) {
	conn := s.TCPConn
	if s.Used {
		// After the first write, there is no special write behavior.
		return conn.Write(b)
	}

	// Setting `used` to true ensures that this code only runs once per socket.
	s.Used = true
	// One-byte segment is unable to be split.
	if len(b) < 2 {
		return conn.Write(b)
	}
	var size int
	if len(b) > s.Size {
		size = s.Size
	} else {
		size = 1
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	isIPv6 := strings.Contains(conn.RemoteAddr().String(), "[")

	rawErr := rawConn.Control(func(fd uintptr) {
		if isIPv6 {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, 1)
		} else {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, 1)
		}
	})
	if err != nil {
		return 0, err
	}
	if rawErr != nil {
		return 0, rawErr
	}
	n1, err := conn.Write(b[:size])
	if err != nil {
		return n1, err
	}

	rawErr = rawConn.Control(func(fd uintptr) {
		if isIPv6 {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, 64)
		} else {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, 64)
		}
	})
	if err != nil {
		return n1, err
	}
	if rawErr != nil {
		return n1, rawErr
	}
	n2, err := conn.Write(b[size:])
	return n1 + n2, err
}

func (s *WeirdSplitter) ReadFrom(reader io.Reader) (bytes int64, err error) {
	if !s.used {
		// This is the first write on this socket.
		// Use copyOnce(), which calls Write(), to get Write's splitting behavior for
		// the first segment.
		if bytes, err = copyOnce(s, reader); err != nil {
			return
		}
	}

	b, err := s.TCPConn.ReadFrom(reader)
	bytes += b
	return
}
