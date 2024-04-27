package dialers

import (
	"io"
	"net"
	"strings"
	"syscall"
	"github.com/celzero/firestack/intra/protect"
)

type WeirdSplitter struct {
	*net.TCPConn
	used         bool
	Size         int
	randomOffset bool
}

// similar to DialWithSplit(), but the second segment will be received first and it allow users to specify the size of 1st segment
func DialWithWeirdSplit(d *protect.RDial, addr *net.TCPAddr, size int) (DuplexConn, error) {
	tcpConn, err := d.DialTCP(addr.Network(), nil, addr)
	if err != nil {
		return nil, err
	}
	if tcpConn == nil {
		return nil, errNoConn
	}
	split1 := &WeirdSplitter{
		TCPConn: tcpConn,
		Size:    size,
	}
	return split1, nil
}

// similar to DialWithSplit(), but the second segment will be received first.
func DialWithWeirdSplitRandomOffset(d *protect.RDial, addr *net.TCPAddr) (DuplexConn, error) {
	tcpConn, err := d.DialTCP(addr.Network(), nil, addr)
	if err != nil {
		return nil, err
	}
	if tcpConn == nil {
		return nil, errNoConn
	}
	split1 := &WeirdSplitter{
		TCPConn:      tcpConn,
		randomOffset: true,
	}
	return split1, nil
}

func (s *WeirdSplitter) Write(b []byte) (int, error) {
	conn := s.TCPConn
	if s.used {
		// After the first write, there is no special write behavior.
		return conn.Write(b)
	}

	// Setting `used` to true ensures that this code only runs once per socket.
	s.used = true
	// One-byte segment is unable to be split.
	if len(b) < 2 {
		return conn.Write(b)
	}
	var b1, b2 []byte
	if s.randomOffset {
		b1, b2 = splitHello(b)
	} else {
		size := s.Size
		if len(b) <= s.Size {
			size = 1
		}
		b1 = b[:size]
		b2 = b[size:]
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
	n1, err := conn.Write(b1)
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
	n2, err := conn.Write(b2)
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
