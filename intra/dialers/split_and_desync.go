package dialers

/*
Combine direct_split with TCB (Transmission Control Block) Desynchronization Attack
Inspired by byedpi
*/

import (
	"crypto/rand"
	"errors"
	"io"
	mathrand "math/rand"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"golang.org/x/sys/unix"
)

const (
	probeSize     = 8
	Http1_1String = "POST / HTTP/1.1\r\nHost: 10.0.0.1\r\nContent-Type: application/octet-stream\r\nContent-Length: 9999999\r\n\r\n"
)

// ttlcache stores the TTL for a given IP address for a limited time.
// TODO: invalidate cache on network changes.
var ttlcache = core.NewDefaultSieve[netip.Addr, int]()

type OverwriteSplitter struct {
	conn    *net.TCPConn
	used    atomic.Bool
	ttl     int
	payload []byte // must be smaller than 1st written packet
	// note: Normal ClientHello generated by browsers is 517 bytes. If kyber is enabled, the ClientHello can be larger.
}

var _ DuplexConn = (*OverwriteSplitter)(nil)

// exceedsHopLimit checks if cmsgs contains an ICMPv6 hop limit exceeded SockExtendedErr
//
//	type SockExtendedErr struct {
//		Errno  uint32
//		Origin uint8
//		Type   uint8
//		Code   uint8
//		Pad    uint8
//		Info   uint32
//		Data   uint32
//	}
//
// https://www.rfc-editor.org/rfc/rfc4443.html#section-3.3
func exceedsHopLimit(cmsgs []unix.SocketControlMessage) bool {
	for _, cmsg := range cmsgs {
		if cmsg.Header.Level == unix.IPPROTO_IPV6 && cmsg.Header.Type == unix.IPV6_RECVERR {
			eeOrigin := cmsg.Data[4]
			if eeOrigin == unix.SO_EE_ORIGIN_ICMP6 {
				eeType := cmsg.Data[5]
				eeCode := cmsg.Data[6]
				if eeType == 3 && eeCode == 0 {
					return true
				}
			}
		}
	}
	return false
}

// exceedsTTL checks if cmsgs contains an ICMPv4 time to live exceeded SockExtendedErr.
// https://www.rfc-editor.org/rfc/rfc792.html#page-6
func exceedsTTL(cmsgs []unix.SocketControlMessage) bool {
	for _, cmsg := range cmsgs {
		if cmsg.Header.Level == unix.IPPROTO_IP && cmsg.Header.Type == unix.IP_RECVERR {
			eeOrigin := cmsg.Data[4]
			if eeOrigin == unix.SO_EE_ORIGIN_ICMP {
				eeType := cmsg.Data[5]
				eeCode := cmsg.Data[6]
				if eeType == 11 && eeCode == 0 {
					return true
				}
			}
		}
	}
	return false
}

// DialWithSplitAndDesyncTraceroute estimates the TTL with UDP traceroute,
// then returns a TCP connection that may launch TCB Desynchronization Attack and split the initial upstream segment
// If `payload` is smaller than the initial upstream segment, it launches the attack and splits.
// This traceroute is not accurate, because of time limit (TCP handshake).
// Note: The path the UDP packet took to reach the destination may differ from the path the TCP packet took.
func DialWithSplitAndDesyncTraceroute(d *protect.RDial, ipp netip.AddrPort, maxTTL int, payload []byte) (*OverwriteSplitter, error) {
	udpAddr := net.UDPAddrFromAddrPort(ipp)
	udpAddr.Port = 1 // unset port

	isIPv6 := ipp.Addr().Is6()
	udpConn, err := d.AnnounceUDP("udp", ":0")
	if err != nil {
		log.E("split-desync: err announcing udp: %v", err)
		return nil, err
	}
	if udpConn == nil {
		return nil, errNoConn
	}

	defer func() {
		err := udpConn.Close()
		logeif(err)("split-desync: close udp; err? %v", err)
	}()

	rawConn, err := udpConn.SyscallConn()
	if err != nil {
		return nil, err
	}
	if rawConn == nil {
		return nil, errors.New("split-desync: SyscallConn(udp) nil")
	}
	var udpFD int
	err = rawConn.Control(func(fd uintptr) {
		udpFD = int(fd)
	})
	if err != nil {
		return nil, err
	}

	if isIPv6 {
		err = unix.SetsockoptInt(udpFD, unix.IPPROTO_IPV6, unix.IPV6_RECVERR, 1)
	} else {
		err = unix.SetsockoptInt(udpFD, unix.IPPROTO_IP, unix.IP_RECVERR, 1)
	}
	if err != nil {
		return nil, err
	}

	var msgBuf [probeSize]byte
	var ttl int
	basePort := 1 + mathrand.Intn(65535-maxTTL) //#nosec G404
	for ttl = 2; ttl <= maxTTL; ttl++ {
		_, err = rand.Read(msgBuf[:])
		if err != nil {
			return nil, err
		}
		if isIPv6 {
			err = unix.SetsockoptInt(udpFD, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, ttl)
		} else {
			err = unix.SetsockoptInt(udpFD, unix.IPPROTO_IP, unix.IP_TTL, ttl)
		}
		if err != nil {
			return nil, err
		}
		udpAddr.Port = basePort + ttl
		_, err = udpConn.WriteToUDP(msgBuf[:], udpAddr)
		if err != nil {
			return nil, err
		}
	}

	tcpConn, err := d.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(ipp))
	if err != nil {
		return nil, err
	}
	if tcpConn == nil {
		return nil, errNoConn
	}

	var cmsgBuf [1024]byte
	split1 := &OverwriteSplitter{
		conn:    tcpConn,
		ttl:     1,
		payload: payload,
	}

	// after TCP handshake, check received ICMP messages.
	for i := 0; i < maxTTL-1; i++ {
		_, cmsgN, _, from, err := unix.Recvmsg(udpFD, msgBuf[:], cmsgBuf[:], unix.MSG_ERRQUEUE)
		if err != nil {
			log.W("split-desync: recvmsg failed: %v", err)
			//udpConn must be nonblocking
			break
		}

		cmsgs, err := unix.ParseSocketControlMessage(cmsgBuf[:cmsgN])
		if err != nil {
			log.W("split-desync: parseSocketControlMessage failed: %v", err)
			continue
		}

		exceeds := false
		if isIPv6 {
			exceeds = exceedsHopLimit(cmsgs)
			if exceeds {
				fromPort := from.(*unix.SockaddrInet6).Port
				ttl = fromPort - basePort
				if ttl <= maxTTL {
					split1.ttl = max(split1.ttl, ttl)
				}
			}
		} else {
			exceeds = exceedsTTL(cmsgs)
			if exceeds {
				fromPort := from.(*unix.SockaddrInet4).Port
				ttl = fromPort - basePort
				if ttl <= maxTTL {
					split1.ttl = max(split1.ttl, ttl)
				}
			}
		}
	}
	log.D("split-desync: addr: %v, ttl: %d", ipp, split1.ttl)

	return split1, nil
}

func DialWithSplitAndDesyncFixedTtl(d *protect.RDial, addr netip.AddrPort, initialTTL int, payload []byte) (*OverwriteSplitter, error) {
	tcpConn, err := d.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(addr))
	if err != nil {
		return nil, err
	}
	if tcpConn == nil {
		return nil, errNoConn
	}
	return &OverwriteSplitter{
		conn:    tcpConn,
		ttl:     initialTTL,
		payload: payload,
	}, nil
}

// DialWithSplitAndDesyncSmart estimates the TTL with UDP traceroute,
// then returns a TCP connection that may launch TCB Desynchronization
// and split the initial upstream segment.
func DialWithSplitAndDesyncSmart(d *protect.RDial, ipp netip.AddrPort, maxTTL int, payload []byte) (DuplexConn, error) {
	ttl, ok := ttlcache.Get(ipp.Addr())
	if ok {
		return DialWithSplitAndDesyncFixedTtl(d, ipp, ttl, payload)
	}
	conn, err := DialWithSplitAndDesyncTraceroute(d, ipp, maxTTL, payload)
	if err == nil {
		ttlcache.Put(ipp.Addr(), conn.ttl)
	}
	return conn, err
}

// Close implements DuplexConn.
func (s *OverwriteSplitter) Close() error { core.CloseTCP(s.conn); return nil }

// CloseRead implements DuplexConn.
func (s *OverwriteSplitter) CloseRead() error { core.CloseTCPRead(s.conn); return nil }

// CloseWrite implements DuplexConn.
func (s *OverwriteSplitter) CloseWrite() error { core.CloseTCPWrite(s.conn); return nil }

// LocalAddr implements DuplexConn.
func (s *OverwriteSplitter) LocalAddr() net.Addr { return laddr(s.conn) }

// RemoteAddr implements DuplexConn.
func (s *OverwriteSplitter) RemoteAddr() net.Addr { return raddr(s.conn) }

func (s *OverwriteSplitter) SetDeadline(t time.Time) error {
	if c := s.conn; c != nil {
		return c.SetDeadline(t)
	}
	return nil // no-op
}

// SetReadDeadline implements DuplexConn.
func (s *OverwriteSplitter) SetReadDeadline(t time.Time) error {
	if c := s.conn; c != nil {
		return c.SetReadDeadline(t)
	}
	return nil // no-op
}

// SetWriteDeadline implements DuplexConn.
func (s *OverwriteSplitter) SetWriteDeadline(t time.Time) error {
	if c := s.conn; c != nil {
		return c.SetWriteDeadline(t)
	}
	return nil // no-op
}

// Read implements DuplexConn.
func (s *OverwriteSplitter) Read(b []byte) (int, error) { return s.conn.Read(b) }

// Write implements DuplexConn.
func (s *OverwriteSplitter) Write(b []byte) (int, error) {
	conn := s.conn
	if s.used.Load() {
		// after the first write, there is no special write behavior.
		return conn.Write(b)
	}

	// set `Used` to ensure this code only runs once per conn.
	s.used.Store(true)
	if len(b) <= len(s.payload) {
		return conn.Write(b)
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	if rawConn == nil {
		return 0, errors.New("split-desync: SyscallConn(tcp) nil")
	}
	var sockFD int
	err = rawConn.Control(func(fd uintptr) {
		sockFD = int(fd)
	})
	if err != nil {
		log.E("split-desync: get sock fd failed; %v", err)
		return 0, err
	}

	fileFD, err := unix.MemfdCreate("haar", unix.O_RDWR)
	if err != nil {
		return 0, err
	}
	defer func() {
		err := unix.Close(fileFD)
		logeif(err)("desync: close memfd; err? %v", err)
	}()
	err = unix.Ftruncate(fileFD, int64(len(s.payload)))
	if err != nil {
		return 0, err
	}
	firstSegment, err := unix.Mmap(fileFD, 0, len(s.payload), unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return 0, err
	}
	defer func() {
		err := unix.Munmap(firstSegment)
		logeif(err)("desync: munmap; err? %v", err)
	}()

	// We want s.Payload to be seen by censors, but don't want s.Payload to be seen by the server.
	copy(firstSegment, s.payload)
	mRemote := conn.RemoteAddr()
	if mRemote == nil {
		return 0, errors.New("split-desync: remoteaddr nil")
	}
	isIPv6 := strings.Contains(mRemote.String(), "[")
	if isIPv6 {
		err = unix.SetsockoptInt(sockFD, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, s.ttl)
	} else {
		err = unix.SetsockoptInt(sockFD, unix.IPPROTO_IP, unix.IP_TTL, s.ttl)
	}
	if err != nil {
		log.E("split-desync: setsockopt failed: %v", err)
		return 0, err
	}
	var offset int64 = 0
	n1, err := unix.Sendfile(sockFD, fileFD, &offset, len(s.payload))
	if err != nil {
		log.E("split-desync: sendfile %d failed: %v", n1, err)
		return n1, err
	}

	copy(firstSegment, b[:len(s.payload)])
	if isIPv6 {
		err = unix.SetsockoptInt(sockFD, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, 64)
	} else {
		err = unix.SetsockoptInt(sockFD, unix.IPPROTO_IP, unix.IP_TTL, 64)
	}
	if err != nil {
		log.E("split-desync: setsockopt failed: %v", err)
		return n1, err
	}

	// write the second segment
	n2, err := conn.Write(b[len(s.payload):])
	logeif(err)("split-desync: write: n1: %d, n2: %d, err: %v", n1, n2, err)
	return n1 + n2, err
}

// ReadFrom reads from the reader and writes to s.
func (s *OverwriteSplitter) ReadFrom(reader io.Reader) (bytes int64, err error) {
	copies := 0
	for !s.used.Load() {
		b, e := copyOnce(s, reader)

		copies++
		bytes += b

		logeif(err)("split-desync: readfrom: copyOnce #%d; sz: %d/%d; err: %v", copies, b, bytes, err)
		if e != nil {
			return bytes, e
		}
	}

	b, err := s.conn.ReadFrom(reader)
	bytes += b
	return
}
