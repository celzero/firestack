package dialers

/*
Combine direct_split with TCB (Transmission Control Block) Desynchronization Attack
Inspired by byedpi
*/

import (
	"crypto/rand"
	"github.com/celzero/firestack/intra/protect"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"strings"
	"errors"
	randNum "math/rand"
)

const (
	probeSize     = 8
	Http1_1String = "POST / HTTP/1.1\r\nHost: 10.0.0.1\r\nContent-Type: application/octet-stream\r\nContent-Length: 9999999\r\n\r\n"
)

type OverwriteSplitter struct {
	*net.TCPConn
	Used    bool
	TTL     int
	Payload []byte //Must be smaller than 1st written packet
	//Note: Normal ClientHello generated by browsers is 517 bytes. If kyber is enabled, the ClientHello can be larger.
}

/*
Check if cmsgArr contains an ICMPv6 hop limit exceeded SockExtendedErr
type SockExtendedErr struct {
	Errno  uint32
	Origin uint8
	Type   uint8
	Code   uint8
	Pad    uint8
	Info   uint32
	Data   uint32
}
https://www.rfc-editor.org/rfc/rfc4443.html#section-3.3
*/
func exceedHopLimit(cmsgArr []unix.SocketControlMessage) bool {
	for _, cmsg := range cmsgArr {
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

/*
Check if cmsgArr contains an ICMPv4 time to live exceeded SockExtendedErr
https://www.rfc-editor.org/rfc/rfc792.html#page-6
*/
func exceedTTL(cmsgArr []unix.SocketControlMessage) bool {
	for _, cmsg := range cmsgArr {
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

/*
DialWithSplitAndDesyncTraceroute estimates the TTL with UDP traceroute,
then returns a TCP connection that may launch TCB Desynchronization Attack and split the initial upstream segment
If `payload` is smaller than the initial upstream segment, it launches the attack and splits.

This traceroute is not accurate, because of time limit (TCP handshake).

Note: The path the UDP packet took to reach the destination may differ from the path the TCP packet took.
*/
func DialWithSplitAndDesyncTraceroute(d *protect.RDial, addr *net.TCPAddr, maxTTL int, payload []byte) (DuplexConn, error) {
	udpAddr := &net.UDPAddr{
		IP:   addr.IP,
		Port: 1,
		Zone: addr.Zone,
	}
	isIPv6 := true
	if addr.IP.To4() != nil {
		isIPv6 = false
	}

	var networkStr string
	if isIPv6 {
		networkStr = "udp6"
	} else {
		networkStr = "udp4"
	}
	udpConn, err := d.AnnounceUDP(networkStr, ":0")
	if err != nil {
		return nil, err
	}
	if udpConn == nil {
		return nil, errNoConn
	}
	defer udpConn.Close()
	rawConn, err := udpConn.SyscallConn()
	if err != nil {
		return nil, err
	}
	if rawConn == nil {
		return nil, errors.New("(*UDPConn) SyscallConn() returned nil")
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
	basePort := 1 + randNum.Intn(65535-maxTTL)
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
		udpAddr.Port = basePort+ttl
		_, err = udpConn.WriteToUDP(msgBuf[:], udpAddr)
		if err != nil {
			return nil, err
		}
	}

	tcpConn, err := d.DialTCP(addr.Network(), nil, addr)
	if err != nil {
		return nil, err
	}
	if tcpConn == nil {
		return nil, errNoConn
	}
	split1 := &OverwriteSplitter{
		TCPConn: tcpConn,
		TTL:     1,
		Payload: payload,
	}

	//After TCP handshake, check received ICMP messages.
	var cmsgBuf [1024]byte
	for i := 0; i < maxTTL-1; i++ {
		_, cmsgN, _, from, err := unix.Recvmsg(udpFD, msgBuf[:], cmsgBuf[:], unix.MSG_ERRQUEUE)
		if err != nil {
			//udpConn must be nonblocking
			break
		}
		cmsgArr, err := unix.ParseSocketControlMessage(cmsgBuf[:cmsgN])
		if err != nil {
			continue
		}
		if isIPv6 {
			if exceedHopLimit(cmsgArr) {
				fromPort := from.(*unix.SockaddrInet6).Port
				ttl = fromPort-basePort
				if ttl > split1.TTL && ttl <= maxTTL {
					split1.TTL = ttl
				}
			}
		} else {
			if exceedTTL(cmsgArr) {
				fromPort := from.(*unix.SockaddrInet4).Port
				ttl = fromPort-basePort
				if ttl > split1.TTL && ttl <= maxTTL {
					split1.TTL = ttl
				}
			}
		}
	}

	return split1, nil
}

func DialWithSplitAndDesyncFixedTtl(d *protect.RDial, addr *net.TCPAddr, initialTTL int, payload []byte) (DuplexConn, error) {
	tcpConn, err := d.DialTCP(addr.Network(), nil, addr)
	if err != nil {
		return nil, err
	}
	if tcpConn == nil {
		return nil, errNoConn
	}
	split1 := &OverwriteSplitter{
		TCPConn: tcpConn,
		TTL:     initialTTL,
		Payload: payload,
	}
	return split1, nil
}

func DialWithSplitAndDesyncSmart(d *protect.RDial, addr *net.TCPAddr, maxTTL int, payload []byte) (DuplexConn, error) {
	ttl, ok := queryTracerouteResult(addr.IP)
	if ok {
		return DialWithSplitAndDesyncFixedTtl(d, addr, ttl, payload)
	}
	conn, err := DialWithSplitAndDesyncTraceroute(d, addr, maxTTL, payload)
	if err == nil {
		addTracerouteResult(addr.IP, conn.(*OverwriteSplitter).TTL)
	}
	return conn, err
}

func (s *OverwriteSplitter) Write(b []byte) (int, error) {
	conn := s.TCPConn
	if s.Used {
		// After the first write, there is no special write behavior.
		return conn.Write(b)
	}

	// Setting `Used` to true ensures that this code only runs once per socket.
	s.Used = true
	if len(b) <= len(s.Payload) {
		return conn.Write(b)
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	if rawConn == nil {
		return 0, errors.New("(*TCPConn) SyscallConn() returned nil")
	}
	var sockFD int
	err = rawConn.Control(func(fd uintptr) {
		sockFD = int(fd)
	})
	if err != nil {
		return 0, err
	}

	fileFD, err := unix.MemfdCreate("haar", unix.O_RDWR)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fileFD)
	err = unix.Ftruncate(fileFD, int64(len(s.Payload)))
	if err != nil {
		return 0, err
	}
	firstSegment, err := unix.Mmap(fileFD, 0, len(s.Payload), unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return 0, err
	}
	defer unix.Munmap(firstSegment)

	// We want s.Payload to be seen by censors, but don't want s.Payload to be seen by the server.
	copy(firstSegment, s.Payload)
	mRemote := conn.RemoteAddr()
	if mRemote == nil {
		return 0, errors.New("RemoteAddr() returned nil")
	}
	isIPv6 := strings.Contains(mRemote.String(), "[")
	if isIPv6 {
		err = unix.SetsockoptInt(sockFD, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, s.TTL)
	} else {
		err = unix.SetsockoptInt(sockFD, unix.IPPROTO_IP, unix.IP_TTL, s.TTL)
	}
	if err != nil {
		return 0, err
	}
	var offset int64 = 0
	n1, err := unix.Sendfile(sockFD, fileFD, &offset, len(s.Payload))
	if err != nil {
		return n1, err
	}

	copy(firstSegment, b[:len(s.Payload)])
	if isIPv6 {
		err = unix.SetsockoptInt(sockFD, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, 64)
	} else {
		err = unix.SetsockoptInt(sockFD, unix.IPPROTO_IP, unix.IP_TTL, 64)
	}
	if err != nil {
		return n1, err
	}

	// Write the second segment
	n2, err := conn.Write(b[len(s.Payload):])
	return n1 + n2, err
}

func (s *OverwriteSplitter) ReadFrom(reader io.Reader) (bytes int64, err error) {
	if !s.Used {
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
