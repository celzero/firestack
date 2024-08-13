// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dialers

import (
	"io"
	"math/rand"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"golang.org/x/sys/unix"
)

const (
	probeSize   = 8
	default_ttl = 64

	// desync_relaxed enables relaxed mode, which lets connections go through without desync.
	desync_relaxed    = true
	desync_http1_1str = "POST / HTTP/1.1\r\nHost: 10.0.0.1\r\nContent-Type: application/octet-stream\r\nContent-Length: 9999999\r\n\r\n"
	// from: github.com/bol-van/zapret/blob/c369f11638/nfq/darkmagic.h#L214-L216
	desync_max_ttl     = 20
	desync_noop_ttl    = 3
	desync_delta_ttl   = 1
	desync_invalid_ttl = -1
)

// ttlcache stores the TTL for a given IP address for a limited time.
// TODO: invalidate cache on network changes.
var ttlcache = core.NewDefaultSieve[netip.Addr, int]()

// Combines direct split with TCB Desynchronization Attack
// Inspired by byedpi: github.com/hufrea/byedpi/blob/82e5229df00/desync.c#L69-L123
type overwriteSplitter struct {
	conn    *net.TCPConn // underlying connection
	used    atomic.Bool  // ensures desync only runs once
	ttl     int          // desync TTL
	ip6     bool         // IPv6
	payload []byte       // must be smaller than 1st written packet
	// note: Normal ClientHello generated by browsers is 517 bytes. If kyber is enabled, the ClientHello can be larger.
}

var _ core.DuplexConn = (*overwriteSplitter)(nil)

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

// tracert dials a UDP conn to the target address over a port range basePort to basePort+DESYNC_MAX_TTL, with TTL
// set to 2, 3, ..., DESYNC_MAX_TTL. It does not take ownership of the conn (which must be closed by the caller).
func tracert(d *protect.RDial, ipp netip.AddrPort, basePort int) (*net.UDPConn, int, error) {
	udpAddr := net.UDPAddrFromAddrPort(ipp)
	udpAddr.Port = 1 // unset port

	isIPv6 := ipp.Addr().Is6()

	// explicitly prefer udp4 for IPv4 to prevent OS from giving cmsg(s) which mix IPPROTO_IPV6 cmsg level
	// & IPv4-related cmsg data, because exceedsTTL() returns false when cmsg.Header.Level == IPPROTO_IPV6.
	// that is: "udp" dials a dual-stack connection, which we don't want.
	proto := "udp4"
	if isIPv6 {
		proto = "udp6"
	}

	var udpFD int
	uc, err := d.AnnounceUDP(proto, ":0")
	if err != nil {
		log.E("split-desync: err announcing udp: %v", err)
		return uc, udpFD, err
	}
	if uc == nil {
		return uc, udpFD, errNoConn
	}

	rawConn, err := uc.SyscallConn()
	if err != nil {
		return uc, udpFD, err
	}
	if rawConn == nil {
		return uc, udpFD, errNoSysConn
	}
	err = rawConn.Control(func(fd uintptr) {
		udpFD = int(fd)
	})
	if err != nil {
		return uc, udpFD, err
	}

	if isIPv6 {
		err = unix.SetsockoptInt(udpFD, unix.IPPROTO_IPV6, unix.IPV6_RECVERR, 1)
	} else {
		err = unix.SetsockoptInt(udpFD, unix.IPPROTO_IP, unix.IP_RECVERR, 1)
	}
	if err != nil {
		return uc, udpFD, err
	}

	var msgBuf [probeSize]byte
	for ttl := 2; ttl <= desync_max_ttl; ttl += desync_delta_ttl {
		_, err = rand.Read(msgBuf[:])
		if err != nil {
			return uc, udpFD, err
		}
		if isIPv6 {
			err = unix.SetsockoptInt(udpFD, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, ttl)
		} else {
			err = unix.SetsockoptInt(udpFD, unix.IPPROTO_IP, unix.IP_TTL, ttl)
		}
		if err != nil {
			return uc, udpFD, err
		}
		udpAddr.Port = basePort + ttl
		_, err = uc.WriteToUDP(msgBuf[:], udpAddr)
		// todo: continue if in relaxed mode?
		if err != nil {
			return uc, udpFD, err
		}
	}
	return uc, udpFD, nil
}

// desyncWithTraceroute estimates the TTL with UDP traceroute,
// then returns a TCP connection that may launch TCB Desynchronization Attack and split the initial upstream segment
// If `payload` is smaller than the initial upstream segment, it launches the attack and splits.
// This traceroute is not accurate, because of time limit (TCP handshake).
// Note: The path the UDP packet took to reach the destination may differ from the path the TCP packet took.
func desyncWithTraceroute(d *protect.RDial, ipp netip.AddrPort) (*overwriteSplitter, error) {
	measureTTL := true
	isIPv6 := ipp.Addr().Is6()
	basePort := 1 + rand.Intn(65535-(desync_max_ttl)) //#nosec G404

	uc, udpFD, err := tracert(d, ipp, basePort)
	defer core.Close(uc)

	logeif(err)("split-desync: dialUDP %v %d: err? %v", ipp, udpFD, err)
	if err != nil {
		measureTTL = false
		if !desync_relaxed {
			return nil, err
		}
	}

	proto := "tcp4"
	if isIPv6 {
		proto = "tcp6"
	}

	tcpConn, err := d.DialTCP(proto, nil, net.TCPAddrFromAddrPort(ipp))
	if err != nil {
		log.E("split-desync: dialTCP %v err: %v", ipp, err)
		return nil, err
	}
	if tcpConn == nil {
		log.E("split-desync: dialTCP %v err: %v", ipp, errNoConn)
		return nil, errNoConn
	}

	var msgBuf [probeSize]byte

	bptr := core.Alloc()
	cmsgBuf := *bptr
	cmsgBuf = cmsgBuf[:cap(cmsgBuf)]
	defer func() {
		*bptr = cmsgBuf
		core.Recycle(bptr)
	}()

	oc := &overwriteSplitter{
		conn:    tcpConn,
		ttl:     desync_noop_ttl,
		payload: []byte(desync_http1_1str),
		ip6:     isIPv6,
	}

	processed := false
	// after TCP handshake, check received ICMP messages, if measureTTL is true.
	for i := 0; i < desync_max_ttl-1 && measureTTL; i += desync_delta_ttl {
		_, cmsgN, _, from, err := unix.Recvmsg(udpFD, msgBuf[:], cmsgBuf[:], unix.MSG_ERRQUEUE)
		if err != nil {
			log.V("split-desync: recvmsg %v, err: %v", ipp, err)
			break
		}

		cmsgs, err := unix.ParseSocketControlMessage(cmsgBuf[:cmsgN])
		if err != nil {
			log.W("split-desync: parseSocketControlMessage %v failed: %v", ipp, err)
			continue
		}

		if isIPv6 {
			if exceedsHopLimit(cmsgs) {
				fromPort := from.(*unix.SockaddrInet6).Port
				ttl := fromPort - basePort
				if ttl > desync_max_ttl {
					break
				}
				oc.ttl = max(oc.ttl, ttl)
				processed = true
			}
		} else {
			if exceedsTTL(cmsgs) {
				fromPort := from.(*unix.SockaddrInet4).Port
				ttl := fromPort - basePort
				if ttl > desync_max_ttl {
					break
				}
				oc.ttl = max(oc.ttl, ttl)
				processed = true
			}
		}
	}

	if !processed {
		// skip desync if no measurement is done
		oc.used.Store(false)
		oc.ttl = desync_invalid_ttl
	}

	log.D("split-desync: done: %v, used? %t, ttl: %d", ipp, oc.used.Load(), oc.ttl)

	return oc, nil
}

func desyncWithFixedTtl(d *protect.RDial, ipp netip.AddrPort, initialTTL int) (*overwriteSplitter, error) {
	tcpConn, err := d.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(ipp))
	if err != nil {
		return nil, err
	}
	if tcpConn == nil {
		return nil, errNoConn
	}
	s := &overwriteSplitter{
		conn:    tcpConn,
		ttl:     initialTTL,
		payload: []byte(desync_http1_1str),
		ip6:     ipp.Addr().Is6(),
	}
	// skip desync if no measurement is done
	s.used.Store(s.ttl == desync_invalid_ttl)
	return s, nil
}

// DialWithSplitAndDesync estimates the TTL with UDP traceroute,
// then returns a TCP connection that may launch TCB Desynchronization
// and split the initial upstream segment.
// ref: github.com/bol-van/zapret/blob/c369f11638/docs/readme.eng.md#dpi-desync-attack
func dialWithSplitAndDesync(d *protect.RDial, ipp netip.AddrPort) (*overwriteSplitter, error) {
	ttl, ok := ttlcache.Get(ipp.Addr())
	if ok {
		return desyncWithFixedTtl(d, ipp, ttl)
	}
	conn, err := desyncWithTraceroute(d, ipp)
	if err == nil && conn != nil { // go vet (incorrectly) complains conn being nil when err is nil
		ttlcache.Put(ipp.Addr(), conn.ttl)
	}
	return conn, err
}

// Close implements DuplexConn.
func (s *overwriteSplitter) Close() error { core.CloseTCP(s.conn); return nil }

// CloseRead implements DuplexConn.
func (s *overwriteSplitter) CloseRead() error { core.CloseTCPRead(s.conn); return nil }

// CloseWrite implements DuplexConn.
func (s *overwriteSplitter) CloseWrite() error { core.CloseTCPWrite(s.conn); return nil }

// LocalAddr implements DuplexConn.
func (s *overwriteSplitter) LocalAddr() net.Addr { return laddr(s.conn) }

// RemoteAddr implements DuplexConn.
func (s *overwriteSplitter) RemoteAddr() net.Addr { return raddr(s.conn) }

func (s *overwriteSplitter) SetDeadline(t time.Time) error {
	if c := s.conn; c != nil {
		return c.SetDeadline(t)
	}
	return nil // no-op
}

// SetReadDeadline implements DuplexConn.
func (s *overwriteSplitter) SetReadDeadline(t time.Time) error {
	if c := s.conn; c != nil {
		return c.SetReadDeadline(t)
	}
	return nil // no-op
}

// SetWriteDeadline implements DuplexConn.
func (s *overwriteSplitter) SetWriteDeadline(t time.Time) error {
	if c := s.conn; c != nil {
		return c.SetWriteDeadline(t)
	}
	return nil // no-op
}

// Read implements DuplexConn.
func (s *overwriteSplitter) Read(b []byte) (int, error) { return s.conn.Read(b) }

// Write implements DuplexConn.
// ref: github.com/hufrea/byedpi/blob/82e5229df00/desync.c#L69-L123
func (s *overwriteSplitter) Write(b []byte) (n int, err error) {
	conn := s.conn
	laddr := laddr(s.conn)
	raddr := raddr(s.conn)

	noop := len(b) == 0 // go vet has us handle this case
	short := len(b) < len(s.payload)
	swapped := false
	used := s.used.Load() // also true when s.ttl == desync_invalid_ttl
	if noop {
		n, err = 0, nil
	} else if used {
		// after the first write, there is no special write behavior.
		// used may also be set to true to avoid desync.
		n, err = conn.Write(b)
	} else if swapped = s.used.CompareAndSwap(false, true); !swapped {
		// set `used` to ensure this code only runs once per conn;
		// if !swapped, some other goroutine has already swapped it.
		n, err = conn.Write(b)
	} else if short {
		n, err = conn.Write(b)
	}
	if used || short || !swapped || noop {
		logeif(err)("split-desync: write: %s => %s; desync done %d; (noop? %t, used? %t, short? %t, race? %t); err? %v",
			laddr, raddr, n, noop, used, short, !swapped, err)
		return n, err
	}

	rawConn, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	if rawConn == nil {
		return 0, errNoSysConn
	}

	var sockFD int
	err = rawConn.Control(func(fd uintptr) {
		sockFD = int(fd)
	})
	if err != nil {
		log.E("split-desync: %s => %s get sock fd failed; %v", laddr, raddr, err)
		return 0, err
	}

	fileFD, err := unix.MemfdCreate("haar", unix.O_RDWR)
	if err != nil {
		return 0, err
	}

	defer core.CloseFD(fileFD)

	err = unix.Ftruncate(fileFD, int64(len(s.payload)))
	if err != nil {
		return 0, err
	}
	firstSegment, err := unix.Mmap(fileFD, 0, len(s.payload), unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = unix.Munmap(firstSegment)
	}()

	// restrict TTL to ensure s.Payload is seen by censors, but not by the server.
	copy(firstSegment, s.payload)
	if s.ip6 {
		err = unix.SetsockoptInt(sockFD, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, s.ttl)
	} else {
		err = unix.SetsockoptInt(sockFD, unix.IPPROTO_IP, unix.IP_TTL, s.ttl)
	}
	if err != nil {
		log.E("split-desync: %s => %s setsockopt(ttl) err: %v", laddr, raddr, err)
		return 0, err
	}
	var offset int64 = 0
	n1, err := unix.Sendfile(sockFD, fileFD, &offset, len(s.payload))
	if err != nil {
		log.E("split-desync: %s => %s sendfile() %d err: %v", laddr, raddr, n1, err)
		return n1, err
	}

	// restore the first-half of the payload so that it gets picked up on retranmission.
	copy(firstSegment, b[:len(s.payload)])

	// restore to default TTL
	if s.ip6 {
		err = unix.SetsockoptInt(sockFD, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, default_ttl)
	} else {
		err = unix.SetsockoptInt(sockFD, unix.IPPROTO_IP, unix.IP_TTL, default_ttl)
	}
	if err != nil {
		log.E("split-desync: %s => %s setsockopt(ttl) err: %v", laddr, raddr, err)
		return n1, err
	}

	// write the second segment
	n2, err := conn.Write(b[len(s.payload):])
	logeif(err)("split-desync: write: n1: %d, n2: %d, err: %v", n1, n2, err)
	return n1 + n2, err
}

// ReadFrom reads from the reader and writes to s.
func (s *overwriteSplitter) ReadFrom(reader io.Reader) (bytes int64, err error) {
	if !s.used.Load() {
		bytes, err = copyOnce(s, reader)
		logeif(err)("split-desync: readfrom: copyOnce; sz: %d; err: %v", bytes, err)
		if err != nil {
			return
		}
	}

	b, err := s.conn.ReadFrom(reader)
	bytes += b
	log.V("split-desync: readfrom: done; sz: %d; err: %v", bytes, err)

	return
}