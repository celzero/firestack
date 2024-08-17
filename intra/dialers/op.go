// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dialers

import (
	"encoding/binary"
	"io"
	"math/rand"
	"net"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
)

// Copy one buffer from src to dst, using dst.Write.
func copyOnce(dst io.Writer, src io.Reader) (int64, error) {
	// A buffer large enough to hold any ordinary first write
	// without introducing extra splitting.
	bptr := core.Alloc()
	buf := *bptr
	buf = buf[:cap(buf)]
	defer func() {
		*bptr = buf
		core.Recycle(bptr)
	}()

	n, err := src.Read(buf) // src: netstack; downstream conn

	if err != nil {
		log.W("op: copyOnce: read %d/%d; err %v", n, len(buf), err)
		return 0, err
	}

	wn, err := dst.Write(buf[:n]) // dst: retrier; upstream conn

	logeif(err)("op: copyOnce: rw %d/%d; err %v", n, wn, err)
	return int64(n), err
}

func getTLSClientHelloRecordLen(h []byte) (uint16, bool) {
	if len(h) < 5 {
		return 0, false
	}

	const (
		TYPE_HANDSHAKE byte   = 22
		VERSION_TLS10  uint16 = 0x0301
		VERSION_TLS11  uint16 = 0x0302
		VERSION_TLS12  uint16 = 0x0303
		VERSION_TLS13  uint16 = 0x0304
	)

	if h[0] != TYPE_HANDSHAKE {
		return 0, false
	}

	ver := binary.BigEndian.Uint16(h[1:3])
	if ver != VERSION_TLS10 && ver != VERSION_TLS11 &&
		ver != VERSION_TLS12 && ver != VERSION_TLS13 {
		return 0, false
	}

	return binary.BigEndian.Uint16(h[3:5]), true
}

func writeTCPSplit(w net.Conn, hello []byte) (n int, err error) {
	var p, q int
	to := raddr(w)
	from := laddr(w)

	first, second := splitHello(hello)

	if p, err = w.Write(first); err != nil {
		log.E("op: splits: TCP1 %s (%d): err %v", to, len(first), err)
		return p, err
	} else if q, err = w.Write(second); err != nil {
		log.E("op: splits: TCP2 %s (%d): err %v", to, len(second), err)
		return p + q, err
	}
	log.D("op: splits: %s->%s; TCP: %d/%d,%d/%d", from, to, p, len(first), q, len(second))

	return p + q, nil
}

// upb-syssec.github.io/blog/2023/record-fragmentation/
// from: github.com/Jigsaw-Code/Intra/blob/27637e0ed497/Android/app/src/go/intra/split/retrier.go#L245
func writeTCPOrTLSSplit(w net.Conn, hello []byte) (n int, err error) {
	to := raddr(w)
	from := laddr(w)

	if len(hello) <= 1 {
		n, err = w.Write(hello)
		log.D("op: splits: %s->%s; len(hello) <= 1; n: %d; err: %v", from, to, n, err)
		return
	}

	const (
		MIN_SPLIT int = 6
		MAX_SPLIT int = 64
	)

	// random number in the range [MIN_SPLIT, MAX_SPLIT]
	// splitLen includes 5 bytes of TLS header
	splitLen := MIN_SPLIT + rand.Intn(MAX_SPLIT+1-MIN_SPLIT)
	limit := len(hello) / 2
	if splitLen > limit {
		splitLen = limit
	}

	recordLen, ok := getTLSClientHelloRecordLen(hello)
	recordSplit1Len := splitLen - 5
	recordSplit2Len := recordLen - uint16(recordSplit1Len)
	if !ok || recordSplit1Len <= 0 || recordSplit1Len >= int(recordLen) {
		// TCP split if hello is not a valid TLS Client Hello, or cannot be fragmented
		return writeTCPSplit(w, hello)
	}

	bptr := core.AllocRegion(len(hello))
	parcel := *bptr
	parcel = parcel[:cap(parcel)]
	defer func() {
		*bptr = parcel
		core.Recycle(bptr)
	}()
	// TLS record layout:
	//	+-------------+ 0
	//	| RecordType  |
	//	+-------------+ 1
	//	|  Protocol   |
	//	|  Version    |
	//	+-------------+ 3
	//	|   Record    |
	//	|   Length    |
	//	+-------------+ 5
	//	|   Message   |
	//	|    Data     |
	//	+-------------+ Message Length + 5
	//
	//	RecordType := invalid(0) | handshake(22) | application_data(23) | ...
	//	LegacyRecordVersion := 0x0301 ("TLS 1.0") | 0x0302 ("TLS 1.1") | 0x0303 ("TLS 1.2")
	//	0 < Message Length (of handshake)        ≤ 2^14
	//	0 ≤ Message Length (of application_data) ≤ 2^14
	//
	// datatracker.ietf.org/doc/html/rfc8446#section-5.1
	// see: github.com/Jigsaw-Code/outline-sdk/blob/19f51846/transport/tlsfrag/tls.go#L24

	// do not modify hello in-place as it "updates" the underlying buffer
	// (go.dev/play/p/CffJ3XziU5u) which breaks the io.Writer.Write contract.

	// 1. copy the split which includes the record header
	// 2. write len(message data) of this split from [3:5]
	p := copy(parcel, hello[:splitLen])
	binary.BigEndian.PutUint16(parcel[3:5], uint16(recordSplit1Len))
	n, err = w.Write(parcel[:p])
	if err != nil {
		log.E("op: Splits: %s->%s; TLS1 %d/%d; n: %d; err: %v", from, to, splitLen, len(hello), n, err)
		return
	}

	// 3. copy the rest of the message data + trailing space for the 5 byte record header
	// 4. write the original record header from [0:5]
	// 5. write len(message data) of this split from [3:5]
	q := copy(parcel, hello[splitLen-5:])
	aux := copy(parcel, hello[:5]) // repeated
	binary.BigEndian.PutUint16(parcel[3:5], recordSplit2Len)
	m, err := w.Write(parcel[:q])
	// discount repeated 5-byte header from total bytes
	n += max(m-aux, 0)

	logeif(err)("op: splits: %s->%s; TLS2 %d/%d; n: %d, m: %d; err: %v",
		from, to, splitLen, len(hello), n, m, err)
	// if n > len(hello); return len(hello) to avoid confusion with the callers
	// that expect bytes written to be equal to the length of the input buffer.
	// splits: [:f29]:55476->[:f5e]:443; TLS2 51/2048; n: 2053; err: <nil>
	// F c.upload: [11] runtime error: slice bounds out of range [:2053] with capacity 2048
	// from: dialers.(*retrier).sendCopyHello
	return min(n, len(hello)), err
}

// splitHello splits the TLS client hello message into two.
func splitHello(hello []byte) ([]byte, []byte) {
	if len(hello) == 0 {
		return hello, hello
	}
	const (
		min int = 32
		max int = 64
	)

	// Random number in the range [MIN_SPLIT, MAX_SPLIT]
	s := min + rand.Intn(max+1-min)
	limit := len(hello) / 2
	if s > limit {
		s = limit
	}
	return hello[:s], hello[s:]
}

// laddr returns the local address of the connection.
func laddr(c net.Conn) net.Addr {
	if c != nil && core.IsNotNil(c) {
		return c.LocalAddr()
	}
	return zeroNetAddr{}
}

func raddr(c net.Conn) net.Addr {
	if c != nil && core.IsNotNil(c) {
		return c.RemoteAddr()
	}
	return zeroNetAddr{}
}

func logeif(e error) log.LogFn {
	if e != nil {
		return log.E
	} else {
		return log.D
	}
}

func logeor(e error, d log.LogFn) log.LogFn {
	if e != nil {
		return log.E
	}
	return d
}
