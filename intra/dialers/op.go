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
		log.E("op: retryLocked: TCP split1 %s (%d): err %v", to, len(first), err)
		return p, err
	} else if q, err = w.Write(second); err != nil {
		log.E("op: retryLocked: TCP split2 %s (%d): err %v", to, len(second), err)
		return p + q, err
	}
	log.D("op: retryLocked: %s->%s; TCP splits: %d,%d", from, to, len(first), len(second))

	return p + q, nil
}

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
	recordSplitLen := splitLen - 5
	if !ok || recordSplitLen <= 0 || recordSplitLen >= int(recordLen) {
		// TCP split if hello is not a valid TLS Client Hello, or cannot be fragmented
		n, err = w.Write(hello[:splitLen])
		if err == nil {
			var m int
			m, err = w.Write(hello[splitLen:])
			n += m
		}
		log.D("op: splits: %s->%s; TCP %d/%d; n: %d; err: %v", from, to, splitLen, len(hello), n, err)
		return
	}

	parcel := hello[:splitLen]
	binary.BigEndian.PutUint16(parcel[3:5], uint16(recordSplitLen))
	if n, err = w.Write(parcel); err != nil {
		log.E("op: Splits: %s->%s; TLS1 %d/%d; n: %d; err: %v", from, to, splitLen, len(hello), n, err)
		return
	}

	parcel = hello[splitLen-5:]
	copy(parcel, hello[:5])
	binary.BigEndian.PutUint16(parcel[3:5], recordLen-uint16(recordSplitLen))

	m, err := w.Write(parcel)
	n += m

	logeif(err)("op: splits: %s->%s; TLS2 %d/%d; n: %d; err: %v", from, to, splitLen, len(hello), n, err)
	return
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
