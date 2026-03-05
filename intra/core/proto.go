// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"io"
	"net"
	"syscall"
	"time"
)

// from: github.com/eycorsican/go-tun2socks/blob/301549c435/core/conn.go#LL3C9-L3C9

// ref: cs.android.com/android/platform/superproject/+/android-latest-release:system/core/libcutils/include/private/android_filesystem_config.h;drc=e999f05f34e91a3a313ba7dd77bcf52b58a0841e
const (
	UNKNOWN_UID         = -1
	UNKNOWN_UID_STR     = "-1"
	ANDROID_UID_STR     = "0"
	DNS_UID_STR         = "1051"
	UNSUPPORTED_NETWORK = -1
)

// TCPConn abstracts a TCP connection coming from TUN. This connection
// should be handled by a registered TCP proxy handler.
type TCPConn interface {
	DuplexCloser

	// RemoteAddr returns the destination network address.
	RemoteAddr() net.Addr
	// LocalAddr returns the local client network address.
	LocalAddr() net.Addr

	// confirms to protect.Conn
	Write([]byte) (int, error)
	Read([]byte) (int, error)

	// Implements MinConn and net.Conn
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// UDPConn abstracts a UDP connection coming from TUN. This connection
// should be handled by a registered UDP proxy handler.
type UDPConn interface {
	io.Closer

	// LocalAddr returns the local client network address.
	LocalAddr() net.Addr
	// RemoteAddr returns the destination network address.
	RemoteAddr() net.Addr

	// confirms to protect.Conn
	Write([]byte) (int, error)
	Read([]byte) (int, error)

	// confirms to net.PacketConn
	WriteTo([]byte, net.Addr) (int, error)
	ReadFrom([]byte) (int, net.Addr, error)

	// Implements MinConn, net.Conn, and net.PacketConn
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

type DuplexCloser interface {
	io.Closer
	CloseRead() error
	CloseWrite() error
}

// DuplexConn represents a bidirectional stream socket.
type DuplexConn interface {
	TCPConn
	DuplexCloser
	PoolableConn
	KeepAliveConn
}

// so it can be used by dialers/retrier.go
type ReadRetrierConn io.ReaderFrom

type WriteRetrierConn io.WriterTo

type RetrierConn interface {
	ReadRetrierConn
	WriteRetrierConn
}

// so it can be pooled by ConnPool.
type PoolableConn syscall.Conn
type ControlConn = PoolableConn

// KeepAliveConn supports keep-alive probes.
type KeepAliveConn interface {
	SetKeepAlive(bool) error
}

type ICMPConn interface {
	ControlConn // see: ping.go:setttl
	net.PacketConn
}

// MinConn is a minimal connection interface that is
// a subset of both net.Conn and net.PacketConn.
type MinConn interface {
	io.Closer

	LocalAddr() net.Addr

	// Doc copied from net.Conn:
	// SetDeadline sets the read and write deadlines associated
	// with the connection. It is equivalent to calling both
	// SetReadDeadline and SetWriteDeadline.
	//
	// A deadline is an absolute time after which I/O operations
	// fail instead of blocking. The deadline applies to all future
	// and pending I/O, not just the immediately following call to
	// Read or Write. After a deadline has been exceeded, the
	// connection can be refreshed by setting a deadline in the future.
	//
	// If the deadline is exceeded a call to Read or Write or to other
	// I/O methods will return an error that wraps os.ErrDeadlineExceeded.
	// This can be tested using errors.Is(err, os.ErrDeadlineExceeded).
	// The error's Timeout method will return true, but note that there
	// are other possible errors for which the Timeout method will
	// return true even if the deadline has not been exceeded.
	//
	// An idle timeout can be implemented by repeatedly extending
	// the deadline after successful Read or Write calls.
	//
	// A zero value for t means I/O operations will not time out.
	SetDeadline(t time.Time) error

	// Doc copied from net.Conn:
	// SetReadDeadline sets the deadline for future Read calls
	// and any currently-blocked Read call.
	// A zero value for t means Read will not time out.
	SetReadDeadline(t time.Time) error

	// Doc copied from net.Conn:
	// SetWriteDeadline sets the deadline for future Write calls
	// and any currently-blocked Write call.
	// Even if write times out, it may return n > 0, indicating that
	// some of the data was successfully written.
	// A zero value for t means Write will not time out.
	SetWriteDeadline(t time.Time) error
}
