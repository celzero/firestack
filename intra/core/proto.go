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

// TCPConn abstracts a TCP connection coming from TUN. This connection
// should be handled by a registered TCP proxy handler.
type TCPConn interface {
	// RemoteAddr returns the destination network address.
	RemoteAddr() net.Addr
	// LocalAddr returns the local client network address.
	LocalAddr() net.Addr

	// confirms to protect.Conn
	Write([]byte) (int, error)
	Read([]byte) (int, error)

	Close() error
	// CloseWrite closes the writing side by sending a FIN
	// segment to local peer. That means we can write no further
	// data to TUN.
	CloseWrite() error
	// CloseRead closes the reading side. That means we can no longer
	// read more from TUN.
	CloseRead() error

	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// UDPConn abstracts a UDP connection coming from TUN. This connection
// should be handled by a registered UDP proxy handler.
type UDPConn interface {
	// LocalAddr returns the local client network address.
	LocalAddr() net.Addr
	RemoteAddr() net.Addr

	// confirms to protect.Conn
	Write([]byte) (int, error)
	Read([]byte) (int, error)

	// confirms to net.PacketConn
	WriteTo([]byte, net.Addr) (int, error)
	ReadFrom([]byte) (int, net.Addr, error)

	// Close closes the connection.
	Close() error

	// Implements net.Conn and net.PacketConn
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// DuplexConn represents a bidirectional stream socket.
type DuplexConn interface {
	TCPConn
	PoolableConn
	io.ReaderFrom
}

// so it can be pooled by ConnPool.
type PoolableConn syscall.Conn

type ICMPConn interface {
	net.PacketConn
}

// MinConn is a minimal connection interface that is
// a subset of both net.Conn and net.PacketConn.
type MinConn interface {
	LocalAddr() net.Addr
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	Close() error
}
