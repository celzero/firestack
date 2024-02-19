// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"net"
	"time"
)

// from: github.com/eycorsican/go-tun2socks/blob/301549c435/core/conn.go#LL3C9-L3C9

// TCPConn abstracts a TCP connection comming from TUN. This connection
// should be handled by a registered TCP proxy handler.
type TCPConn interface {
	// RemoteAddr returns the destination network address.
	RemoteAddr() net.Addr

	// LocalAddr returns the local client network address.
	LocalAddr() net.Addr

	// confirms to protect.Conn
	Write(data []byte) (int, error)
	Read(data []byte) (int, error)
	Close() error

	// CloseWrite closes the writing side by sending a FIN
	// segment to local peer. That means we can write no further
	// data to TUN.
	CloseWrite() error

	// CloseRead closes the reading side. That means we can no longer
	// read more from TUN.
	CloseRead() error

	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// UDPConn abstracts a UDP connection comming from TUN. This connection
// should be handled by a registered UDP proxy handler.
type UDPConn interface {
	// LocalAddr returns the local client network address.
	LocalAddr() net.Addr
	RemoteAddr() net.Addr

	// confirms to protect.Conn
	Write(data []byte) (int, error)
	Read(data []byte) (int, error)

	// confirms to net.PacketConn
	WriteTo(data []byte, addr net.Addr) (int, error)
	ReadFrom(data []byte) (int, net.Addr, error)

	// Close closes the connection.
	Close() error

	// Implements net.Conn
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}
