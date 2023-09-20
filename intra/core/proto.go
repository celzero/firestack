// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"io"
	"net"
	"time"
)

// from: github.com/eycorsican/go-tun2socks/blob/301549c435/core/conn.go#LL3C9-L3C9

// Adapter to keep gomobile happy as it can't export net.Conn
type Conn interface {
	io.ReadWriteCloser
}

// TCPConn abstracts a TCP connection comming from TUN. This connection
// should be handled by a registered TCP proxy handler.
type TCPConn interface {
	Conn
	// RemoteAddr returns the destination network address.
	RemoteAddr() net.Addr

	// LocalAddr returns the local client network address.
	LocalAddr() net.Addr

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

// TCPConn abstracts a UDP connection comming from TUN. This connection
// should be handled by a registered UDP proxy handler.
type UDPConn interface {
	Conn
	// LocalAddr returns the local client network address.
	LocalAddr() *net.UDPAddr
	RemoteAddr() *net.UDPAddr

	// Wait for the underlying connection to be ready.
	Ready() bool

	// ReceiveTo will be called when data arrives from remote, and the received
	// data should be sent to addr.
	ReceiveTo(data []byte, addr *net.UDPAddr) error

	// WriteFrom writes data to remote, addr will be set as source address.
	WriteFrom(data []byte, addr *net.UDPAddr) (int, error)

	// Close closes the connection.
	Close() error
}
