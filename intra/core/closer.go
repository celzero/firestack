// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"io"
	"net"
	"reflect"
)

// CloseUDP closes cs.
func CloseUDP(cs ...*net.UDPConn) {
	for _, c := range cs {
		if c != nil {
			_ = c.Close()
		}
	}
}

// CloseTCP closes cs.
func CloseTCP(cs ...*net.TCPConn) {
	for _, c := range cs {
		if c != nil {
			_ = c.Close()
		}
	}
}

// CloseTCPRead closes the read end of r.
func CloseTCPRead(r TCPConn) {
	if r != nil && IsNotNil(r) {
		_ = r.CloseRead()
	}
}

// CloseTCPWrite closes the write end of w.
func CloseTCPWrite(w TCPConn) {
	if w != nil && IsNotNil(w) {
		_ = w.CloseWrite()
	}
}

// CloseConn closes c.
func CloseConn(c net.Conn) {
	Close(c) // ok even if c is nil; go.dev/play/p/3hL0DUL6_kJ
}

// Close closes cs.
func Close(cs ...io.Closer) {
	for _, c := range cs {
		if c != nil && !IsNil(c) {
			_ = c.Close()
		}
	}
}

// CloseOp closes op on c.
// op can be "r", "w", or "rw" (default).
// net.TCPConn confirms to core.TCPConn
func CloseOp(c io.Closer, op string) {
	if c == nil {
		return
	}
	if op == "rw" {
		Close(c)
		return
	}
	switch x := c.(type) {
	case TCPConn:
		if op == "r" {
			CloseTCPRead(x)
		} else if op == "w" {
			CloseTCPWrite(x)
		} else { // == "rw"
			CloseConn(x)
		}
	case UDPConn:
		CloseConn(x)
	case io.Closer:
		Close(x)
	}
}

func IsNotNil(x any) bool {
	return !IsNil(x)
}

// IsNil reports whether x is nil if its Chan, Func, Map,
// Pointer, UnsafePointer, Interface, and Slice;
// may panic if x is not addressable
func IsNil(x any) bool {
	// from: stackoverflow.com/a/76595928
	if x == nil {
		return true
	}
	v := reflect.ValueOf(x)
	k := v.Kind()
	switch k {
	case reflect.Pointer, reflect.UnsafePointer, reflect.Interface, reflect.Chan, reflect.Func, reflect.Map, reflect.Slice:
		return v.IsNil()
	}
	return false
}
