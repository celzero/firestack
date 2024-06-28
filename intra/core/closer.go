// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"io"
	"net"
	"os"
	"reflect"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

type CloserOp int

const (
	CopR CloserOp = iota
	CopW
	CopRW
	CopAny
)

func CloseFile(f *os.File) {
	if f != nil {
		_ = f.Close()
	}
}

// CloseUDP closes c.
func CloseUDP(c *net.UDPConn) {
	if c != nil {
		_ = c.Close()
	}
}

// CloseTCP closes c.
func CloseTCP(c *net.TCPConn) {
	if c != nil {
		_ = c.Close()
	}
}

// CloseTCPRead closes the read end of r.
func CloseTCPRead(r TCPConn) {
	if r != nil {
		// avoid expensive reflection:
		// groups.google.com/g/golang-nuts/c/wnH302gBa4I
		switch x := r.(type) {
		case *net.TCPConn:
			if x != nil {
				_ = x.CloseRead()
			}
		case *gonet.TCPConn:
			if x != nil {
				_ = x.CloseRead()
			}
		default:
			if IsNotNil(r) {
				_ = r.CloseRead()
			}
		}
	}
}

// CloseTCPWrite closes the write end of w.
func CloseTCPWrite(w TCPConn) {
	if w != nil {
		switch x := w.(type) {
		case *net.TCPConn:
			if x != nil {
				_ = x.CloseWrite()
			}
		case *gonet.TCPConn:
			if x != nil {
				_ = x.CloseWrite()
			}
		default:
			if IsNotNil(w) {
				_ = w.CloseWrite()
			}
		}
	}
}

// CloseConn closes cs.
func CloseConn(cs ...net.Conn) {
	for _, c := range cs {
		if c == nil {
			continue
		}
		switch x := c.(type) {
		case *net.TCPConn:
			if x != nil {
				_ = x.Close()
			}
		case *net.UDPConn:
			if x != nil {
				_ = x.Close()
			}
		case *gonet.TCPConn:
			if x != nil {
				_ = x.Close()
			}
		case *gonet.UDPConn:
			if x != nil {
				_ = x.Close()
			}
		default:
			if IsNotNil(c) {
				_ = c.Close()
			}
		}
	}
}

// Close closes cs.
func Close(cs ...io.Closer) {
	for _, c := range cs {
		CloseOp(c, CopAny)
	}
}

// CloseOp closes op on c.
func CloseOp(c io.Closer, op CloserOp) {
	if c == nil {
		return
	}
	switch x := c.(type) {
	case TCPConn:
		if op == CopR {
			CloseTCPRead(x)
		} else if op == CopW {
			CloseTCPWrite(x)
		} else { // == "rw"
			CloseConn(x)
		}
	case *net.UDPConn:
		CloseUDP(x)
	case UDPConn:
		CloseConn(x)
	case *net.TCPListener:
		if x != nil {
			_ = x.Close()
		}
	case *io.PipeReader:
		if x != nil {
			_ = x.Close()
		}
	case *io.PipeWriter:
		if x != nil {
			_ = x.Close()
		}
	case *os.File:
		CloseFile(x)
	case io.Closer: // ex: net.PacketConn
		if IsNotNil(c) {
			_ = c.Close()
		}
	}
}

// may panic or return false if x is not addressable
func IsNotNil(x any) bool {
	return !IsNil(x)
}

// IsNil reports whether x is nil if its Chan, Func, Map,
// Pointer, UnsafePointer, Interface, and Slice;
// may panic or return false if x is not addressable
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

func TypeEq(a, b any) bool {
	return reflect.TypeOf(a) == reflect.TypeOf(b)
}
