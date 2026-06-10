// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"net"
	"syscall"

	"github.com/celzero/firestack/intra/log"
	"golang.org/x/sys/unix"
)

// github.com/tailscale/tailscale/blob/65fe0ba7b5/cmd/derper/derper.go#L75-L78
// blog.cloudflare.com/when-tcp-sockets-refuse-to-die/
// shorter count / interval for faster drops
const (
	defaultIdle     = 600 // in seconds
	defaultCount    = 4   // unacknowledged probes
	defaultInterval = 5   // in seconds
	// usrTimeoutMillis = 1000*defaultIdle + (defaultInterval * defaultCount)
)

var (
	kacfg = net.KeepAliveConfig{
		Enable:   true,
		Idle:     defaultIdle,
		Count:    defaultCount,
		Interval: defaultInterval,
	}
)

func SetKeepAliveConfig(c MinConn) bool {
	if tc, ok := c.(*net.TCPConn); ok {
		return tc.SetKeepAliveConfig(kacfg) == nil
	}
	return false
}

func SetTimeoutSockOpt(c MinConn, timeoutms int) bool {
	if tc, ok := c.(PoolableConn); ok {
		id := conn2str(c)
		rawConn, err := tc.SyscallConn()
		if err != nil || rawConn == nil {
			return false
		}
		ok := true
		err = rawConn.Control(func(fd uintptr) {
			sock := int(fd)
			// code.googlesource.com/google-api-go-client/+/master/transport/grpc/dial_socketopt.go#30
			if err := unix.SetsockoptInt(sock, unix.SOL_TCP, unix.TCP_USER_TIMEOUT, timeoutms); err != nil {
				log.D("core: sockopt: set TCP_USER_TIMEOUT %s (%d) failed: %dms, %v", id, sock, timeoutms, err)
				ok = false
			}
		})
		if err != nil {
			log.E("core: sockopt: %s RawConn.Control() err: %v", id, err)
			ok = false
		}
		return ok
	}
	return false
}

func DisableKeepAlive(c MinConn) (done bool) {
	if sc, ok := c.(PoolableConn); ok {
		raw, err := sc.SyscallConn()
		if raw == nil || err != nil {
			return
		}
		err = raw.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 0)
		})
		return err == nil
	}
	return
}

// SetKeepAliveConfigSockOpt sets for a TCP connection, SO_KEEPALIVE,
// TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT, TCP_USER_TIMEOUT.
// args is optional, and should be in the order of idle, interval, count.
func SetKeepAliveConfigSockOpt(c MinConn, args ...int) (ok bool) {
	switch pc := c.(type) {
	case *net.UDPConn:
		return
	case PoolableConn:
		id := conn2str(c)

		rawConn, err := pc.SyscallConn()
		if err != nil || rawConn == nil {
			ok = false
			return ok
		}

		idle := defaultIdle         // secs
		interval := defaultInterval // secs
		count := defaultCount
		if len(args) >= 1 && args[0] > 0 {
			idle = args[0]
		}
		if len(args) >= 2 && args[1] > 0 {
			interval = args[1]
		}
		if len(args) >= 3 && args[2] > 0 {
			count = args[2]
		}
		usertimeoutms := idle*1000 + (interval * count) // millis

		ok = true
		err = rawConn.Control(func(fd uintptr) {
			sock := int(fd)
			if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, boolint(true)); err != nil {
				log.V("core: sockopt: set SO_KEEPALIVE %s (%d) failed: %v", id, sock, err)
				ok = false
			}
			if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE, idle); err != nil {
				log.V("core: sockopt: set TCP_KEEPIDLE %s (%d) failed: %ds, %v", id, sock, idle, err)
				ok = false
			}
			if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, interval); err != nil {
				log.V("core: sockopt: set TCP_KEEPINTVL %s (%d) failed: %ds, %v", id, sock, interval, err)
				ok = false
			}
			if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, count); err != nil {
				log.V("core: sockopt: set TCP_KEEPCNT %s (%d) failed: #%d, %v", id, sock, count, err)
				ok = false
			}
			// code.googlesource.com/google-api-go-client/+/master/transport/grpc/dial_socketopt.go#30
			if err := unix.SetsockoptInt(sock, unix.SOL_TCP, unix.TCP_USER_TIMEOUT, usertimeoutms); err != nil {
				log.V("core: sockopt: set TCP_USER_TIMEOUT %s (%d) failed: %dms, %v", id, sock, usertimeoutms, err)
				ok = false
			}
		})
		if err != nil {
			log.E("core: sockopt: %s RawConn.Control() err: %v", id, err)
			ok = false
		}
	}
	return ok
}

var (
	MinMtu6 = 1280
	MinMtu4 = 576
)

func ChangeBufferSizes(c MinConn, rsz, wsz int) (n int, err error) {
	// min socket buffer size is at least 4kib
	if rsz < MinMtu6*4 || wsz < MinMtu6*4 {
		return -1, errBufferSmall
	}
	switch x := c.(type) {
	case *net.TCPConn:
		rerr := x.SetReadBuffer(rsz)
		werr := x.SetWriteBuffer(wsz)
		return rsz, JoinErr(rerr, werr)
	case *net.UDPConn:
		rerr := x.SetReadBuffer(rsz)
		werr := x.SetWriteBuffer(wsz)
		return rsz, JoinErr(rerr, werr)
	}
	return -2, errNotTcpNotUdp
}

func ChangeBufferSizesSockOpt(c MinConn, rsz, wsz int) (n int, err error) {
	// min socket buffer size is at least 4kib
	if rsz < MinMtu6*4 || wsz < MinMtu6*4 {
		return -1, errBufferSmall
	}
	cs, ok := c.(ControlConn)
	if !ok {
		return -2, errNotSyscallConn
	}
	s, err := cs.SyscallConn()
	if err != nil || s == nil {
		return -3, OneErr(err, errNotSyscallConn)
	}
	var oerr1, oerr2 error
	err = s.Control(func(fd uintptr) {
		sock := int(fd)
		if oerr1 = syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_RCVBUF, rsz); oerr1 != nil {
			log.V("core: sockopt: set SO_RCVBUF %d failed: %v", sock, oerr1)
		}
		if oerr2 = syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_SNDBUF, wsz); oerr2 != nil {
			log.V("core: sockopt: set SO_SNDBUF %d failed: %v", sock, oerr2)
		}
	})
	return rsz, JoinErr(err, oerr1, oerr2)
}

func boolint(b bool) int {
	if b {
		return 1
	}
	return 0
}
