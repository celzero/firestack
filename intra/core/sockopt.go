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
	defaultIdle      = 600 // in seconds
	defaultCount     = 4   // unacknowledged probes
	defaultInterval  = 5   // in seconds
	usrTimeoutMillis = 1000*defaultIdle + (defaultInterval * defaultCount)
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

// SetKeepAliveConfigSockOpt sets for a TCP connection, SO_KEEPALIVE,
// TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT, TCP_USER_TIMEOUT.
// args is optional, and should be in the order of idle, interval, count.
func SetKeepAliveConfigSockOpt(c MinConn, args ...int) (ok bool) {
	var tc *net.TCPConn
	if tc, ok = c.(*net.TCPConn); ok {
		id := conn2str(tc)

		rawConn, err := tc.SyscallConn()
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
				log.D("set SO_KEEPALIVE %s failed: %v", id, err)
				ok = false
			}
			if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE, idle); err != nil {
				log.D("set TCP_KEEPIDLE %s failed: %ds, %v", id, idle, err)
				ok = false
			}
			if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, interval); err != nil {
				log.D("set TCP_KEEPINTVL %s failed: %ds, %v", id, interval, err)
				ok = false
			}
			if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, count); err != nil {
				log.D("set TCP_KEEPCNT %s failed: #%d, %v", id, count, err)
				ok = false
			}
			// code.googlesource.com/google-api-go-client/+/master/transport/grpc/dial_socketopt.go#30
			if err := unix.SetsockoptInt(sock, unix.SOL_TCP, unix.TCP_USER_TIMEOUT, usertimeoutms); err != nil {
				log.D("set TCP_USER_TIMEOUT %s failed: %dms, %v", id, usertimeoutms, err)
				ok = false
			}
		})
		if err != nil {
			log.E("dialers: sockopt: %s RawConn.Control() err: %v", id, err)
			ok = false
		}
	}
	return ok
}

func boolint(b bool) int {
	if b {
		return 1
	}
	return 0
}
