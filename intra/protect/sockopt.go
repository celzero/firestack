// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package protect

import (
	"net"
	"syscall"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
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

func SetKeepAliveConfig(c Conn) bool {
	if !settings.GetDialerOpts().LowerKeepAlive {
		return false
	}

	if tc, ok := c.(*net.TCPConn); ok {
		return tc.SetKeepAliveConfig(kacfg) == nil
	}
	return false
}

func SetKeepAliveConfigSockOpt(c Conn) bool {
	if !settings.GetDialerOpts().LowerKeepAlive {
		return false
	}

	if tc, ok := c.(*net.TCPConn); ok {
		rawConn, err := tc.SyscallConn()
		if err != nil || rawConn == nil {
			ok = false
			return ok
		}
		err = rawConn.Control(func(fd uintptr) {
			sock := int(fd)
			if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, boolint(true)); err != nil {
				log.D("set SO_KEEPALIVE failed: %v", err)
				ok = false
			}
			if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE, defaultIdle); err != nil {
				log.D("set TCP_KEEPIDLE failed: %v", err)
				ok = false
			}
			if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, defaultInterval); err != nil {
				log.D("set TCP_KEEPINTVL failed: %v", err)
				ok = false
			}
			if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, defaultCount); err != nil {
				log.D("set TCP_KEEPCNT failed: %v", err)
				ok = false
			}
			// code.googlesource.com/google-api-go-client/+/master/transport/grpc/dial_socketopt.go#30
			if err := unix.SetsockoptInt(sock, unix.SOL_TCP, unix.TCP_USER_TIMEOUT, usrTimeoutMillis); err != nil {
				log.D("set TCP_USER_TIMEOUT failed: %v", err)
				ok = false
			}
		})
		if err != nil {
			log.E("RawConn.Control() failed: %v", err)
			ok = false
		}
		return ok
	}
	return false
}

func boolint(b bool) int {
	if b {
		return 1
	}
	return 0
}
