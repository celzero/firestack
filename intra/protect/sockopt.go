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
)

// shorter count / interval for faster drops
const (
	defaultIdle     = 180 // in seconds
	defaultCount    = 4   // unacknowledged probes
	defaultInterval = 5   // in seconds
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
	if settings.GetDialerOpts().LowerKeepAlive {
		if tc, ok := c.(*net.TCPConn); ok {
			return tc.SetKeepAliveConfig(kacfg) == nil
		}
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
		})
		if err != nil {
			log.E("RawConn.Control() failed: %v", err)
			ok = false
		}
		return ok
	}
	return false
}
