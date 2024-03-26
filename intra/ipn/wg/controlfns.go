// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     SPDX-License-Identifier: MIT
//
//     Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.

package wg

import (
	"fmt"
	"runtime"
	"syscall"

	"github.com/celzero/firestack/intra/protect"
	"golang.org/x/sys/unix"
)

// from: github.com/WireGuard/wireguard-go/blob/12269c276/conn/controlfns.go

// UDP socket read/write buffer size (7MB). The value of 7MB is chosen as it is
// the max supported by a default configuration of macOS. Some platforms will
// silently clamp the value to other maximums, such as linux clamping to
// net.core.{r,w}mem_max (see _linux.go for additional implementation that works
// around this limitation)
const socketBufferSize = 7 << 20

// controlFns is a list of functions that are called from the listen config
// that can apply socket options.
var controlFns = []protect.ControlFn{}

// A net.ListenConfig (protect.MakeNsListenConfigExt) must apply the controlFns
// to the socket prior to bind. This is used to apply socket buffer sizing and
// packet information OOB configuration for sticky sockets.
// from: github.com/WireGuard/wireguard-go/blob/12269c276/conn/controlfns_linux.go
func init() {
	controlFns = append(controlFns,
		// Attempt to set the socket buffer size beyond net.core.{r,w}mem_max by
		// using SO_*BUFFORCE. This requires CAP_NET_ADMIN, and is allowed here to
		// fail silently - the result of failure is lower performance on very fast
		// links or high latency links.
		func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Set up to *mem_max
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, socketBufferSize)
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, socketBufferSize)
				// Set beyond *mem_max if CAP_NET_ADMIN
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, socketBufferSize)
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, socketBufferSize)
			})
		},

		// Enable receiving of the packet information (IP_PKTINFO for IPv4,
		// IPV6_PKTINFO for IPv6) that is used to implement sticky socket support.
		func(network, address string, c syscall.RawConn) error {
			var err error
			switch network {
			case "udp4":
				if runtime.GOOS != "android" {
					c.Control(func(fd uintptr) {
						err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
					})
				}
			case "udp6":
				c.Control(func(fd uintptr) {
					if runtime.GOOS != "android" {
						err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
						if err != nil {
							return
						}
					}
					err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1)
				})
			default:
				err = fmt.Errorf("unhandled network: %s: %w", network, unix.EINVAL)
			}
			return err
		},

		// Attempt to enable UDP_GRO
		func(network, address string, c syscall.RawConn) error {
			c.Control(func(fd uintptr) {
				_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
			})
			return nil
		},
	)
}
