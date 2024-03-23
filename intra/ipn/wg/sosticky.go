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

import "net/netip"

// "sticky socks" disabled on Android: github.com/WireGuard/wireguard-go/commit/3a9e75374f

func (e *StdNetEndpoint2) SrcIP() netip.Addr {
	return netip.Addr{}
}

func (e *StdNetEndpoint2) SrcIfidx() int32 {
	return 0
}

func (e *StdNetEndpoint2) SrcToString() string {
	return ""
}

// getSrcFromControl parses the control for PKTINFO and if found updates ep with
// the source information found.
func getSrcFromControl(control []byte, ep *StdNetEndpoint2) {
}

// setSrcControl parses the control for PKTINFO and if found updates ep with
// the source information found.
func setSrcControl(control *[]byte, ep *StdNetEndpoint2) {
}

// stickyControlSize returns the recommended buffer size for pooling sticky
// offloading control data; for linux: stickyControlSize = unix.CmsgSpace(unix.SizeofInet6Pktinfo)
const stickyControlSize = 0

// no netlink on Androids: github.com/WireGuard/wireguard-go/blob/12269c2761/device/sticky_linux.go#L28
// for linux: StdNetSupportsStickySockets = true
const StdNetSupportsStickySockets = false
