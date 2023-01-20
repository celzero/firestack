// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     Copyright 2019 The Outline Authors
//
//     Licensed under the Apache License, Version 2.0 (the "License");
//     you may not use this file except in compliance with the License.
//     You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
//     Unless required by applicable law or agreed to in writing, software
//     distributed under the License is distributed on an "AS IS" BASIS,
//     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//     See the License for the specific language governing permissions and
//     limitations under the License.

package tun2socks

import (
	"runtime/debug"

	"github.com/celzero/firestack/intra"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/tunnel"

	"github.com/celzero/firestack/intra/log"
)

var engine int = settings.Ns46

func init() {
	// Conserve memory by increasing garbage collection frequency.
	debug.SetGCPercent(10)
	log.SetLevel(log.WARN)
}

// ConnectIntraTunnel reads packets from a TUN device and applies the Intra routing
// rules.  Currently, this only consists of redirecting DNS packets to a specified
// server; all other data flows directly to its destination.
//
// `fd` is the TUN device.  The IntraTunnel acquires an additional reference to it, which
//  is released by IntraTunnel.Disconnect(), so the caller must close `fd` _and_ call
//  Disconnect() in order to close the TUN device.
// `fakedns` is the DNS server that the system believes it is using, in "host:port" style.
//  The port is normally 53.
// `dohdns` is the initial DoH transport.  It must not be `nil`.
// `protector` is a wrapper for Android's VpnService.protect() method.
// `blocker` implements firewall rules.
// `listener` will be provided with a summary of each TCP and UDP socket when it is closed.
//
// Throws an exception if the TUN file descriptor cannot be opened, or if the tunnel fails to
// connect.
func ConnectIntraTunnel(fd int, mtu int, fakedns string, dohdns dnsx.Transport, blocker protect.Blocker, listener intra.Listener) (t intra.Tunnel, err error) {
	l3 := settings.L3(engine)

	dupfd, err := tunnel.Dup(fd)
	if err != nil {
		return nil, err
	}
	return intra.NewGTunnel(fakedns, dohdns, dupfd, l3, mtu, blocker, listener)
}

func EnableDebugLog() {
	log.SetLevel(log.DEBUG)
}

func PreferredEngine(w int) {
	switch w {
	case settings.Ns4:
	case settings.Ns6:
	case settings.Ns46:
	default:
		log.Warnf("tun2socks: engine(%d) unknown, using default", w)
		w = settings.Ns46
	}
	engine = w
}
