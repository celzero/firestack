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
	"github.com/celzero/firestack/intra/settings"

	"github.com/celzero/firestack/intra/log"
)

func init() {
	// Conserve memory by increasing garbage collection frequency.
	debug.SetGCPercent(10)
	log.SetLevel(log.WARN)
}

// Connect reads packets from a TUN device.
// `fd` is the TUN device.  The IntraTunnel acquires an additional reference to it, which
//
//	is released by Disconnect(), so the caller must close `fd` _and_ call
//	Disconnect() in order to close the TUN device.
//
// `mtu` is the MTU of the TUN device.
// `engine` IP protocols to route: one of settings.Ns4, settings.Ns6, settings.Ns46.
// `fakedns` are the DNS servers that the system believes it is using, in "host:port" style.
//
// `bdg` is a kotlin object that implements the Bridge interface.
//
// Throws an exception if the TUN file descriptor cannot be opened, or if the tunnel fails to
// connect.
func Connect(fd, mtu, engine int, fakedns string, dns dnsx.Transport, bdg intra.Bridge) (t intra.Tunnel, err error) {
	tunmode := settings.DefaultTunMode()
	tunmode.IpMode = engine
	return intra.NewTunnel(fd, mtu, fakedns, dns, tunmode, bdg)
}

func LogLevel(level int) {
	dbg := false
	dlvl := log.WARN
	switch l := log.LogLevel(level); l {
	case log.VERBOSE:
		dlvl = log.VERBOSE
		dbg = true
	case log.DEBUG:
		dlvl = log.DEBUG
		dbg = true
	case log.INFO:
		dlvl = log.INFO
	case log.WARN:
		dlvl = log.WARN
	case log.ERROR:
		dlvl = log.ERROR
	default:
		log.W("tun: unknown log-level(%d), using warn", l)
	}
	log.SetLevel(dlvl)
	settings.Debug = dbg
}
