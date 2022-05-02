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
	"errors"
	"os"
	"runtime/debug"
	"strings"

	"github.com/eycorsican/go-tun2socks/common/log"

	"github.com/celzero/firestack/intra"
	"github.com/celzero/firestack/intra/doh"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/tunnel"
)

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
const gvisor bool = true
const mtu uint32 = 1500

func ConnectIntraTunnel(fd int, fakedns string, dohdns doh.Transport, protector protect.Protector, flow protect.Flow, listener intra.Listener) (t intra.Tunnel, err error) {
	dupfd, err := tunnel.Dup(fd)
	if err != nil {
		return nil, err
	}
	dialer := protect.MakeDialer(protector)
	config := protect.MakeListenConfig(protector)
	if gvisor {
		return intra.NewGTunnel(fakedns, dohdns, fd, mtu, dialer, flow, config, listener)
	} else {
		// java-land gives up its ownership of fd
		tun := os.NewFile(uintptr(dupfd), "")
		if tun == nil {
			return nil, errors.New("failed to open TUN file descriptor")
		}
		t, err = intra.NewTunnel(fakedns, dohdns, tun, dialer, flow, config, listener)
		go tunnel.ProcessInputPackets(t, tun)
		return
	}
}

// NewDoHTransport returns a DNSTransport that connects to the specified DoH server.
// `url` is the URL of a DoH server (no template, POST-only).  If it is nonempty, it
//   overrides `udpdns` and `tcpdns`.
// `ips` is an optional comma-separated list of IP addresses for the server.  (This
//   wrapper is required because gomobile can't make bindings for []string.)
// `protector` is the socket protector to use for all external network activity.
// `auth` will provide a client certificate if required by the TLS server.
// `listener` will be notified after each DNS query succeeds or fails.
func NewDoHTransport(url string, ips string, protector protect.Protector, auth doh.ClientAuth, listener intra.Listener) (doh.Transport, error) {
	split := []string{}
	if len(ips) > 0 {
		split = strings.Split(ips, ",")
	}
	dialer := protect.MakeDialer(protector)
	return doh.NewTransport(url, split, dialer, auth, listener)
}

func EnableDebugLog() {
	log.SetLevel(log.DEBUG)
}
