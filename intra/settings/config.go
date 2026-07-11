// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package settings

import (
	"sync/atomic"

	"github.com/celzero/firestack/intra/core"
)

// NICID is the default network interface card ID for the network stack.
const NICID = 0x01

// Debug is a global flag to enable debug behaviour.
var Debug bool = false

// Loopingback is a global flag to adjust netstack behaviour
// wrt preventing split dialing, closing tunfd without delay etc.
var Loopingback = atomic.Bool{}

// SingleThreaded is a global flag to run Netstack's packet forwarder
// in a single-threaded mode.
var SingleThreaded = atomic.Bool{}

// PortForward is a global flag to enable bound to the same port
// for the outgoing conn as the incoming sockisfied conn.
var PortForward = atomic.Bool{}

// HappyEyeballs is a global flag to enable Happy Eyeballs algorithm
// for dual-stack (IPv4+IPv6) connections.
var HappyEyeballs = atomic.Bool{}

// ExperimentalWireGuard is a global flag to enable experimental
// settings for WireGuard.
var ExperimentalWireGuard = core.NewForeverFlow(false)

// FloodWireGuard is a global flag to enable flooding WireGuard
// tunnel with randomly sized non-null packets.
var FloodWireGuard = atomic.Bool{}

// EndpointIndependentMapping is a global flag to enable endpoint-independent
// mapping for UDP as per RFC 4787.
var EndpointIndependentMapping = atomic.Bool{}

// EndpointIndependentFiltering is a global flag to enable endpoint-independent
// filtering for UDP as per RFC 4787.
var EndpointIndependentFiltering = atomic.Bool{}

// SystemDNSForUndelegatedDomains is a global flag to always use System DNS
// for undelegated domains.
var SystemDNSForUndelegatedDomains = atomic.Bool{}

// DefaultDNSAsFallback is a global flag to allow using the Default transport
// as a fallback when the Preferred transport is missing or paused or ended.
var DefaultDNSAsFallback = atomic.Bool{}

// SetUserAgent is a global flag to set User-Agent for DoH requests
// to "Intra" and for HTTP "Reaches" checks to the Android default.
var SetUserAgent = atomic.Bool{}

// Android's default user-agent as set for connectivity checks
// PROBE_HTTPS https://www.google.com/generate_204 time=183ms ret=204 request={Connection=[close], User-Agent=[Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.32 Safari/537.36]}
// headers={null=[HTTP/1.1 204 No Content], Alt-Svc=[h3=":443"; ma=2592000,h3-29=":443"; ma=2592000], Connection=[close], Content-Length=[0], Cross-Origin-Resource-Policy=[cross-origin],
// Date=[Fri, 27 Jun 2025 10:56:24 GMT], X-Android-Received-Millis=[1751021784573], X-Android-Response-Source=[NETWORK 204], X-Android-Selected-Protocol=[http/1.1], X-Android-Sent-Millis=[1751021784495]}
// also: android-developers.googleblog.com/2024/12/user-agent-reduction-on-android-webview.html
const AndroidCcUa = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.32 Safari/537.36"
const IntraUa = "Intra"

// OwnTunFd is a global flag to indicate that the TUN fd is fully owned by netstack.
// that is, he TUN FD won't be dup'd and will be closed after use.
var OwnTunFd = atomic.Bool{}
