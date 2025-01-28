// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package settings

import (
	"sync/atomic"
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

// ExperimentalWireGuard is a global flag to enable experimental
// settings for WireGuard.
var ExperimentalWireGuard = atomic.Bool{}

// EndpointIndependentMapping is a global flag to enable endpoint-independent
// mapping for UDP as per RFC 4787.
var EndpointIndependentMapping = atomic.Bool{}

// EndpointIndependentFiltering is a global flag to enable endpoint-independent
// filtering for UDP as per RFC 4787.
var EndpointIndependentFiltering = atomic.Bool{}

// SystemDNSForUndelegatedDomains is a global flag to always use System DNS
// for undelegated domains.
var SystemDNSForUndelegatedDomains = atomic.Bool{}

// SetUserAgentForDoH is a global flag to set User-Agent for DoH requests
// to "Intra".
var SetUserAgentForDoH = atomic.Bool{}

// PanicAtRandom is a global flag to panic the network engine
// every once in a while (for testing).
var PanicAtRandom = atomic.Bool{}
