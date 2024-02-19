// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package intra

import (
	"net/netip"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/netstack"
)

// ref: github.com/pion/transport/blob/03c807b/udp/conn.go

func (h *udpHandler) ProxyMux(conn *netstack.GUDPConn, src netip.AddrPort) bool {
	log.W("udp: mux at %s; unsupported", src)
	// only ipn.Exit and ipn.Base support udp mux / packet conns
	const fin = true // disconnect
	// Connect does not really finish since the conn isn't even open yet
	conn.Connect(fin)
	return false
}
