// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dialers

import (
	"context"
	"net"
	"net/netip"

	"github.com/celzero/firestack/intra/log"
)

func netConnect(d *net.Dialer, proto string, ip netip.Addr, port int) (net.Conn, error) {
	if d == nil {
		log.E("ndial: netConnect: nil dialer")
		return nil, errNoDialer
	} else if !ipok(ip) {
		log.E("ndial: netConnect: invalid ip", ip)
		return nil, errNoIps
	}
	return d.Dial(proto, addrstr(ip, port))
}

// NetDial connects to the address on the named network using net.Dialer.
func NetDial(d *net.Dialer, network, addr string) (net.Conn, error) {
	return unPtr(commondial(d, network, addr, adaptNetDial(netConnect)))
}

// NetListenPacket listens for UDP on local address using cfg.
// Returned net.Conn is guaranteed to be a *net.UDPConn.
func NetListenPacket(cfg *net.ListenConfig, network, local string) (net.PacketConn, error) {
	if cfg == nil {
		log.E("ndial: NetListenPacket: nil listen config")
		return nil, errNoListener
	}
	return cfg.ListenPacket(context.Background(), network, local)
}

// NetListen listens for TCP on local address using cfg.
func NetListen(cfg *net.ListenConfig, network, local string) (net.Listener, error) {
	if cfg == nil {
		log.E("ndial: NetListen: nil listen config")
		return nil, errNoListener
	}
	return cfg.Listen(context.Background(), network, local)
}
