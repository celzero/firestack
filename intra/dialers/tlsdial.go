// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dialers

import (
	"crypto/tls"
	"net"
	"net/netip"

	"github.com/celzero/firestack/intra/log"
)

func tlsConnect(d *tls.Dialer, proto string, ip netip.Addr, port int) (net.Conn, error) {
	if d == nil {
		log.E("tlsdial: tlsConnect: nil dialer")
		return nil, errNoDialer
	} else if !ipok(ip) {
		log.E("tlsdial: tlsConnect: invalid ip", ip)
		return nil, errNoIps
	}

	switch proto {
	case "tcp", "tcp4", "tcp6":
		fallthrough
	case "udp", "udp4", "udp6":
		fallthrough
	default:
		return d.Dial(proto, addrstr(ip, port))
	}
}

func TlsDial(d *tls.Dialer, network, addr string) (net.Conn, error) {
	d.Config = ensureSni(d.Config, addr)
	return dialtls(d, d.Config, network, addr, adaptTlsDial(tlsConnect))
}
