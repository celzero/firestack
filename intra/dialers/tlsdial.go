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

func tlsConnect(d *tls.Dialer, proto string, local, remote netip.AddrPort) (net.Conn, error) {
	if d == nil {
		log.E("tlsdial: tlsConnect: nil dialer")
		return nil, errNoDialer
	} else if !ipok(remote.Addr()) {
		log.E("tlsdial: tlsConnect: invalid ip", remote)
		return nil, errNoIps
	}
	if local.IsValid() {
		cd := new(net.Dialer)
		*cd = *d.NetDialer // shallow copy
		cd.LocalAddr = net.TCPAddrFromAddrPort(local)
		return cd.Dial(proto, remote.String())
	} else {
		return d.Dial(proto, remote.String())
	}
}

func TlsDial(d *tls.Dialer, network, addr string) (net.Conn, error) {
	d.Config = ensureSni(d.Config, addr)
	return dialtls(d, d.Config, network, "", addr, adaptTlsDial(tlsConnect))
}
