// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dialers

import (
	"errors"
	"net"
	"net/netip"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"golang.org/x/net/proxy"
)

// todo: dial bound to the local address if specified
func proxyConnect(d *proxy.Dialer, proto string, local, remote netip.AddrPort) (net.Conn, error) {
	if d == nil { // unlikely
		log.E("pdial: proxyConnect: nil dialer")
		return nil, errNoDialer
	} else if !ipok(remote.Addr()) {
		log.E("pdial: proxyConnect: invalid ip", remote)
		return nil, errNoIps
	}

	return (*d).Dial(proto, remote.String())
}

// ProxyDial tries to connect to addr using d
func ProxyDial(d proxy.Dialer, network, addr string) (net.Conn, error) {
	if d == nil || core.IsNil(d) {
		log.E("pdial: ProxyDial: nil dialer")
		return nil, errNoDialer
	}
	return unPtr(commondial(&d, network, addr, adaptProxyDial(proxyConnect)))
}

// ProxyDials tries to connect to addr using each dialer in dd
func ProxyDials(dd []proxy.Dialer, network, addr string) (c net.Conn, err error) {
	tot := len(dd)
	for i, d := range dd {
		c, err = ProxyDial(d, network, addr)
		if c == nil && err == nil {
			err = errors.Join(err, errNoConn)
		} else if err != nil {
			clos(c)
			log.W("pdial: trying %s dialer of %d / %d to %s", network, i, tot, addr)
			err = errors.Join(err)
		} else if c != nil {
			err = nil
			return
		}
	}
	if c == nil && err == nil {
		log.W("pdial: no dialer (sz: %d) succeeded for %s", tot, addr)
		return nil, errNoDialer
	}
	return
}
