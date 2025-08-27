// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dialers

import (
	"net"
	"net/netip"
	"time"

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
func ProxyDials(dd []proxy.Dialer, network, addr string) (c net.Conn, errs error) {
	start := time.Now()
	tot := len(dd)
	for i, d := range dd {
		if time.Since(start) > dialRetryTimeout {
			errs = core.JoinErr(errs, errRetryTimeout)
			break
		}
		conn, err := ProxyDial(d, network, addr)
		if conn == nil && err == nil {
			errs = core.JoinErr(errs, errNoConn)
		} else if err != nil {
			clos(conn)
			log.W("pdial: trying %s dialer of %d / %d to %s", network, i, tot, addr)
			errs = core.JoinErr(errs, err)
		} else if conn != nil {
			c = conn
			errs = nil
			return
		}
	}
	log.W("pdial: no dialer (sz: %d) could connect to %s", tot, addr)
	return nil, core.OneErr(errs, errNoDialer)
}
