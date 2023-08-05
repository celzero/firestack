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

package intra

import (
	"net/netip"
	"strings"

	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/tunnel"
)

// Listener receives usage statistics when a UDP or TCP socket is closed,
// or a DNS query is completed.
type Listener interface {
	UDPListener
	TCPListener
	ICMPListener
	dnsx.Listener
}

// Tunnel represents an Intra session.
type Tunnel interface {
	tunnel.Tunnel
	// Get the resolver
	GetResolver() dnsx.Resolver
	// Add system dns
	SetSystemDNS(ippcsv string) int
	// Set DNSMode, BlockMode, PtMode.
	SetTunMode(int, int, int)
	// Get the proxies
	GetProxies() ipn.Proxies
}

type intratunnel struct {
	tunnel.Tunnel
	tcp          TCPHandler
	udp          UDPHandler
	tunmode      *settings.TunMode
	proxyOptions *settings.ProxyOptions
	natpt        ipn.NatPt
	resolver     dnsx.Resolver
}

func NewTunnel(fakedns string, defaultdns dnsx.Transport, fd int, fpcap string, l3 string, mtu int, ctl protect.Controller, listener Listener) (Tunnel, error) {
	tunmode := settings.DefaultTunMode()

	natpt := ipn.NewNatPt(l3, ctl, tunmode)

	resolver := dnsx.NewResolver(fakedns, tunmode, defaultdns, listener, natpt)
	resolver.Add(newBlockAllTransport())
	resolver.Add(NewMDNSTransport(l3))
	resolver.Add(newDNSCryptTransport())

	tcph := NewTCPHandler(resolver, natpt, ctl, tunmode, listener)
	udph := NewUDPHandler(resolver, natpt, ctl, tunmode, listener)
	icmph := NewICMPHandler(resolver, natpt, ctl, tunmode, listener)
	t, err := tunnel.NewGTunnel(fd, fpcap, l3, mtu, tcph, udph, icmph)

	if err != nil {
		return nil, err
	}

	gt := &intratunnel{
		Tunnel:   t,
		tunmode:  tunmode,
		udp:      udph,
		tcp:      tcph,
		natpt:    natpt,
		resolver: resolver,
	}

	resolver.Start()
	return gt, nil
}

func (t *intratunnel) Disconnect() {
	t.resolver.Stop()
	t.Tunnel.Disconnect()
}

func (t *intratunnel) GetResolver() dnsx.Resolver {
	return t.resolver
}

func (t *intratunnel) GetProxies() ipn.Proxies {
	return t.natpt
}

func (t *intratunnel) SetSystemDNS(ippcsv string) int {
	ipports := strings.Split(ippcsv, ",")
	d := t.resolver.RemoveSystemDNS()
	if len(ipports) <= 0 {
		log.I("dns: removed %d system dns(es)", d)
		return 0
	}
	n := 0
	for _, ipport := range ipports {
		if ipp, err := netip.ParseAddrPort(ipport); err == nil {
			if sdns, err := newDNSProxy(dnsx.System, ipp); err == nil {
				t.resolver.AddSystemDNS(sdns)
				n += 1
			} else {
				log.W("dns: make system dns %s; err(%v)", ipport, err)
			}
		} else {
			log.W("dns: invalid system dns %s; err(%v)", ipport, err)
		}
	}
	log.I("dns: added %d system dns(es) from %s", n, ipports)
	return n
}

func (t *intratunnel) SetTunMode(dnsmode int, blockmode int, ptmode int) {
	t.tunmode.SetMode(dnsmode, blockmode, ptmode)
}
