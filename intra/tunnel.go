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
	"errors"
	"net/netip"
	"strings"
	"sync"

	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/rnet"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/x64"
	"github.com/celzero/firestack/tunnel"
)

var errClosed = errors.New("tunnel closed for business")

type Bridge interface {
	Listener
	protect.Controller
}

// Listener receives usage statistics when a UDP or TCP socket is closed,
// or a DNS query is completed.
type Listener interface {
	SocketListener
	dnsx.DNSListener
	rnet.ServerListener
}

// Tunnel represents an Intra session.
type Tunnel interface {
	tunnel.Tunnel
	// Get the resolver.
	GetResolver() dnsx.Resolver
	// Add one or more system dns as csv string.
	SetSystemDNS(ippcsv string) int
	// Set DNSMode, BlockMode, PtMode. These are the enum constants
	// defined in package settings.
	SetTunMode(dnsmode, blockmode, ptmode int)
	// Get proxies.
	GetProxies() ipn.Proxies
	// Sets new default routes for the given engine, where engine is
	// one of the constants (Ns4, Ns6, Ns46) defined in package settings.
	SetRoute(engine int) error
	// Sets pcap output to fpcap which is the absolute filepath
	// to which a PCAP file will be written to.
	// If len(fpcap) is 0, no PCAP file will be written.
	// If len(fpcap) is 1, PCAP be written to stdout.
	SetPcap(fpcap string) error
}

type rtunnel struct {
	tunnel.Tunnel
	tunmode  *settings.TunMode
	proxies  ipn.Proxies
	resolver dnsx.Resolver
	services rnet.Services
	clomu    sync.RWMutex
	closed   bool
}

func NewTunnel(fd, mtu int, fakedns string, dns dnsx.Transport, tunmode *settings.TunMode, bdg Bridge) (Tunnel, error) {
	l3 := tunmode.L3()

	natpt := x64.NewNatPt(tunmode)
	proxies := ipn.NewProxifier(bdg)
	services := rnet.NewServices(proxies, bdg, bdg)

	resolver := dnsx.NewResolver(fakedns, dns, tunmode, bdg, natpt)
	resolver.Add(newBlockAllTransport())
	resolver.Add(newDNSCryptTransport(proxies))
	resolver.Add(newMDNSTransport(l3))

	tcph := NewTCPHandler(resolver, proxies, tunmode, bdg, bdg)
	udph := NewUDPHandler(resolver, proxies, tunmode, bdg, bdg)
	icmph := NewICMPHandler(resolver, proxies, tunmode, bdg)

	gt, err := tunnel.NewGTunnel(fd, mtu, tunmode.IpMode, tcph, udph, icmph)

	if err != nil {
		log.I("tun: <<< new >>>; err(%v)", err)
		return nil, err
	}

	t := &rtunnel{
		Tunnel:   gt,
		tunmode:  tunmode,
		proxies:  proxies,
		resolver: resolver,
		services: services,
	}

	log.I("tun: <<< new >>>; ok")
	resolver.Start()
	return t, nil
}

func (t *rtunnel) Disconnect() {
	t.clomu.Lock()
	closed := t.closed
	t.closed = true
	t.clomu.Unlock()

	if closed {
		log.W("tun: <<< disconnect >>>; already closed")
		return
	}

	err0 := t.resolver.Stop()
	err1 := t.proxies.StopProxies()
	n := t.services.StopServers()
	log.I("tun: <<< disconnect >>>; err0(%v); err1(%v); svc(%d)", err0, err1, n)

	t.Tunnel.Disconnect()
}

func (t *rtunnel) SetRoute(engine int) error {
	t.clomu.RLock()
	closed := t.closed
	t.clomu.RUnlock()

	if closed {
		log.W("tun: <<< set route >>>; already closed")
		return errClosed
	}

	t.tunmode.SetMode(t.tunmode.DNSMode, t.tunmode.BlockMode, t.tunmode.PtMode, engine)
	return t.Tunnel.SetRoute(engine)
}

func (t *rtunnel) GetResolver() dnsx.Resolver {
	return t.resolver
}

func (t *rtunnel) GetProxies() ipn.Proxies {
	return t.proxies
}

func (t *rtunnel) GetServices() rnet.Services {
	return t.services
}

func (t *rtunnel) SetSystemDNS(ippcsv string) int {
	ipports := strings.Split(ippcsv, ",")
	d := t.resolver.RemoveSystemDNS()
	if len(ipports) <= 0 {
		log.I("dns: removed %d system dns(es)", d)
		return 0
	}
	n := 0
	for _, ipport := range ipports {
		if ipp, err := netip.ParseAddrPort(ipport); err == nil {
			if sdns, err := newSystemDNSProxy(ipp); err == nil {
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

func (t *rtunnel) SetTunMode(dnsmode, blockmode, ptmode int) {
	t.tunmode.SetMode(dnsmode, blockmode, ptmode, t.tunmode.IpMode)
}
