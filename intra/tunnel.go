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
	"fmt"
	"sync"
	"sync/atomic"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/rnet"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/x64"
	"github.com/celzero/firestack/tunnel"
)

var errClosed = errors.New("tunnel closed for business")

type Bridge interface {
	Listener
	x.Controller
}

// Listener receives usage statistics when a UDP or TCP socket is closed,
// or a DNS query is completed.
type Listener interface {
	SocketListener
	x.DNSListener
	rnet.ServerListener
	x.ProxyListener
}

// Tunnel represents an Intra session.
type Tunnel interface {
	tunnel.Tunnel
	// Get the resolver.
	GetResolver() (x.DNSResolver, error)
	// Get the internal resolver.
	internalResolver() (dnsx.Resolver, error)
	// Get proxies.
	GetProxies() (x.Proxies, error)
	// Get the internal proxies.
	internalProxies() (ipn.Proxies, error)
	// A bridge to the client code.
	getBridge() Bridge
	// Sets new default routes for the given engine, where engine is
	// one of the constants (Ns4, Ns6, Ns46) defined in package settings.
	SetRoute(engine int) error
	// Sets pcap output to fpcap which is the absolute filepath
	// to which a PCAP file will be written to.
	// If len(fpcap) is 0, no PCAP file will be written.
	// If len(fpcap) is 1, PCAP be written to stdout.
	// Must be called on a background thread.
	SetPcap(fpcap string) error
	// Set DNSMode, BlockMode, PtMode.
	SetTunMode(dnsmode, blockmode, ptmode int)
}

type rtunnel struct {
	tunnel.Tunnel
	tunmode  *settings.TunMode
	bridge   Bridge
	proxies  ipn.Proxies
	resolver dnsx.Resolver
	services rnet.Services
	closed   atomic.Bool
	once     sync.Once
}

func NewTunnel(fd, mtu int, fakedns string, tunmode *settings.TunMode, dtr DefaultDNS, bdg Bridge) (Tunnel, error) {
	if bdg == nil || dtr == nil {
		return nil, fmt.Errorf("tun: no bridge? %t or default-dns? %t", bdg == nil, dtr == nil)
	}

	natpt := x64.NewNatPt(tunmode)
	proxies := ipn.NewProxifier(bdg, bdg)
	services := rnet.NewServices(proxies, bdg, bdg)

	if proxies == nil || services == nil {
		return nil, fmt.Errorf("tun: no proxies? %t or services? %t", proxies == nil, services == nil)
	}

	if err := dtr.kickstart(proxies, bdg); err != nil {
		log.I("tun: <<< new >>>; kickstart err(%v)", err)
		return nil, err
	}

	resolver := dnsx.NewResolver(fakedns, tunmode, dtr, bdg, natpt)
	resolver.Add(newGoosTransport(bdg, proxies))     // os-resolver; fixed
	resolver.Add(newBlockAllTransport())             // fixed
	resolver.Add(newDNSCryptTransport(proxies, bdg)) // fixed
	resolver.Add(newMDNSTransport(settings.IP46))    // fixed

	addIPMapper(resolver, settings.IP46) // namespace aware os-resolver for pkg dialers

	tcph := NewTCPHandler(resolver, proxies, tunmode, bdg, bdg)
	udph := NewUDPHandler(resolver, proxies, tunmode, bdg, bdg)
	icmph := NewICMPHandler(resolver, proxies, tunmode, bdg)

	gt, err := tunnel.NewGTunnel(fd, mtu, tcph, udph, icmph)

	if err != nil {
		log.I("tun: <<< new >>>; err(%v)", err)
		return nil, err
	}

	t := &rtunnel{
		Tunnel:   gt,
		tunmode:  tunmode,
		bridge:   bdg,
		proxies:  proxies,
		resolver: resolver,
		services: services,
	}

	log.I("tun: <<< new >>>; ok")
	return t, nil
}

func (t *rtunnel) getBridge() Bridge {
	return t.bridge // may return nil, esp after Disconnect()
}

func (t *rtunnel) Disconnect() {
	if t.closed.Load() {
		log.I("tun: <<< disconnect >>> already closed")
		return
	}
	t.once.Do(func() {
		t.closed.Store(true)

		removeIPMapper()
		err0 := t.resolver.Stop()
		err1 := t.proxies.StopProxies()
		n := t.services.StopServers()
		// t.bridge = nil // "free" ref to the client
		log.I("tun: <<< disconnect >>>; err0(%v); err1(%v); svc(%d)", err0, err1, n)

		t.Tunnel.Disconnect()
	})
}

func (t *rtunnel) SetRoute(engine int) error {
	if t.closed.Load() {
		log.W("tun: <<< set route >>>; already closed")
		return errClosed
	}

	return t.Tunnel.SetRoute(engine)
}

func (t *rtunnel) SetLinkAndRoutes(fd, mtu, engine int) error {
	if t.closed.Load() {
		log.W("tun: <<< set link and route >>>; already closed")
		return errClosed
	}

	l3 := settings.L3(engine)
	dialers.IPProtos(l3)
	t.resolver.Add(newMDNSTransport(l3))
	return t.Tunnel.SetLink(fd, mtu) // route is always dual-stack
}

func (t *rtunnel) GetResolver() (x.DNSResolver, error) {
	return t.internalResolver()
}

func (t *rtunnel) internalResolver() (dnsx.Resolver, error) {
	ko := t.closed.Load()
	if ko || t.resolver == nil {
		log.W("tun: <<< get internal resolver >>>; already closed? %t / %t", ko, t.resolver == nil)
		return nil, errClosed
	}

	return t.resolver, nil
}

func (t *rtunnel) GetProxies() (x.Proxies, error) {
	return t.internalProxies()
}

func (t *rtunnel) internalProxies() (ipn.Proxies, error) {
	ko := t.closed.Load()
	if ko || t.proxies == nil {
		log.W("tun: <<< get internal proxies >>>; already closed; %t / %t", ko, t.proxies == nil)
		return nil, errClosed
	}

	return t.proxies, nil
}

func (t *rtunnel) GetServices() (rnet.Services, error) {
	ko := t.closed.Load()

	if ko || t.proxies == nil {
		log.W("tun: <<< get svc >>>; already closed; %t / %t", ko, t.services == nil)
		return nil, errClosed
	}

	return t.services, nil
}

func (t *rtunnel) SetTunMode(dnsmode, blockmode, ptmode int) {
	t.tunmode.SetMode(dnsmode, blockmode, ptmode)
}
