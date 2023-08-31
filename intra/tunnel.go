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
	"github.com/celzero/firestack/intra/settings"
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
	UDPListener
	TCPListener
	ICMPListener
	dnsx.Listener
}

// Tunnel represents an Intra session.
type Tunnel interface {
	tunnel.Tunnel
	// Get the resolver.
	GetResolver() dnsx.Resolver
	// Add system dns.
	SetSystemDNS(ippcsv string) int
	// Set DNSMode, BlockMode, PtMode.
	SetTunMode(int, int, int)
	// Get proxies.
	GetProxies() ipn.Proxies
	// Reset the tunnel with new tundevice, mtu, engine, pcap file.
	Reset(int, int, int, string) error
}

type intratunnel struct {
	tunnel.Tunnel
	tcp      TCPHandler
	udp      UDPHandler
	icmp     ICMPHandler
	tunmode  *settings.TunMode
	natpt    ipn.NatPt
	proxies  ipn.Proxies
	resolver dnsx.Resolver
	clomu    sync.RWMutex
	closed   bool
}

func NewTunnel(fd, mtu int, fpcap, fakedns string, dns dnsx.Transport, tunmode *settings.TunMode, bdg Bridge) (Tunnel, error) {
	l3 := tunmode.L3()

	natpt := ipn.NewNatPt(tunmode)
	proxies := ipn.NewProxifier(bdg)

	resolver := dnsx.NewResolver(fakedns, dns, tunmode, bdg, natpt)
	resolver.Add(newBlockAllTransport())
	resolver.Add(newDNSCryptTransport())
	resolver.Add(NewMDNSTransport(l3))

	tcph := NewTCPHandler(resolver, natpt, proxies, bdg, tunmode, bdg)
	udph := NewUDPHandler(resolver, natpt, proxies, bdg, tunmode, bdg)
	icmph := NewICMPHandler(resolver, natpt, proxies, bdg, tunmode, bdg)

	gt, err := tunnel.NewGTunnel(fd, fpcap, l3, mtu, tcph, udph, icmph)

	if err != nil {
		log.I("tun: <<< new >>>; err(%v)", err)
		return nil, err
	}

	t := &intratunnel{
		Tunnel:   gt,
		tunmode:  tunmode,
		udp:      udph,
		tcp:      tcph,
		icmp:     icmph,
		natpt:    natpt,
		proxies:  proxies,
		resolver: resolver,
	}

	log.I("tun: <<< new >>>; ok")
	resolver.Start()
	return t, nil
}

func (t *intratunnel) Disconnect() {
	t.clomu.Lock()
	if t.closed {
		log.W("tun: <<< disconnect >>>; already closed")
		t.clomu.Unlock()
		return
	} else {
		t.closed = true
	}
	t.clomu.Unlock()

	err0 := t.resolver.Stop()
	err1 := t.proxies.StopProxies()
	log.I("tun: <<< disconnect >>>; err0(%v); err1(%v)", err0, err1)

	t.Tunnel.Disconnect()
}

func (t *intratunnel) Reset(fd, mtu, engine int, fpcap string) error {
	t.clomu.RLock()
	closed := t.closed
	t.clomu.RUnlock()

	if closed {
		log.W("tun: <<< reset >>>; already closed")
		return errClosed
	}

	t.tunmode.SetMode(t.tunmode.DNSMode, t.tunmode.BlockMode, t.tunmode.PtMode, engine)
	l3 := t.tunmode.L3()

	gt, err := tunnel.NewGTunnel(fd, fpcap, l3, mtu, t.tcp, t.udp, t.icmp)
	if err != nil {
		log.I("tun: <<< reset >>>; err?(%v)", err)
		return err
	}
	if prevgt := t.Tunnel; prevgt != nil {
		go prevgt.Disconnect()
		log.I("tun: <<< reset >>>; disconnecting prev tunnel")
	}
	t.Tunnel = gt

	log.I("tun: <<< reset >>>; ok")
	return nil
}

func (t *intratunnel) GetResolver() dnsx.Resolver {
	return t.resolver
}

func (t *intratunnel) GetProxies() ipn.Proxies {
	return t.proxies
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

func (t *intratunnel) SetTunMode(dnsmode, blockmode, ptmode int) {
	t.tunmode.SetMode(dnsmode, blockmode, ptmode, t.tunmode.IpMode)
}
