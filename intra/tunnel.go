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
	"io"
	"net/netip"
	"strings"

	"github.com/eycorsican/go-tun2socks/core"

	"github.com/celzero/firestack/intra/dnscrypt"
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
	dnsx.Listener
}

// Tunnel represents an Intra session.
type Tunnel interface {
	tunnel.Tunnel
	// Add the DNSTransport (default: nil).
	GetResolver() dnsx.Resolver
	// Add system dns
	SetSystemDNS(ippcsv string) int
	NewDNSCryptProxy(string, string) (dnscrypt.Controller, error)
	GetDNSCryptProxy() dnscrypt.Controller
	// Set DNSMode, BlockMode, ProxyMode, PtMode.
	SetTunMode(int, int, int, int)
	// When set to true, Intra will pre-emptively split all HTTPS connections.
	SetAlwaysSplitHTTPS(bool)
	// StartTCPProxy starts tcp and udp forwarding proxy as dictated by current TunMode.
	StartProxy(uname string, pwd string, ip string, port string) error
	// GetTCPProxyOptions returns "uname,pwd,ip,port" csv
	GetProxyOptions() string
}

type intratunnel struct {
	tunnel.Tunnel
	tcp          TCPHandler
	udp          UDPHandler
	tunmode      *settings.TunMode
	dnscrypt     *dnscrypt.Proxy
	proxyOptions *settings.ProxyOptions
	dns          dnsx.Transport
	dnsproxy     dnsx.Transport
	bravedns     dnsx.BraveDNS
	natpt        ipn.NatPt
	resolver     dnsx.Resolver
}

// NewTunnel creates a connected Intra session.
//
// `fakedns` is the DNS server (IP and port) that will be used by apps on the TUN device.
//    This will normally be a reserved or remote IP address, port 53.
// `udpdns` and `tcpdns` are the actual location of the DNS server in use.
//    These will normally be localhost with a high-numbered port.
// `dohdns` is the initial DOH transport.
// `tunWriter` is the downstream VPN tunnel.  IntraTunnel.Disconnect() will close `tunWriter`.
// `dialer` and `config` will be used for all network activity.
// `listener` will be notified at the completion of every tunneled socket.
func NewTunnel(fakedns string, defaultdns dnsx.Transport, tunWriter io.WriteCloser, l3 string, mtu int, blocker protect.Blocker, listener Listener) (Tunnel, error) {
	if tunWriter == nil {
		return nil, errors.New("Must provide a valid TUN writer")
	}
	defaultmode := settings.DefaultTunMode()
	natpt := ipn.NewNatPt(l3, defaultmode)
	core.RegisterOutputFn(tunWriter.Write)
	t := &intratunnel{
		Tunnel:   tunnel.NewTunnel(tunWriter, core.NewLWIPStack(), mtu),
		tunmode:  defaultmode,
		natpt:    natpt,
		resolver: dnsx.NewResolver(fakedns, defaultmode, defaultdns, listener, natpt),
	}
	if err := t.registerConnectionHandlers(fakedns, l3, blocker, listener); err != nil {
		return nil, err
	}
	return t, nil
}

func NewGTunnel(fakedns string, defaultdns dnsx.Transport, fd int, l3 string, mtu int, blocker protect.Blocker, listener Listener) (Tunnel, error) {

	tunmode := settings.DefaultTunMode()

	natpt := ipn.NewNatPt(l3, tunmode)
	resolver := dnsx.NewResolver(fakedns, tunmode, defaultdns, listener, natpt)

	tcph := NewTCPHandler(resolver, natpt, blocker, tunmode, listener)
	udph := NewUDPHandler(resolver, natpt, blocker, tunmode, listener)
	t, err := tunnel.NewGTunnel(fd, l3, mtu, tcph, udph)

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

	return gt, nil
}

// Registers Intra's custom UDP and TCP connection handlers to the tun2socks core.
func (t *intratunnel) registerConnectionHandlers(fakedns, l3 string, blocker protect.Blocker, listener Listener) error {

	t.udp = NewUDPHandler(t.resolver, t.natpt, blocker, t.tunmode, listener)
	core.RegisterUDPConnHandler(t.udp)

	t.tcp = NewTCPHandler(t.resolver, t.natpt, blocker, t.tunmode, listener)
	core.RegisterTCPConnHandler(t.tcp)

	return nil
}

func (t *intratunnel) GetResolver() dnsx.Resolver {
	return t.resolver
}

func (t *intratunnel) SetSystemDNS(ippcsv string) int {
	ipports := strings.Split(ippcsv, ",")
	d := t.resolver.RemoveSystemDNS()
	if len(ipports) <= 0 {
		log.Infof("removed %d system dns(es)", d)
		return 0
	}
	n := 0
	for _, ipport := range ipports {
		if ipp, err := netip.ParseAddrPort(ipport); err == nil {
			if sdns, err := newDNSProxy(dnsx.System, ipp); err == nil {
				t.resolver.AddSystemDNS(sdns)
				n += 1
			} else {
				log.Warnf("make system dns %s; err(%v)", ipport, err)
			}
		} else {
			log.Warnf("invalid system dns %s; err(%v)", ipport, err)
		}
	}
	log.Infof("added %d system dns(es)", n)
	return n
}

func (t *intratunnel) SetTunMode(dnsmode int, blockmode int, proxymode int, ptmode int) {
	t.tunmode.SetMode(dnsmode, blockmode, proxymode, ptmode)
}

func (t *intratunnel) SetAlwaysSplitHTTPS(s bool) {
	t.tcp.SetAlwaysSplitHTTPS(s)
}

func (t *intratunnel) StartProxy(uname string, pwd string, ip string, port string) (err error) {
	p := settings.NewAuthProxyOptions(uname, pwd, ip, port)
	if err = t.tcp.SetProxyOptions(p); err != nil {
		t.proxyOptions = nil
		return
	}
	t.proxyOptions = p
	if err = t.udp.SetProxyOptions(p); err != nil {
		// TODO: unset tcp proxy, or leave that upto the client?
		t.proxyOptions = nil
		return
	}
	return
}

func (t *intratunnel) GetProxyOptions() string {
	return t.proxyOptions.String()
}
