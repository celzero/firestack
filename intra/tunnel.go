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
	"io"
	"net"
	"time"

	"github.com/eycorsican/go-tun2socks/core"

	"github.com/celzero/firestack/intra/dnscrypt"
	"github.com/celzero/firestack/intra/dnsproxy"
	"github.com/celzero/firestack/intra/doh"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/rdns"
	"github.com/celzero/firestack/intra/settings"

	"github.com/celzero/firestack/tunnel"
)

// Listener receives usage statistics when a UDP or TCP socket is closed,
// or a DNS query is completed.
type Listener interface {
	UDPListener
	TCPListener
	rdns.Listener
}

// Tunnel represents an Intra session.
type Tunnel interface {
	tunnel.Tunnel
	// Get the DNSTransport (default: nil).
	GetDNS() doh.Transport
	// Set the DNSTransport.  This method must be called before connecting the transport
	// to the TUN device.  The transport can be changed at any time during operation, but
	// must not be nil.
	SetDNS(doh.Transport)
	// Set DNSMode and BlockMode.
	SetTunMode(int, int)
	// When set to true, Intra will pre-emptively split all HTTPS connections.
	SetAlwaysSplitHTTPS(bool)
	// StartDNSCryptProxy starts a DNSCrypt proxy instance for resolvers
	// (csv of dns-stamps) and relays (csv of dns-stamps).
	StartDNSCryptProxy(string, string, Listener) (string, error)
	// StopDNSCryptProxy stops DNSCrypt proxy
	StopDNSCryptProxy() error
	// GetDNSCryptProxy gets DNSCrypt proxy in-use.
	GetDNSCryptProxy() *dnscrypt.Proxy
	// StartTCPProxy starts tcp and udp forwarding proxy as dictated by current TunMode.
	SetProxy(typ int, id, uname, pwd, ip, port string) error
	// StartDNSProxy starts dns proxy as dictated by current TunMode.
	StartDNSProxy(ip, port string, listener Listener) error
	// GetDNSOptions returns "ip,port" csv
	GetDNSProxy() dnsproxy.Transport
	// SetRethinkDNS sets rethinkdns with various dns transports
	SetRethinkDNS(rdns.RethinkDNS) error
	// GetRethinkDNS gets rethinkdns in-use by various dns transports
	GetRethinkDNS() rdns.RethinkDNS
}

type intratunnel struct {
	tunnel.Tunnel
	tcp        TCPHandler
	udp        UDPHandler
	dns        doh.Transport
	tunmode    *settings.TunMode
	dnscrypt   *dnscrypt.Proxy
	dnsproxy   dnsproxy.Transport
	rethinkdns rdns.RethinkDNS
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
func NewTunnel(fakedns string, dohdns doh.Transport, tunWriter io.WriteCloser, dialer *net.Dialer, flow protect.Flow, config *net.ListenConfig, listener Listener) (Tunnel, error) {
	if tunWriter == nil {
		return nil, errors.New("invalid tunnel writer")
	}

	core.RegisterOutputFn(tunWriter.Write)
	t := &intratunnel{
		Tunnel:  tunnel.NewTunnel(tunWriter, core.NewLWIPStack()),
		tunmode: settings.DefaultTunMode(),
	}
	if err := t.registerConnectionHandlers(fakedns, dialer, flow, config, listener); err != nil {
		return nil, err
	}
	t.SetDNS(dohdns)
	return t, nil
}

func NewGTunnel(fakedns string, dohdns doh.Transport, fd int, mtu uint32, dialer *net.Dialer, flow protect.Flow, config *net.ListenConfig, listener Listener) (Tunnel, error) {
	fakednsaddr := net.TCPAddr{IP: net.ParseIP(fakedns)}

	tunmode := settings.DefaultTunMode()

	tcph := NewTCPHandler(fakednsaddr, dialer, flow, tunmode, listener)
	t, err := tunnel.NewGTunnel(fd, mtu, tcph)

	if err != nil {
		return nil, err
	}

	gt := &intratunnel{
		Tunnel:  t,
		tunmode: tunmode,
	}

	if err := gt.registerGConnectionHandlers(fakedns, dialer, flow, config, listener); err != nil {
		return nil, err
	}

	gt.SetDNS(dohdns)
	return gt, nil
}

// Registers Intra's custom UDP and TCP connection handlers to the tun2socks core.
func (t *intratunnel) registerConnectionHandlers(fakedns string, dialer *net.Dialer, flow protect.Flow, config *net.ListenConfig, listener Listener) error {
	// RFC 4787 REQ-5 requires a timeout no shorter than 5 minutes.
	timeout, _ := time.ParseDuration("5m")

	udpfakedns, err := net.ResolveUDPAddr("udp", fakedns)
	if err != nil {
		return err
	}
	t.udp = NewUDPHandler(*udpfakedns, timeout, flow, t.tunmode, config, listener)
	core.RegisterUDPConnHandler(t.udp)

	tcpfakedns, err := net.ResolveTCPAddr("tcp", fakedns)
	if err != nil {
		return err
	}
	t.tcp = NewTCPHandler(*tcpfakedns, dialer, flow, t.tunmode, listener)
	core.RegisterTCPConnHandler(t.tcp)
	return nil
}

// FIXME: Remove, as this fn is similar to registerConnectionHandlers
func (t *intratunnel) registerGConnectionHandlers(fakedns string, dialer *net.Dialer, flow protect.Flow, config *net.ListenConfig, listener Listener) error {
	tunmode := settings.DefaultTunMode()
	tcpfakedns, err := net.ResolveTCPAddr("tcp", fakedns)
	if err != nil {
		return err
	}
	t.tcp = NewTCPHandler(*tcpfakedns, dialer, flow, tunmode, listener)
	return nil
}

func (t *intratunnel) SetDNS(dns doh.Transport) {
	rethinkdns := t.rethinkdns
	t.dns = dns
	t.udp.SetDNS(dns)
	t.tcp.SetDNS(dns)
	dns.SetRethinkDNS(rethinkdns)
}

func (t *intratunnel) GetDNS() doh.Transport {
	return t.dns
}

func (t *intratunnel) SetTunMode(dnsmode, blockmode int) {
	t.tunmode.SetMode(dnsmode, blockmode)
}

func (t *intratunnel) SetAlwaysSplitHTTPS(s bool) {
	t.tcp.SetAlwaysSplitHTTPS(s)
}

func (t *intratunnel) StartDNSProxy(ip string, port string, listener Listener) (err error) {
	d, err := dnsproxy.NewTransport(settings.NewDNSOptions(ip, port), listener)

	if err != nil {
		t.tcp.SetDNSProxy(nil)
		t.udp.SetDNSProxy(nil)
		t.dnsproxy = nil
		return
	}

	t.tcp.SetDNSProxy(d)
	t.udp.SetDNSProxy(d)
	t.dnsproxy = d

	return
}

func (t *intratunnel) GetDNSProxy() dnsproxy.Transport {
	return t.dnsproxy
}

func (t *intratunnel) StartDNSCryptProxy(resolvers string, relays string, listener Listener) (string, error) {
	var err error
	rethinkdns := t.rethinkdns
	if t.dnscrypt != nil {
		return "", fmt.Errorf("only one instance of dns-crypt proxy allowed")
	}
	p := dnscrypt.NewProxy(listener)
	if _, err = p.AddServers(resolvers); err == nil {
		if len(relays) > 0 {
			_, err = p.AddRoutes(relays)
		}
	}
	if err != nil {
		t.udp.SetDNSCryptProxy(nil)
		t.tcp.SetDNSCryptProxy(nil)
		return "", err
	}
	t.udp.SetDNSCryptProxy(p)
	t.tcp.SetDNSCryptProxy(p)
	p.SetRethinkDNS(rethinkdns)

	t.dnscrypt = p
	return p.StartProxy()
}

func (t *intratunnel) StopDNSCryptProxy() error {
	// TODO: implement this as a TunMode method?
	if t.tunmode.DNSMode == settings.DNSModeCryptIP || t.tunmode.DNSMode == settings.DNSModeCryptPort {
		return fmt.Errorf("dns-crypt-mode for the current session is active")
	}
	if t.dnscrypt == nil {
		return fmt.Errorf("no dns-crypt instance running")
	}
	err := t.dnscrypt.StopProxy()
	t.udp.SetDNSCryptProxy(nil)
	t.tcp.SetDNSCryptProxy(nil)
	t.dnscrypt.SetRethinkDNS(nil)
	t.dnscrypt = nil
	return err
}

func (t *intratunnel) GetDNSCryptProxy() *dnscrypt.Proxy {
	return t.dnscrypt
}

func (t *intratunnel) UnsetProxy(id string) {
	p := settings.NewEmptyAuthProxyOptions(id)
	t.tcp.SetProxyOptions(p)
	t.udp.SetProxyOptions(p)
}

func (t *intratunnel) SetProxy(typ int, id, uname, pwd, ip, port string) (err error) {
	p := settings.NewAuthProxyOptions(typ, id, uname, pwd, ip, port)
	if err = t.tcp.SetProxyOptions(p); err != nil {
		t.UnsetProxy(id)
		return
	}
	if err = t.udp.SetProxyOptions(p); err != nil {
		t.UnsetProxy(id)
		return
	}
	return
}

func (t *intratunnel) SetRethinkDNS(b rdns.RethinkDNS) error {
	doh := t.dns
	dnscrypt := t.dnscrypt
	dnsproxy := t.dnsproxy

	t.rethinkdns = b

	if doh != nil {
		doh.SetRethinkDNS(b)
	}
	if dnscrypt != nil {
		dnscrypt.SetRethinkDNS(b)
	}
	if dnsproxy != nil {
		dnsproxy.SetRethinkDNS(b)
	}

	return nil
}

func (t *intratunnel) GetRethinkDNS() rdns.RethinkDNS {
	return t.rethinkdns
}
