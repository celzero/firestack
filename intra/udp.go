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

// Derived from go-tun2socks's "direct" handler under the Apache 2.0 license.

package intra

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"github.com/eycorsican/go-tun2socks/common/log"
	"github.com/eycorsican/go-tun2socks/core"
	"github.com/txthinking/socks5"

	"github.com/celzero/firestack/intra/dnscrypt"
	"github.com/celzero/firestack/intra/dnsproxy"
	"github.com/celzero/firestack/intra/doh"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"

	"github.com/celzero/firestack/intra/netstack"
)

// UDPSocketSummary describes a non-DNS UDP association, reported when it is discarded.
type UDPSocketSummary struct {
	UploadBytes   int64 // Amount uploaded (bytes)
	DownloadBytes int64 // Amount downloaded (bytes)
	Duration      int32 // How long the socket was open (seconds)
}

// UDPListener is notified when a non-DNS UDP association is discarded.
type UDPListener interface {
	OnUDPSocketClosed(*UDPSocketSummary)
}

type tracker struct {
	conn     interface{} // net.Conn and net.PacketConn
	start    time.Time
	upload   int64        // Non-DNS upload bytes
	download int64        // Non-DNS download bytes
	ip       *net.UDPAddr // masked addr
}

func makeTracker(conn interface{}) *tracker {
	return &tracker{conn, time.Now(), 0, 0, nil}
}

// UDPHandler adds DOH support to the base UDPConnHandler interface.
type UDPHandler interface {
	core.UDPConnHandler
	netstack.GUDPConnHandler

	SetDNS(dns doh.Transport)
	onConn(localudp core.UDPConn, target *net.UDPAddr) string
	SetDNSCryptProxy(*dnscrypt.Proxy)
	SetProxyOptions(*settings.ProxyOptions) error
	SetDNSProxy(dnsproxy.Transport)
}

type udpHandler struct {
	UDPHandler
	sync.RWMutex

	timeout  time.Duration
	udpConns map[core.UDPConn]*tracker
	fakedns  net.UDPAddr
	tunMode  *settings.TunMode
	dns      doh.Transport
	dnscrypt *dnscrypt.Proxy
	dnsproxy dnsproxy.Transport
	config   *net.ListenConfig
	flow     protect.Flow
	listener UDPListener
	proxies  map[string]*proxy.Dialer
}

// NewUDPHandler makes a UDP handler with Intra-style DNS redirection:udpHandler
// All packets are routed directly to their destination, except packets whose
// destination is `fakedns`.  Those packets are redirected to DOH.
// `timeout` controls the effective NAT mapping lifetime.
// `config` is used to bind new external UDP ports.
// `listener` receives a summary about each UDP binding when it expires.
func NewUDPHandler(fakedns net.UDPAddr, timeout time.Duration, flow protect.Flow,
	tunMode *settings.TunMode, config *net.ListenConfig, listener UDPListener) UDPHandler {
	return &udpHandler{
		timeout:  timeout,
		udpConns: make(map[core.UDPConn]*tracker, 8),
		fakedns:  fakedns,
		flow:     flow,
		tunMode:  tunMode,
		config:   config,
		listener: listener,
		proxies:  make(map[string]*proxy.Dialer),
	}
}

// fetchUDPInput reads from nat.conn to masqurade-write it to core.UDPConn
func (h *udpHandler) fetchUDPInput(conn core.UDPConn, nat *tracker) {
	buf := core.NewBytes(core.BufSize)

	defer func() {
		h.Close(conn)
		core.FreeBytes(buf)
	}()

	for {
		var n int
		var addr net.Addr
		var err error

		// FIXME: ReadFrom seems to block for 50mins+ at times:
		// Cancel the goroutine in such cases and close the conns
		switch c := nat.conn.(type) {
		case net.PacketConn:
			// reads a packet from t.conn copying it to buf
			n, addr, err = c.ReadFrom(buf)
			c.SetDeadline(time.Now().Add(h.timeout)) // extend deadline
		case net.Conn:
			// c is already dialed-in to some addr in udpHandler.Connect
			n, err = c.Read(buf)
			c.SetDeadline(time.Now().Add(h.timeout)) // extend deadline
		default:
			err = errors.New("failed to read from proxy udp conn")
		}

		if err != nil {
			return
		}

		var udpaddr *net.UDPAddr
		if nat.ip == nil && addr != nil {
			udpaddr = addr.(*net.UDPAddr)
		} else {
			// overwrite source-addr as set in t.ip
			udpaddr = nat.ip
		}

		nat.download += int64(n)
		// writes data to conn (tun) with addr as source
		_, err = conn.WriteFrom(buf[:n], udpaddr)
		if err != nil {
			log.Warnf("failed to write UDP data to TUN from %s", udpaddr)
			return
		}
	}
}

func (h *udpHandler) onConn(localudp core.UDPConn, target *net.UDPAddr) (netid string) {
	// BlockModeNone returns false, BlockModeSink returns true
	if h.tunMode.BlockMode == settings.BlockModeSink {
		return protect.NetIdBlock
	}
	if h.tunMode.BlockMode == settings.BlockModeNone {
		return protect.NetIdActive
	}
	// localudp is either core.UDPConn or gonet.UDPConn wrapped in GUDPConn
	uconn := localudp.LocalAddr()
	// Next-up If: BlockModeFilter or BlockModeFilterProc
	return h.onNewConn(uconn, target)
}

func (h *udpHandler) onNewConn(source *net.UDPAddr, target *net.UDPAddr) (netid string) {
	uid := -1
	if h.tunMode.BlockMode == settings.BlockModeFilterProc {
		procEntry := settings.FindProcNetEntry("udp", source.IP, source.Port, target.IP, target.Port)
		if procEntry != nil {
			uid = procEntry.UserID
		}
	}

	netid = h.flow.On(17 /*UDP*/, uid, source.String(), target.String())

	if netid == protect.NetIdBlock {
		log.Infof("firewalled udp connection from %s:%s to %s:%s",
			source.Network(), source.String(), target.Network(), target.String())
	}

	return
}

func (h *udpHandler) NewUDPConnection(conn *netstack.GUDPConn, _, dst *net.UDPAddr) bool {
	/*gconn := GTCPConn{C: conn}
	newConn:= gconn.(net.Conn)*/
	if err := h.Connect(conn, dst); err != nil {
		return false
	}
	return true
}

// Connect connects the proxy server. Note that target can be nil.
func (h *udpHandler) Connect(conn core.UDPConn, target *net.UDPAddr) error {
	netid := h.onConn(conn, target)

	if netid == protect.NetIdBlock {
		// an error here results in a core.udpConn.Close
		return fmt.Errorf("udp connection firewalled")
	}

	var forwarder *proxy.Dialer
	if netid != protect.NetIdActive {
		h.RLock()
		forwarder = h.proxies[netid]
		h.RUnlock()
	}

	if forwarder == nil && netid != protect.NetIdActive {
		return fmt.Errorf("connection to non-existent netid %s firewalled", netid)
	}

	var c interface{}
	var err error
	if forwarder != nil { // TODO: h.httpproxy.Dial with quic
		// deprecated: https://github.com/golang/go/issues/25104
		// FIXME: target can be nil: What happens then?
		c, err = (*forwarder).Dial(target.Network(), target.String())
	} else {
		bindAddr := &net.UDPAddr{IP: nil, Port: 0}
		c, err = h.config.ListenPacket(context.TODO(), bindAddr.Network(), bindAddr.String())
	}

	if err != nil {
		log.Errorf("failed to bind udp addr %s %w", target.String(), err)
		return err
	}

	t := makeTracker(c)

	if forwarder != nil {
		t.ip = target
	}

	h.Lock()
	h.udpConns[conn] = t
	h.Unlock()

	go h.fetchUDPInput(conn, t)
	log.Infof("new udp proxy (mode: %s) conn to target: %s", (forwarder != nil), target.String())

	return nil
}

func (h *udpHandler) doDNSProxy(dns dnsproxy.Transport, nat *tracker, conn core.UDPConn, data []byte) {
	defer h.Close(conn)

	resp, err := dns.Query("udp", data)

	if resp != nil {
		_, err = conn.WriteFrom(resp, nat.ip)
	}
	if err != nil {
		log.Warnf("dnsproxy udp query fail: %v", err)
	}
}

func (h *udpHandler) doDoh(dns doh.Transport, nat *tracker, conn core.UDPConn, data []byte) {
	defer h.Close(conn)

	resp, err := dns.Query(data)

	if resp != nil {
		_, err = conn.WriteFrom(resp, nat.ip)
	}
	if err != nil {
		log.Warnf("doh udp query fail: %v", err)
	}
}

func (h *udpHandler) doDNSCrypt(p *dnscrypt.Proxy, nat *tracker, conn core.UDPConn, data []byte) {
	defer h.Close(conn)

	resp, err := dnscrypt.HandleUDP(p, data)
	if err != nil || resp == nil {
		log.Errorf("dnscrypt udp query fail: %v", err)
	} else {
		_, err = conn.WriteFrom(resp, nat.ip)
		if err != nil {
			log.Errorf("dnscrypt udp query reply fail: %v", err)
		}
	}
}

func (h *udpHandler) isDNSProxy(addr *net.UDPAddr) bool {
	if h.dnsproxy == nil {
		log.Warnf("dnsproxy nil")
		return false
	}

	if h.tunMode.DNSMode == settings.DNSModeProxyIP {
		return addr.IP.Equal(h.fakedns.IP) && addr.Port == h.fakedns.Port
	} else if h.tunMode.DNSMode == settings.DNSModeProxyPort {
		// h.fakedns.Port always expected to be 53?
		return addr.Port == h.fakedns.Port
	}
	return false
}

func (h *udpHandler) isDoh(addr *net.UDPAddr) bool {
	if h.dns == nil {
		log.Errorf("doh transport nil")
		return false
	}
	if h.tunMode.DNSMode == settings.DNSModeIP {
		return addr.IP.Equal(h.fakedns.IP) && addr.Port == h.fakedns.Port
	} else if h.tunMode.DNSMode == settings.DNSModePort {
		// h.fakedns.Port always expected to be 53?
		return addr.Port == h.fakedns.Port
	}
	return false
}

func (h *udpHandler) isDNSCrypt(addr *net.UDPAddr, t *tracker) bool {
	if h.dnscrypt == nil {
		log.Errorf("dnscrypt nil")
		return false
	}

	if h.tunMode.DNSMode == settings.DNSModeCryptIP {
		return addr.IP.Equal(h.fakedns.IP) && addr.Port == h.fakedns.Port
	} else if h.tunMode.DNSMode == settings.DNSModeCryptPort {
		// h.fakedns.Port always expected to be 53?
		return addr.Port == h.fakedns.Port
	}
	return false
}

func (h *udpHandler) dnsOverride(nat *tracker, conn core.UDPConn, addr *net.UDPAddr, data []byte) bool {
	query := append([]byte{}, data...)

	h.RLock()
	doh := h.dns
	dcrypt := h.dnscrypt
	dproxy := h.dnsproxy
	h.RUnlock()

	if h.isDoh(addr) {
		nat.ip = addr
		go h.doDoh(doh, nat, conn, query)
		return true
	} else if h.isDNSCrypt(addr, nat) {
		nat.ip = addr
		go h.doDNSCrypt(dcrypt, nat, conn, query)
		return true
	} else if h.isDNSProxy(addr) {
		nat.ip = addr
		go h.doDNSProxy(dproxy, nat, conn, query)
		return true
	}
	// assert h.tunMode.DNSMode == settings.DNSModeNone
	return false
}

func (h *udpHandler) HandleData(conn *netstack.GUDPConn, data []byte, addr *net.UDPAddr) error {
	return h.ReceiveTo(conn, data, addr)
}

// ReceiveTo is called when data arrives from conn (tun).
func (h *udpHandler) ReceiveTo(conn core.UDPConn, data []byte, addr *net.UDPAddr) (err error) {
	h.RLock()
	nat, ok1 := h.udpConns[conn]
	h.RUnlock()

	if !ok1 {
		return fmt.Errorf("connection %v->%v does not exists", conn.LocalAddr(), addr)
	}

	if h.dnsOverride(nat, conn, addr, data) {
		return nil
	}

	nat.upload += int64(len(data))

	switch c := nat.conn.(type) {
	case net.PacketConn:
		c.SetDeadline(time.Now().Add(h.timeout))
		// writes packet payload, data, to addr
		_, err = c.WriteTo(data, addr)
	case net.Conn:
		c.SetDeadline(time.Now().Add(h.timeout))
		// c is already dialed-in to some addr in udpHandler.Connect
		_, err = c.Write(data)
	default:
		err = errors.New("failed write to udp proxy")
	}

	if err != nil {
		log.Warnf("failed to forward udp payload")
		return errors.New("failed to write udp data")
	}

	return nil
}

func (h *udpHandler) Close(conn core.UDPConn) {
	conn.Close()

	h.Lock()
	defer h.Unlock()

	if t, ok := h.udpConns[conn]; ok {
		switch c := t.conn.(type) {
		case net.PacketConn:
			c.Close()
		case net.Conn:
			c.Close()
		default:
		}
		// TODO: Cancel any outstanding DoH queries.
		duration := int32(time.Since(t.start).Seconds())
		h.listener.OnUDPSocketClosed(&UDPSocketSummary{t.upload, t.download, duration})
		delete(h.udpConns, conn)
	}
}

func (h *udpHandler) SetDNS(dns doh.Transport) {
	h.Lock()
	h.dns = dns
	h.Unlock()
}

func (h *udpHandler) SetDNSCryptProxy(dcrypt *dnscrypt.Proxy) {
	h.Lock()
	h.dnscrypt = dcrypt
	h.Unlock()
}

func (h *udpHandler) SetDNSProxy(dnsproxy dnsproxy.Transport) {
	h.Lock()
	h.dnsproxy = dnsproxy
	h.Unlock()
}

func (h *udpHandler) SetProxyOptions(po *settings.ProxyOptions) (err error) {
	if po.IsGrounded() {
		h.Lock()
		delete(h.proxies, po.Id)
		h.Unlock()
		return
	}

	var pd proxy.Dialer
	if po.IsSocks5() {
		// x.net.proxy doesn't yet support udp
		// https://github.com/golang/net/blob/62affa334/internal/socks/socks.go#L233
		// fproxy, err = proxy.SOCKS5("udp", po.IPPort, po.Auth, proxy.Direct)
		timeoutsec := int(h.timeout.Seconds())
		pd, err = socks5.NewClient(po.IPPort, po.Auth.User, po.Auth.Password, timeoutsec, timeoutsec)
	} else if po.IsHttp() {
		err = errors.New("http/quic proxy over udp unsupported")
	} else {
		err = errors.New("invalid proxy")
	}

	if err != nil && pd != nil {
		h.Lock()
		h.proxies[po.Id] = &pd
		h.Unlock()
	}

	return
}
