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

	"github.com/Jigsaw-Code/outline-go-tun2socks/intra/dnscrypt"
	"github.com/Jigsaw-Code/outline-go-tun2socks/intra/doh"
	"github.com/Jigsaw-Code/outline-go-tun2socks/intra/protect"
	"github.com/Jigsaw-Code/outline-go-tun2socks/intra/settings"
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
	SetDNS(dns doh.Transport)
	blockConn(localudp core.UDPConn, target *net.UDPAddr) bool
	SetDNSCryptProxy(*dnscrypt.Proxy)
	SetProxyOptions(*settings.ProxyOptions) error
	SetDNSOptions(*settings.DNSOptions) error
}

type udpHandler struct {
	UDPHandler
	sync.RWMutex

	timeout  time.Duration
	udpConns map[core.UDPConn]*tracker
	fakedns  net.UDPAddr
	dns      doh.Transport
	config   *net.ListenConfig
	blocker  protect.Blocker
	tunMode  *settings.TunMode
	listener UDPListener
	dnscrypt *dnscrypt.Proxy
	dnsproxy *net.UDPAddr
	proxy    proxy.Dialer
}

// NewUDPHandler makes a UDP handler with Intra-style DNS redirection:
// All packets are routed directly to their destination, except packets whose
// destination is `fakedns`.  Those packets are redirected to DOH.
// `timeout` controls the effective NAT mapping lifetime.
// `config` is used to bind new external UDP ports.
// `listener` receives a summary about each UDP binding when it expires.
func NewUDPHandler(fakedns net.UDPAddr, timeout time.Duration, blocker protect.Blocker,
	tunMode *settings.TunMode, config *net.ListenConfig, listener UDPListener) UDPHandler {
	return &udpHandler{
		timeout:  timeout,
		udpConns: make(map[core.UDPConn]*tracker, 8),
		fakedns:  fakedns,
		blocker:  blocker,
		tunMode:  tunMode,
		config:   config,
		listener: listener,
	}
}

func (h *udpHandler) fetchUDPInput(conn core.UDPConn, t *tracker) {
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
		switch c := t.conn.(type) {
		case net.PacketConn:
			// reads a packet from t.conn copying it to buf
			n, addr, err = c.ReadFrom(buf)
			c.SetDeadline(time.Now().Add(h.timeout))
		case net.Conn:
			// c is already dialed-in to some addr in udpHandler.Connect
			n, err = c.Read(buf)
			c.SetDeadline(time.Now().Add(h.timeout))
		default:
			err = errors.New("failed to read from proxy udp conn")
		}

		if err != nil {
			return
		}

		var udpaddr *net.UDPAddr
		if t.ip == nil && addr != nil {
			udpaddr = addr.(*net.UDPAddr)
		} else {
			// overwrite source-addr as set in t.ip
			udpaddr = t.ip
		}

		t.download += int64(n)
		// writes data to conn (tun) with addr as source
		_, err = conn.WriteFrom(buf[:n], udpaddr)
		if err != nil {
			log.Warnf("failed to write UDP data to TUN from %s", udpaddr)
			return
		}
	}
}

func (h *udpHandler) blockConn(localudp core.UDPConn, target *net.UDPAddr) (block bool) {
	// BlockModeNone returns false, BlockModeSink returns true
	if h.tunMode.BlockMode == settings.BlockModeSink {
		return true
	}
	if h.tunMode.BlockMode == settings.BlockModeNone {
		return false
	}
	// Implict: BlockModeFilter or BlockModeFilterProc
	localaddr := localudp.LocalAddr() //.(*net.UDPAddr)
	return h.blockConnAddr(localaddr, target)
}

func (h *udpHandler) blockConnAddr(source *net.UDPAddr, target *net.UDPAddr) (block bool) {

	uid := -1
	if h.tunMode.BlockMode == settings.BlockModeFilterProc {
		procEntry := settings.FindProcNetEntry("udp", source.IP, source.Port, target.IP, target.Port)
		if procEntry != nil {
			uid = procEntry.UserID
		}
	}

	block = h.blocker.Block(17 /*UDP*/, uid, source.String(), target.String())

	if block {
		log.Infof("firewalled udp connection from %s:%s to %s:%s",
			source.Network(), source.String(), target.Network(), target.String())
	}
	return block
}

// Connect connects the proxy server. Note that target can be nil.
func (h *udpHandler) Connect(conn core.UDPConn, target *net.UDPAddr) error {
	if h.blockConn(conn, target) {
		// an error here results in a core.udpConn.Close
		return fmt.Errorf("udp connection firewalled")
	}

	proxymode := h.hasProxy() && (h.socks5Proxy() || h.httpsProxy())

	var c interface{}
	var err error
	if proxymode {
		// deprecated: https://github.com/golang/go/issues/25104
		// FIXME: target can be nil: What happens then?
		c, err = h.proxy.Dial(target.Network(), target.String())
	} else {
		bindAddr := &net.UDPAddr{IP: nil, Port: 0}
		c, err = h.config.ListenPacket(context.TODO(), bindAddr.Network(), bindAddr.String())
	}

	if err != nil {
		log.Errorf("failed to bind udp addr %s %w", target.String(), err)
		return err
	}

	t := makeTracker(c)

	if proxymode {
		t.ip = target
	}

	h.Lock()
	h.udpConns[conn] = t
	h.Unlock()
	go h.fetchUDPInput(conn, t)
	log.Infof("new udp proxy (mode: %s) conn to target: %s", proxymode, target.String())
	return nil
}

func (h *udpHandler) doDoh(dns doh.Transport, t *tracker, conn core.UDPConn, data []byte) {
	resp, err := dns.Query(data)

	if resp != nil {
		_, err = conn.WriteFrom(resp, t.ip)
	}
	if err != nil {
		log.Warnf("DoH query failed: %v", err)
	}
	// Note: Reading t.upload and t.download on this thread, while they are written on
	// other threads, is theoretically a race condition.  In practice, this race is
	// impossible on 64-bit platforms, likely impossible on 32-bit platforms, and
	// low-impact if it occurs (a mixed-use socket might be closed early).
	if t.upload == 0 && t.download == 0 {
		// conn was only used for this DNS query, so it's unlikely to be used again.
		h.Close(conn)
	}
}

func (h *udpHandler) doDNSCrypt(p *dnscrypt.Proxy, t *tracker, conn core.UDPConn, data []byte) {
	resp, err := dnscrypt.HandleUDP(p, data)
	if err != nil || resp == nil {
		log.Errorf("dns-crypt udp query failed: %v", err)
	} else {
		_, err = conn.WriteFrom(resp, t.ip)
		if err != nil {
			log.Errorf("dns-crypt udp query reply failed: %v", err)
		}
	}

	if t.upload == 0 && t.download == 0 {
		// conn was only used for this DNS query, so it's unlikely to be used again.
		h.Close(conn)
	}
}

func (h *udpHandler) isDNSProxy(addr *net.UDPAddr) bool {
	if h.tunMode.DNSMode == settings.DNSModeProxyIP {
		return addr.IP.Equal(h.fakedns.IP) && addr.Port == h.fakedns.Port
	} else if h.tunMode.DNSMode == settings.DNSModeProxyPort {
		// h.fakedns.Port always expected to be 53?
		return addr.Port == h.fakedns.Port
	}
	return false
}

func (h *udpHandler) isDoh(addr *net.UDPAddr) bool {
	if h.tunMode.DNSMode == settings.DNSModeIP {
		return addr.IP.Equal(h.fakedns.IP) && addr.Port == h.fakedns.Port
	} else if h.tunMode.DNSMode == settings.DNSModePort {
		// h.fakedns.Port always expected to be 53?
		return addr.Port == h.fakedns.Port
	}
	return false
}

func (h *udpHandler) isDNSCrypt(addr *net.UDPAddr, t *tracker) bool {
	if h.tunMode.DNSMode == settings.DNSModeCryptIP {
		return addr.IP.Equal(h.fakedns.IP) && addr.Port == h.fakedns.Port
	} else if h.tunMode.DNSMode == settings.DNSModeCryptPort {
		// h.fakedns.Port always expected to be 53?
		return addr.Port == h.fakedns.Port
	}
	return false
}

func (h *udpHandler) dnsOverride(dns doh.Transport, dcrypt *dnscrypt.Proxy,
	t *tracker, conn core.UDPConn, addr *net.UDPAddr, data []byte) bool {
	dataCopy := append([]byte{}, data...)

	if h.isDoh(addr) {
		if dns == nil {
			log.Errorf("doh transport nil")
			return false
		}
		t.ip = addr
		go h.doDoh(dns, t, conn, dataCopy)
		return true
	} else if h.isDNSCrypt(addr, t) {
		if dcrypt == nil {
			log.Errorf("dns crypt nil")
			return false
		}
		t.ip = addr
		go h.doDNSCrypt(dcrypt, t, conn, dataCopy)
		return true
	}
	// assert h.tunMode.DNSMode == settings.DNSModeNone
	return false
}

// ReceiveTo is called when data arrives from conn (tun).
func (h *udpHandler) ReceiveTo(conn core.UDPConn, data []byte, addr *net.UDPAddr) (err error) {
	h.RLock()
	doh := h.dns
	dcrypt := h.dnscrypt
	dnsproxy := h.dnsproxy
	t, ok1 := h.udpConns[conn]
	h.RUnlock()

	if !ok1 {
		return fmt.Errorf("connection %v->%v does not exists", conn.LocalAddr(), addr)
	}

	if h.isDNSProxy(addr) {
		if dnsproxy == nil {
			log.Errorf("dns proxy nil")
		} else {
			t.ip = addr
			addr = h.dnsproxy
		}
	} else if h.dnsOverride(doh, dcrypt, t, conn, addr, data) {
		return nil
	}

	t.upload += int64(len(data))

	switch c := t.conn.(type) {
	case net.PacketConn:
		// Update deadline.
		c.SetDeadline(time.Now().Add(h.timeout))
		// writes packet payload, data, to addr
		_, err = c.WriteTo(data, addr)
	case net.Conn:
		// Update deadline.
		c.SetDeadline(time.Now().Add(h.timeout))
		// c is already dialed-in to some addr in udpHandler.Connect
		_, err = c.Write(data)
	default:
		err = errors.New("failed to write to proxy udp conn")
	}

	if err != nil {
		log.Warnf("failed to forward UDP payload")
		return errors.New("failed to write UDP data")
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

func (h *udpHandler) SetDNSOptions(do *settings.DNSOptions) error {
	h.Lock()
	dnsaddr, err := net.ResolveUDPAddr("udp", do.IPPort)
	h.dnsproxy = dnsaddr
	h.Unlock()
	return err
}

// TODO: move these to settings pkg
func (h *udpHandler) socks5Proxy() bool {
	return h.tunMode.ProxyMode == settings.ProxyModeSOCKS5
}

func (h *udpHandler) httpsProxy() bool {
	return h.tunMode.ProxyMode == settings.ProxyModeHTTPS
}

func (h *udpHandler) hasProxy() bool {
	return h.proxy != nil
}

func (h *udpHandler) SetProxyOptions(po *settings.ProxyOptions) error {
	var fproxy proxy.Dialer
	var err error
	if h.socks5Proxy() {
		// x.net.proxy doesn't yet support udp
		// https://github.com/golang/net/blob/62affa334/internal/socks/socks.go#L233
		// fproxy, err = proxy.SOCKS5("udp", po.IPPort, po.Auth, proxy.Direct)
		err = errors.New("udp not supported")
	} else if h.httpsProxy() {
		err = fmt.Errorf("http-proxy not supported")
	} else {
		err = errors.New("proxy mode not set")
	}
	if err != nil {
		h.proxy = nil
		return err
	}
	h.proxy = fproxy
	return nil
}
