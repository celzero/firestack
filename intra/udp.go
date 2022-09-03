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

	"github.com/celzero/firestack/intra/dns53"
	"github.com/celzero/firestack/intra/log"
	"github.com/eycorsican/go-tun2socks/core"
	"github.com/txthinking/socks5"

	"github.com/celzero/firestack/intra/dnscrypt"
	"github.com/celzero/firestack/intra/doh"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/netstack"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
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
	blockConn(localudp core.UDPConn, target *net.UDPAddr) bool
	SetDNSCryptProxy(*dnscrypt.Proxy)
	SetProxyOptions(*settings.ProxyOptions) error
	SetDNSProxy(dns53.Transport)
}

type udpHandler struct {
	UDPHandler
	sync.RWMutex

	timeout  time.Duration
	udpConns map[core.UDPConn]*tracker
	fakedns  []*net.UDPAddr
	dns      doh.Transport
	config   *net.ListenConfig
	blocker  protect.Blocker
	tunMode  *settings.TunMode
	listener UDPListener
	dnscrypt *dnscrypt.Proxy
	dnsproxy dns53.Transport
	proxy    proxy.Dialer
	pt       ipn.NatPt
}

// NewUDPHandler makes a UDP handler with Intra-style DNS redirection:
// All packets are routed directly to their destination, except packets whose
// destination is `fakedns`.  Those packets are redirected to DOH.
// `timeout` controls the effective NAT mapping lifetime.
// `config` is used to bind new external UDP ports.
// `listener` receives a summary about each UDP binding when it expires.
func NewUDPHandler(fakedns []*net.UDPAddr, pt ipn.NatPt, blocker protect.Blocker,
	tunMode *settings.TunMode, listener UDPListener) UDPHandler {
	// RFC 4787 REQ-5 requires a timeout no shorter than 5 minutes.
	udptimeout, _ := time.ParseDuration("5m")
	c := protect.MakeListenConfig2(blocker)
	h := &udpHandler{
		timeout:  udptimeout,
		udpConns: make(map[core.UDPConn]*tracker, 8),
		fakedns:  fakedns,
		blocker:  blocker,
		tunMode:  tunMode,
		config:   c,
		listener: listener,
		pt:       pt,
	}

	return h
}

// fetchUDPInput reads from nat.conn to masqurade-write it to core.UDPConn
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

		log.Debugf("t.udp.fetchudp: read remote for local-addr(%v)", conn.LocalAddr())
		// FIXME: ReadFrom seems to block for 50mins+ at times:
		// Cancel the goroutine in such cases and close the conns
		switch c := t.conn.(type) {
		case net.PacketConn:
			c.SetDeadline(time.Now().Add(h.timeout)) // extend deadline
			// reads a packet from t.conn copying it to buf
			n, addr, err = c.ReadFrom(buf)
		case net.Conn:
			c.SetDeadline(time.Now().Add(h.timeout)) // extend deadline
			// c is already dialed-in to some addr in udpHandler.Connect
			n, err = c.Read(buf)
		default:
			err = errors.New("failed to read from proxy udp conn")
		}

		if err != nil {
			log.Infof("t.udp.fetchudpinput: err(%v)", err)
			return
		}

		var udpaddr *net.UDPAddr
		if t.ip == nil && addr != nil {
			udpaddr = addr.(*net.UDPAddr)
		} else {
			// overwrite source-addr as set in t.ip
			udpaddr = t.ip
		}

		log.Debugf("t.udp.fetchudpinput: data(%d) from remote(actual:%v/masq:%v)", n, addr, udpaddr)

		t.download += int64(n)
		// writes data to conn (tun) with addr as source
		_, err = conn.WriteFrom(buf[:n], udpaddr)
		if err != nil {
			log.Warnf("failed to write udp data to tun from %s", udpaddr)
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

func (h *udpHandler) OnNewConn(conn *netstack.GUDPConn, _, dst *net.UDPAddr) bool {
	if err := h.Connect(conn, dst); err != nil {
		return false
	}
	return true
}

// Connect connects the proxy server. Note that target can be nil.
func (h *udpHandler) Connect(conn core.UDPConn, target *net.UDPAddr) error {
	if h.blockConn(conn, target) {
		// an error here results in a core.udpConn.Close
		return fmt.Errorf("udp connection firewalled")
	}

	proxymode := h.hasProxy() && (h.socks5Proxy() || h.httpsProxy())

	dnsredir := h.isDns(target)

	var c interface{}
	var err error
	if proxymode && !dnsredir {
		// TODO: translate target to addr4 when local dns64/nat64
		// TODO: target can be nil: What happens then?
		// deprecated: github.com/golang/go/issues/25104
		c, err = h.proxy.Dial(target.Network(), target.String())
	} else {
		bindaddr := &net.UDPAddr{IP: nil, Port: 0}
		c, err = h.config.ListenPacket(context.TODO(), target.Network(), bindaddr.String())
		// ipaddr, _ := netip.AddrFromSlice(h.pt.UIP(target.Network()))
		// ipp := netip.AddrPortFrom(ipaddr.Unmap(), 0)
		// bindaddr := &net.UDPAddr{
		//	IP:   h.pt.UIP(target.Network()),
		//	Port: 0,
		// }
	}

	if err != nil {
		log.Errorf("failed to bind udp addr for(%s); err(%v)", target.String(), err)
		return err
	}

	t := makeTracker(c)

	if proxymode {
		t.ip = target
	}

	h.Lock()
	h.udpConns[conn] = t
	h.Unlock()

	// TODO: fetch-udp-input not required for dns? dns-override takes over;
	// and funcs doDoh and doDnscrypt close the conns once tx is complete.
	go h.fetchUDPInput(conn, t)

	log.Infof("new udp proxy (mode: %s) conn to target: %s", proxymode, target.String())
	return nil
}

func (h *udpHandler) doDNSProxy(dns dns53.Transport, t *tracker, conn core.UDPConn, data []byte) {
	resp, err := dns.Query("udp", data)

	if resp != nil {
		_, err = conn.WriteFrom(resp, t.ip)
	}
	if err != nil {
		log.Warnf("dnsproxy udp query fail: %v", err)
	}

	if t.upload == 0 && t.download == 0 {
		// conn was only used for this DNS query, so it's unlikely to be used again.
		h.Close(conn)
	}
}

func (h *udpHandler) doDoh(dns doh.Transport, t *tracker, conn core.UDPConn, data []byte) {
	resp, err := dns.Query(data)

	if resp != nil {
		_, err = conn.WriteFrom(resp, t.ip)
	}
	if err != nil {
		log.Warnf("doh udp query failed: %v", err)
	}

	if t.upload == 0 && t.download == 0 {
		// conn was only used for this DNS query, so it's unlikely to be used again.
		h.Close(conn)
	}
}

func (h *udpHandler) doDNSCrypt(p *dnscrypt.Proxy, t *tracker, conn core.UDPConn, data []byte) {
	resp, err := dnscrypt.HandleUDP(p, data)
	if err != nil || resp == nil {
		log.Errorf("dnscrypt udp query failed: %v", err)
	} else {
		_, err = conn.WriteFrom(resp, t.ip)
		if err != nil {
			log.Errorf("dnscrypt udp query reply failed: %v", err)
		}
	}

	if t.upload == 0 && t.download == 0 {
		// conn was only used for this DNS query, so it's unlikely to be used again.
		h.Close(conn)
	}
}

func (h *udpHandler) isFakeDnsIpPort(addr *net.UDPAddr) bool {
	if addr == nil || len(h.fakedns) <= 0 {
		log.Errorf("nil dst-addr(%v) or dns(%v)", addr, h.fakedns)
		return false
	}
	for _, dnsaddr := range h.fakedns {
		if addr.IP.Equal(dnsaddr.IP) && addr.Port == dnsaddr.Port {
			return true
		}
	}
	return false
}

func (h *udpHandler) isFakeDnsPort(addr *net.UDPAddr) bool {
	if addr == nil || len(h.fakedns) <= 0 {
		log.Errorf("nil dst-addr(%v) or dns(%v)", addr, h.fakedns)
		return false
	}
	// isn't h.fakedns.Port always expected to be 53?
	for _, dnsaddr := range h.fakedns {
		if addr.Port == dnsaddr.Port {
			return true
		}
	}
	return false
}

func (h *udpHandler) isDNSProxy(addr *net.UDPAddr) bool {
	if h.tunMode.DNSMode == settings.DNSModeProxyIP {
		if yes := h.isFakeDnsIpPort(addr); yes {
			return true
		}
	} else if h.tunMode.DNSMode == settings.DNSModeProxyPort {
		if yes := h.isFakeDnsPort(addr); yes {
			return true
		}
	}
	return false
}

func (h *udpHandler) isDoh(addr *net.UDPAddr) bool {
	if h.tunMode.DNSMode == settings.DNSModeIP {
		if yes := h.isFakeDnsIpPort(addr); yes {
			return true
		}
	} else if h.tunMode.DNSMode == settings.DNSModePort {
		if yes := h.isFakeDnsPort(addr); yes {
			return true
		}
	}
	return false
}

func (h *udpHandler) isDNSCrypt(addr *net.UDPAddr) bool {
	if h.tunMode.DNSMode == settings.DNSModeCryptIP {
		if yes := h.isFakeDnsIpPort(addr); yes {
			return true
		}
	} else if h.tunMode.DNSMode == settings.DNSModeCryptPort {
		if yes := h.isFakeDnsPort(addr); yes {
			return true
		}
	}
	return false
}

func (h* udpHandler) isDns(addr *net.UDPAddr) bool {
	return h.isDoh(addr) || h.isDNSCrypt(addr) || h.isDNSProxy(addr)
}

func (h *udpHandler) dnsOverride(nat *tracker, conn core.UDPConn, addr *net.UDPAddr, query []byte) bool {
	// TODO: copy required? query := append([]byte{}, data...)
	h.RLock()
	doh := h.dns
	dcrypt := h.dnscrypt
	dproxy := h.dnsproxy
	h.RUnlock()

	if doh != nil && h.isDoh(addr) {
		nat.ip = addr
		go h.doDoh(doh, nat, conn, query)
		return true
	} else if dcrypt != nil && h.isDNSCrypt(addr) {
		nat.ip = addr
		go h.doDNSCrypt(dcrypt, nat, conn, query)
		return true
	} else if dproxy != nil && h.isDNSProxy(addr) {
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
	t, ok1 := h.udpConns[conn]
	h.RUnlock()

	if !ok1 {
		log.Warnf("t.udp.rcv: no nat(%v -> %v)", conn.LocalAddr(), addr)
		return fmt.Errorf("conn %v->%v does not exist", conn.LocalAddr(), addr)
	}

	if h.dnsOverride(t, conn, addr, data) {
		log.Debugf("t.udp.rcv: dns-override for dstaddr(%v)", addr)
		return nil
	} else if h.pt.IsNat64(ipn.Local464Resolver, addr.IP) {
		if ip4 := h.pt.X64(ipn.Local464Resolver, addr.IP); len(ip4) >= net.IPv4len {
			h.Lock()
			t.ip = addr
			addr.IP = ip4
			h.Unlock()
		}
		log.Debugf("t.udp.rcv: local-nat to addr4(%v) for addr6(%v)", addr, t.ip)
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
		err = errors.New("failed write to udp proxy")
	}

	if err != nil {
		log.Debugf("t.udp.rcv: forward udp err(%v)", err)
		return errors.New("failed to write udp data")
	}

	log.Infof("t.udp.rcv: src(%v) -> dst(%v) / data(%d)", conn.LocalAddr(), addr, len(data))
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

func (h *udpHandler) SetDNSProxy(dnsproxy dns53.Transport) {
	h.Lock()
	h.dnsproxy = dnsproxy
	h.Unlock()
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
	if po == nil {
		h.proxy = nil
		err = fmt.Errorf("udp: proxyopts nil")
		log.Warnf("udp: err proxying to(%v): %v", po, err)
		return err
	}

	// TODO: merge this code which is similar between tcp.go/udp.go
	if h.socks5Proxy() {
		// x.net.proxy doesn't yet support udp
		// https://github.com/golang/net/blob/62affa334/internal/socks/socks.go#L233
		// fproxy, err = proxy.SOCKS5("udp", po.IPPort, po.Auth, proxy.Direct)
		udptimeoutsec := 5 * 60                    // 5m
		tcptimeoutsec := (2 * 60 * 60) + (40 * 60) // 2h40m
		fproxy, err = socks5.NewClient(po.IPPort, po.Auth.User, po.Auth.Password, tcptimeoutsec, udptimeoutsec)
	} else if h.httpsProxy() {
		err = fmt.Errorf("http-proxy not supported")
	} else {
		err = errors.New("proxy mode not set")
	}
	if err != nil {
		h.proxy = nil
		log.Warnf("udp: err proxying to(%v): %v", po, err)
		return err
	}
	h.proxy = fproxy
	return nil
}
