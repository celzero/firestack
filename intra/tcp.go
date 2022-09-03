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
	"fmt"
	"io"
	"net"
	"time"

	"github.com/txthinking/socks5"
	"golang.org/x/net/proxy"

	"github.com/celzero/firestack/intra/dns53"
	"github.com/celzero/firestack/intra/log"
	"github.com/eycorsican/go-tun2socks/core"

	"github.com/celzero/firestack/intra/dnscrypt"
	"github.com/celzero/firestack/intra/doh"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/netstack"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/split"
)

// TCPHandler is a core TCP handler that also supports DOH and splitting control.
type TCPHandler interface {
	core.TCPConnHandler
	netstack.GTCPConnHandler

	SetDNS(doh.Transport)
	SetAlwaysSplitHTTPS(bool)
	blockConn(localConn net.Conn, target *net.TCPAddr) bool
	dnsOverride(net.Conn, *net.TCPAddr) bool
	SetDNSCryptProxy(*dnscrypt.Proxy)
	SetDNSProxy(dns53.Transport)
	SetProxyOptions(*settings.ProxyOptions) error
}

type tcpHandler struct {
	TCPHandler
	fakedns          []*net.TCPAddr
	dns              doh.Atomic
	alwaysSplitHTTPS bool
	dialer           *net.Dialer
	blocker          protect.Blocker
	tunMode          *settings.TunMode
	listener         TCPListener
	dnscrypt         *dnscrypt.Proxy
	dnsproxy         dns53.Transport
	proxy            proxy.Dialer
	pt               ipn.NatPt
}

// TCPSocketSummary provides information about each TCP socket, reported when it is closed.
type TCPSocketSummary struct {
	DownloadBytes int64 // Total bytes downloaded.
	UploadBytes   int64 // Total bytes uploaded.
	Duration      int32 // Duration in seconds.
	ServerPort    int16 // The server port.  All values except 53, 80, 443, and 0 are set to -1.
	Synack        int32 // TCP handshake latency (ms)
	// Retry is non-nil if retry was possible.  Retry.Split is non-zero if a retry occurred.
	Retry *split.RetryStats
}

// TCPListener is notified when a socket closes.
type TCPListener interface {
	OnTCPSocketClosed(*TCPSocketSummary)
}

// NewTCPHandler returns a TCP forwarder with Intra-style behavior.
// Connections to `fakedns` are redirected to DOH.
// All other traffic is forwarded using `dialer`.
// `listener` is provided with a summary of each socket when it is closed.
func NewTCPHandler(fakedns []*net.TCPAddr, pt ipn.NatPt, blocker protect.Blocker,
	tunMode *settings.TunMode, listener TCPListener) TCPHandler {
	d := protect.MakeDialer2(blocker)
	h := &tcpHandler{
		fakedns:  fakedns,
		dialer:   d,
		blocker:  blocker,
		tunMode:  tunMode,
		listener: listener,
		pt:       pt,
	}

	return h
}

// TODO: Propagate TCP RST using local.Abort(), on appropriate errors.
func (h *tcpHandler) handleUpload(local core.TCPConn, remote split.DuplexConn, upload chan int64) {
	ci := conn2str(local, remote)
	// io.copy does remote.ReadFrom(local)
	bytes, err := io.Copy(remote, local)
	log.Debugf("t.tcp handle-upload(%d) done(%v) b/w %s", bytes, err, ci)
	local.CloseRead()
	remote.CloseWrite()
	upload <- bytes
}

func conn2str(a net.Conn, b net.Conn) string {
	ar := a.RemoteAddr()
	br := b.RemoteAddr()
	al := a.LocalAddr()
	bl := b.LocalAddr()
	return fmt.Sprintf("a(%v->%v) => b(%v<-%v)", al, ar, bl, br)
}

func (h *tcpHandler) handleDownload(local core.TCPConn, remote split.DuplexConn) (bytes int64, err error) {
	ci := conn2str(local, remote)
	bytes, err = io.Copy(local, remote)
	log.Debugf("t.tcp handle-download(%d) done(%v) b/w %s", bytes, err, ci)
	local.CloseWrite()
	remote.CloseRead()
	return
}

func (h *tcpHandler) forward(local net.Conn, remote split.DuplexConn, summary *TCPSocketSummary) {
	localtcp := local.(core.TCPConn)
	upload := make(chan int64)
	start := time.Now()
	go h.handleUpload(localtcp, remote, upload)
	download, _ := h.handleDownload(localtcp, remote)
	summary.DownloadBytes = download
	summary.UploadBytes = <-upload
	summary.Duration = int32(time.Since(start).Seconds())
	h.listener.OnTCPSocketClosed(summary)
}

func filteredPort(addr net.Addr) int16 {
	_, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return -1
	}
	if port == "80" {
		return 80
	}
	if port == "443" {
		return 443
	}
	if port == "0" {
		return 0
	}
	if port == "53" {
		return 53
	}
	return -1
}

func (h *tcpHandler) isFakeDnsIpPort(addr *net.TCPAddr) bool {
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

func (h *tcpHandler) isFakeDnsPort(addr *net.TCPAddr) bool {
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

func (h *tcpHandler) isDNSProxy(addr *net.TCPAddr) bool {
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

func (h *tcpHandler) isDoh(addr *net.TCPAddr) bool {
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

func (h *tcpHandler) isDNSCrypt(addr *net.TCPAddr) bool {
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

func (h *tcpHandler) dnsOverride(conn net.Conn, addr *net.TCPAddr) bool {
	if h.isDoh(addr) {
		if dns := h.dns.Load(); dns != nil {
			go doh.Accept(dns, conn)
			return true
		}
	} else if h.isDNSCrypt(addr) {
		if dns := h.dnscrypt; dns != nil {
			go dnscrypt.HandleTCP(dns, conn)
			return true
		}
	} else if h.isDNSProxy(addr) {
		if dns := h.dnsproxy; dns != nil {
			go dns53.Accept(dns, conn)
			return true
		}
	}
	// assert h.tunMode.DNSMode == settings.DNSModeNone
	return false
}

func (h *tcpHandler) blockConn(localConn net.Conn, target *net.TCPAddr) (block bool) {
	// BlockModeNone returns false, BlockModeSink returns true
	if h.tunMode.BlockMode == settings.BlockModeSink {
		return true
	} else if h.tunMode.BlockMode == settings.BlockModeNone {
		return false
	}
	// Implict: BlockModeFilter or BlockModeFilterProc
	localtcp := localConn.(core.TCPConn)
	localaddr := localtcp.LocalAddr().(*net.TCPAddr)

	uid := -1
	if h.tunMode.BlockMode == settings.BlockModeFilterProc {
		procEntry := settings.FindProcNetEntry("tcp", localaddr.IP, localaddr.Port, target.IP, target.Port)
		if procEntry != nil {
			uid = procEntry.UserID
		}
	}

	block = h.blocker.Block(6 /*TCP*/, uid, localaddr.String(), target.String())

	if block {
		log.Infof("firewalled connection from %s:%s to %s:%s",
			localaddr.Network(), localaddr.String(), target.Network(), target.String())
	}

	return
}

// TODO: move these to settings pkg
func (h *tcpHandler) socks5Proxy() bool {
	return h.tunMode.ProxyMode == settings.ProxyModeSOCKS5
}

func (h *tcpHandler) httpsProxy() bool {
	return h.tunMode.ProxyMode == settings.ProxyModeHTTPS
}

func (h *tcpHandler) hasProxy() bool {
	return h.proxy != nil
}

func (h *tcpHandler) OnNewConn(conn *netstack.GTCPConn, _, dst *net.TCPAddr) {
	if err := h.Handle(conn, dst); err != nil {
		conn.Close()
	}
}

// TODO: Request upstream to make `conn` a `core.TCPConn` so we can avoid a type assertion.
func (h *tcpHandler) Handle(conn net.Conn, target *net.TCPAddr) error {
	if h.blockConn(conn, target) {
		// an error here results in a core.tcpConn.Abort
		return fmt.Errorf("tcp connection firewalled")
	}

	if h.dnsOverride(conn, target) {
		return nil
	} else if h.pt.IsNat64(ipn.Local464Resolver, target.IP) {
		// TODO: check if the network this process binds to has ipv4 connectivity
		if ip4 := h.pt.X64(ipn.Local464Resolver, target.IP); len(ip4) >= net.IPv4len {
			log.Debugf("t.tcp.handle: local nat64 to ip4(%v) for ip6(%v)", ip4, target.IP)
			target.IP = ip4
		} else {
			log.Warnf("t.tcp.handle: failed local nat64 to ip4(%v) for ip6(%v)", ip4, target.IP)
		}
	}

	var summary TCPSocketSummary
	summary.ServerPort = filteredPort(target)
	start := time.Now()
	var c split.DuplexConn
	var err error

	// TODO: Cancel dialing if c is closed
	// Ref: stackoverflow.com/questions/63656117
	// Ref: stackoverflow.com/questions/40328025
	if p := h.proxy; (h.socks5Proxy() || h.httpsProxy()) && p != nil {
		var generic net.Conn
		// deprecated: github.com/golang/go/issues/25104
		generic, err = p.Dial(target.Network(), target.String())
		if generic != nil {
			switch uc := generic.(type) {
			// if p is golang/x/net/proxy, then underlying-conn is simply uc
			case *net.TCPConn:
				c = uc
			// if p is txthinking/socks5, then underlying-conn is uc.TCPConn
			// github.com/txthinking/socks5/blob/39268fae/client.go#L15
			case *socks5.Client:
				c = uc.TCPConn
			default:
				err = fmt.Errorf("Proxy dialer failed to make a tcp conn")
			}
		}
	} else if summary.ServerPort == 443 {
		if h.alwaysSplitHTTPS {
			c, err = split.DialWithSplit(h.dialer, target)
		} else {
			summary.Retry = &split.RetryStats{}
			c, err = split.DialWithSplitRetry(h.dialer, target, summary.Retry)
		}
	} else {
		var generic net.Conn
		generic, err = h.dialer.Dial(target.Network(), target.String())
		if generic != nil {
			c = generic.(*net.TCPConn)
		}
	}

	if err != nil {
		log.Warnf("tcp: err dialing to(%v): %v", target, err)
		return err
	}
	summary.Synack = int32(time.Since(start).Seconds() * 1000)

	go h.forward(conn, c, &summary)

	log.Infof("tcp: new proxy conn(%s) from(%s) to target(%s)", target.Network(), conn.LocalAddr(), target)
	return nil
}

func (h *tcpHandler) SetDNS(dns doh.Transport) {
	h.dns.Store(dns)
}

func (h *tcpHandler) SetAlwaysSplitHTTPS(s bool) {
	h.alwaysSplitHTTPS = s
}

func (h *tcpHandler) SetDNSCryptProxy(dcrypt *dnscrypt.Proxy) {
	h.dnscrypt = dcrypt
}

func (h *tcpHandler) SetDNSProxy(d dns53.Transport) {
	h.dnsproxy = d
}

func (h *tcpHandler) SetProxyOptions(po *settings.ProxyOptions) error {
	var fproxy proxy.Dialer
	var err error
	if po == nil {
		h.proxy = nil
		log.Warnf("tcp: err proxying to(%v): %v", po, err)
		return fmt.Errorf("tcp: proxyopts nil")
	}
	if h.socks5Proxy() {
		// x.net.proxy doesn't yet support udp
		// https://github.com/golang/net/blob/62affa334/internal/socks/socks.go#L233
		// if po.Auth.User and po.Auth.Password are empty strings, the upstream
		// socks5 server may throw err when dialing with golang/net/x/proxy;
		// although, txthinking/socks5 deals gracefully with empty auth strings
		// fproxy, err = proxy.SOCKS5("udp", po.IPPort, po.Auth, proxy.Direct)
		udptimeoutsec := 5 * 60                    // 5m
		tcptimeoutsec := (2 * 60 * 60) + (40 * 60) // 2h40m
		fproxy, err = socks5.NewClient(po.IPPort, po.Auth.User, po.Auth.Password, tcptimeoutsec, udptimeoutsec)
	} else if h.httpsProxy() {
		err = fmt.Errorf("tcp: http-proxy not supported")
	} else {
		err = fmt.Errorf("tcp: proxy mode not set")
	}
	if err != nil {
		log.Warnf("tcp: err proxying to(%v): %v", po, err)
		h.proxy = nil
		return err
	}
	h.proxy = fproxy
	return nil
}
