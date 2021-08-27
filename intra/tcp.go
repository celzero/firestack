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
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"github.com/elazarl/goproxy"
	"github.com/eycorsican/go-tun2socks/common/log"
	"github.com/eycorsican/go-tun2socks/core"

	"github.com/celzero/firestack/intra/dnscrypt"
	"github.com/celzero/firestack/intra/doh"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/split"
)

// TCPHandler is a core TCP handler that also supports DOH and splitting control.
type TCPHandler interface {
	core.TCPConnHandler
	SetDNS(doh.Transport)
	SetAlwaysSplitHTTPS(bool)
	blockConn(localConn net.Conn, target *net.TCPAddr) bool
	dnsOverride(net.Conn, *net.TCPAddr) bool
	SetDNSCryptProxy(*dnscrypt.Proxy)
	SetProxyOptions(*settings.ProxyOptions) error
	SetDNSOptions(*settings.DNSOptions) error
}

type tcpHandler struct {
	TCPHandler
	sync.RWMutex

	fakedns          net.TCPAddr
	dns              doh.Atomic
	alwaysSplitHTTPS bool
	dialer           *net.Dialer
	flow             protect.Flow
	tunMode          *settings.TunMode
	listener         TCPListener
	dnscrypt         *dnscrypt.Proxy
	dnsproxy         *net.TCPAddr
	proxies          map[string]*proxy.Dialer
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
func NewTCPHandler(fakedns net.TCPAddr, dialer *net.Dialer, flow protect.Flow,
	tunMode *settings.TunMode, listener TCPListener) TCPHandler {
	return &tcpHandler{
		fakedns:  fakedns,
		dialer:   dialer,
		flow:     flow,
		tunMode:  tunMode,
		listener: listener,
		proxies:  make(map[string]*proxy.Dialer, 8),
	}
}

// TODO: Propagate TCP RST using local.Abort(), on appropriate errors.
func (h *tcpHandler) handleUpload(local core.TCPConn, remote split.DuplexConn, upload chan int64) {
	bytes, _ := remote.ReadFrom(local)
	local.CloseRead()
	remote.CloseWrite()
	upload <- bytes
}

func (h *tcpHandler) handleDownload(local core.TCPConn, remote split.DuplexConn) (bytes int64, err error) {
	bytes, err = io.Copy(local, remote)
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

func (h *tcpHandler) isDNSProxy(addr *net.TCPAddr) bool {
	if h.tunMode.DNSMode == settings.DNSModeProxyIP {
		return addr.IP.Equal(h.fakedns.IP) && addr.Port == h.fakedns.Port
	} else if h.tunMode.DNSMode == settings.DNSModeProxyPort {
		// h.fakedns.Port always expected to be 53?
		return addr.Port == h.fakedns.Port
	}
	return false
}

func (h *tcpHandler) isDoh(addr *net.TCPAddr) bool {
	if h.tunMode.DNSMode == settings.DNSModeIP {
		return addr.IP.Equal(h.fakedns.IP) && addr.Port == h.fakedns.Port
	} else if h.tunMode.DNSMode == settings.DNSModePort {
		// h.fakedns.Port always expected to be 53?
		return addr.Port == h.fakedns.Port
	}
	return false
}

func (h *tcpHandler) isDNSCrypt(addr *net.TCPAddr) bool {
	if h.tunMode.DNSMode == settings.DNSModeCryptIP {
		return addr.IP.Equal(h.fakedns.IP) && addr.Port == h.fakedns.Port
	} else if h.tunMode.DNSMode == settings.DNSModeCryptPort {
		// h.fakedns.Port always expected to be 53?
		return addr.Port == h.fakedns.Port
	}
	return false
}

func (h *tcpHandler) dnsOverride(conn net.Conn, addr *net.TCPAddr) bool {

	if h.isDoh(addr) {
		dns := h.dns.Load()
		go doh.Accept(dns, conn)
		return true
	} else if h.isDNSCrypt(addr) {
		go dnscrypt.HandleTCP(h.dnscrypt, conn)
		return true
	}
	// assert h.tunMode.DNSMode == settings.DNSModeNone
	return false
}

func (h *tcpHandler) onConn(localConn net.Conn, target *net.TCPAddr) (netid string) {
	// BlockModeNone returns false, BlockModeSink returns true
	if h.tunMode.BlockMode == settings.BlockModeSink {
		return protect.NetIdBlock
	} else if h.tunMode.BlockMode == settings.BlockModeNone {
		return protect.NetIdActive
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

	netid = h.flow.On(6 /*TCP*/, uid, localaddr.String(), target.String())

	if netid == protect.NetIdBlock {
		log.Infof("firewalled connection from %s:%s to %s:%s",
			localaddr.Network(), localaddr.String(), target.Network(), target.String())
	}

	return
}

// TODO: Request upstream to make `conn` a `core.TCPConn` so we can avoid a type assertion.
func (h *tcpHandler) Handle(conn net.Conn, target *net.TCPAddr) error {
	netid := h.onConn(conn, target)

	if netid == protect.NetIdBlock {
		// an error here results in a core.tcpConn.Abort
		return fmt.Errorf("tcp connection firewalled")
	}

	if h.dnsOverride(conn, target) {
		return nil
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

	var summary TCPSocketSummary
	summary.ServerPort = filteredPort(target)
	start := time.Now()
	var c split.DuplexConn
	var err error

	// TODO: Cancel dialing if c is closed
	// Ref: https://stackoverflow.com/questions/63656117/
	// Ref: https://stackoverflow.com/questions/40328025
	if forwarder != nil {
		var generic net.Conn
		// deprecated: https://github.com/golang/go/issues/25104
		generic, err = (*forwarder).Dial(target.Network(), target.String())
		if generic != nil {
			c = generic.(*net.TCPConn)
		}
	} else if summary.ServerPort == 443 || summary.ServerPort == 80 {
		if summary.ServerPort == 443 && h.alwaysSplitHTTPS { // always split-dial https
			c, err = split.DialWithSplit(h.dialer, target)
		} else { // split with retry otherwise
			summary.Retry = &split.RetryStats{}
			c, err = split.DialWithSplitRetry(h.dialer, target, summary.Retry)
		}
	} else if summary.ServerPort == 53 && h.isDNSProxy(target) {
		var generic net.Conn
		target = h.dnsproxy
		generic, err = h.dialer.Dial(target.Network(), target.String())
		if generic != nil {
			c = generic.(*net.TCPConn)
		}
	} else {
		var generic net.Conn
		generic, err = h.dialer.Dial(target.Network(), target.String())
		if generic != nil {
			c = generic.(*net.TCPConn)
		}
	}
	if err != nil {
		return err
	}
	summary.Synack = int32(time.Since(start).Seconds() * 1000)
	go h.forward(conn, c, &summary)
	log.Infof("new proxy connection for target: %s:%s", target.Network(), target.String())
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

func (h *tcpHandler) SetDNSOptions(do *settings.DNSOptions) error {
	dnsaddr, err := net.ResolveTCPAddr("tcp", do.IPPort)
	h.dnsproxy = dnsaddr
	return err
}

func (h *tcpHandler) SetProxyOptions(po *settings.ProxyOptions) (err error) {
	if po.IsEmpty() {
		h.Lock()
		delete(h.proxies, po.Id)
		h.Unlock()
		return
	}

	var pd proxy.Dialer
	if po.IsSocks5() {
		pd, err = proxy.SOCKS5("tcp", po.IPPort, po.Auth, proxy.Direct)
	} else if po.IsHttp() {
		pd = newHttpProxy(po)
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

type httpsproxy struct {
	underlyingServer *goproxy.ProxyHttpServer
}

func (p *httpsproxy) Dial(network, addr string) (c net.Conn, err error) {
	return p.underlyingServer.ConnectDial(network, addr)
}

func newHttpProxy(po *settings.ProxyOptions) proxy.Dialer {
	server := goproxy.NewProxyHttpServer()
	server.ConnectDial = server.NewConnectDialToProxy(po.String())
	return &httpsproxy{
		server,
	}
}
