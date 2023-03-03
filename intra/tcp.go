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
	"net/netip"
	"strings"
	"time"

	"github.com/txthinking/socks5"
	"golang.org/x/net/proxy"

	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/netstack"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/split"
)

const (
	blocktime = 25 * time.Second
)

// TCPHandler is a core TCP handler that also supports DOH and splitting control.
type TCPHandler interface {
	core.TCPConnHandler
	netstack.GTCPConnHandler

	SetAlwaysSplitHTTPS(bool)
	blockConn(localConn *net.TCPAddr, target *net.TCPAddr) bool
	dnsOverride(net.Conn, *net.TCPAddr) bool
	SetProxyOptions(*settings.ProxyOptions) error
}

type tcpHandler struct {
	TCPHandler
	resolver         dnsx.Resolver
	alwaysSplitHTTPS bool
	dialer           *net.Dialer
	blocker          protect.Blocker
	tunMode          *settings.TunMode
	listener         TCPListener
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
func NewTCPHandler(resolver dnsx.Resolver, pt ipn.NatPt, blocker protect.Blocker,
	tunMode *settings.TunMode, listener TCPListener) TCPHandler {
	d := protect.MakeDialer2(blocker)
	h := &tcpHandler{
		resolver: resolver,
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
	log.D("t.tcp handle-upload(%d) done(%v) b/w %s", bytes, err, ci)

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
	log.D("t.tcp handle-download(%d) done(%v) b/w %s", bytes, err, ci)

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

func (h *tcpHandler) dnsOverride(conn net.Conn, addr *net.TCPAddr) bool {
	// addr with zone information removed; see: netip.ParseAddrPort which h.resolver relies on
	addr2 := &net.TCPAddr{IP: addr.IP, Port: addr.Port}
	if h.resolver.IsDnsAddr(dnsx.NetTypeTCP, addr2.String()) {
		// conn closed by the resolver
		h.resolver.Serve(conn)
		return true
	}
	return false
}

func (h *tcpHandler) onFlow(localaddr *net.TCPAddr, target *net.TCPAddr, realips, domains, blocklists string) (block bool) {
	// BlockModeNone returns false, BlockModeSink returns true
	if h.tunMode.BlockMode == settings.BlockModeSink {
		return true
	} else if h.tunMode.BlockMode == settings.BlockModeNone {
		return false
	}

	if len(realips) <= 0 || len(domains) <= 0 {
		log.D("onFlow: no realips(%s) or domains(%s), for src=%s dst=%s", realips, domains, localaddr, target)
	}

	// Implict: BlockModeFilter or BlockModeFilterProc
	uid := -1
	if h.tunMode.BlockMode == settings.BlockModeFilterProc {
		procEntry := settings.FindProcNetEntry("tcp", localaddr.IP, localaddr.Port, target.IP, target.Port)
		if procEntry != nil {
			uid = procEntry.UserID
		}
	}

	var proto int32 = 6 // tcp
	src := localaddr.String()
	dst := target.String()
	if len(realips) > 0 && len(domains) > 0 {
		block = h.blocker.BlockAlg(proto, uid, src, dst, realips, domains, blocklists)
	} else {
		block = h.blocker.Block(proto, uid, src, dst)
	}

	if block {
		log.I("firewalled connection from %s:%s to %s:%s",
			localaddr.Network(), src, target.Network(), dst)
		// sleep for a while to avoid busy conns
		time.Sleep(blocktime)
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
	localaddr, err := tcpaddr(conn)
	if err != nil {
		log.E("conn has invalid local-addr(%s); %v", conn.LocalAddr(), err)
		return err
	}

	// alg happens before nat64, and so, alg has no knowledge of nat-ed ips
	// ipx4 is un-nated (but same as target.IP when no nat64 is involved)
	ipx4 := maybeUndoNat64(h.pt, target.IP)
	realips, domains, blocklists := undoAlg(h.resolver, ipx4)

	// flow/dns-override are nat-aware, as in, they can deal with
	// nat-ed ips just fine, and so, use target as-is instead of ipx4
	if h.onFlow(localaddr, target, realips, domains, blocklists) {
		// an error here results in a core.tcpConn.Abort
		return fmt.Errorf("tcp connection firewalled")
	}
	if h.dnsOverride(conn, target) {
		return nil
	}

	// dialers must connect to un-nated ips; overwrite target.IP with ipx4
	// but ipx4 might itself be an alg ip; so check if there's a real-ip to connect to
	target.IP = oneRealIp(realips, ipx4)

	var summary TCPSocketSummary
	summary.ServerPort = filteredPort(target)
	start := time.Now()
	var c split.DuplexConn

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
				err = errors.New("t.tcp: could not create tcp conn")
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
		log.W("tcp: err dialing to(%v): %v", target, err)
		return err
	}
	summary.Synack = int32(time.Since(start).Seconds() * 1000)

	go h.forward(conn, c, &summary)

	log.I("tcp: new proxy conn(%s) from(%s) to target(%s)", target.Network(), conn.LocalAddr(), target)
	return nil
}

func (h *tcpHandler) SetAlwaysSplitHTTPS(s bool) {
	h.alwaysSplitHTTPS = s
}

func (h *tcpHandler) SetProxyOptions(po *settings.ProxyOptions) error {
	var fproxy proxy.Dialer
	var err error
	if po == nil {
		h.proxy = nil
		log.W("tcp: err proxying to(%v): %v", po, err)
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
		log.W("tcp: err proxying to(%v): %v", po, err)
		h.proxy = nil
		return err
	}
	h.proxy = fproxy
	return nil
}

func maybeUndoNat64(pt ipn.NAT64, ip net.IP) net.IP {
	ipx4 := ip
	// TODO: need the actual ID of the transport that did nat64
	if pt.IsNat64(ipn.Local464Resolver, ip) { // un-nat64, when dns64 done by local464-resolver
		// TODO: check if the network this process binds to has ipv4 connectivity
		ipx4 = pt.X64(ipn.Local464Resolver, ip) // ipx4 may be nil
		if len(ipx4) < net.IPv4len {            // no nat?
			ipx4 = ip // reassign the actual ip
			log.W("t.tcp.handle: No local nat64 to ip4(%v) for ip6(%v)", ipx4, ip)
		}
	}
	return ipx4
}

func netipFrom(ip net.IP) *netip.Addr {
	if addr, ok := netip.AddrFromSlice(ip); ok {
		addr = addr.Unmap()
		return &addr
	}
	return nil
}

func oneRealIp(realips string, dstip net.IP) net.IP {
	if len(realips) <= 0 {
		return dstip
	}
	// override alg-ip with the first real-ip
	if ips := strings.Split(realips, ","); len(ips) > 0 {
		for _, v := range ips {
			// len may be zero when realips is "," or ""
			if len(v) > 0 {
				ip := net.ParseIP(v)
				if !ip.IsUnspecified() {
					return ip
				}
			}
		}
	}
	return dstip
}

func undoAlg(r dnsx.Resolver, algip net.IP) (realips, domains, blocklists string) {
	dstip := netipFrom(algip)
	if gw := r.Gateway(); dstip.IsValid() && gw != nil {
		dst := dstip.AsSlice()
		domains = gw.PTR(dst)
		realips = gw.X(dst)
		blocklists = gw.RDNSBL(dst)
	} else {
		log.D("t.tcp.handle: no gw(%t) or alg-ip(%s)", gw == nil, algip)
	}
	return
}

func tcpaddr(conn net.Conn) (*net.TCPAddr, error) {
	localtcp, ok1 := conn.(core.TCPConn)
	if !ok1 {
		return nil, fmt.Errorf("t.tcp Handle: non-tcp-conn(%v)", conn)
	}
	localaddr, ok2 := localtcp.LocalAddr().(*net.TCPAddr)
	if !ok2 {
		return nil, fmt.Errorf("t.tcp Handle: non-tcp-addr(%v)", localtcp.LocalAddr())
	}
	return localaddr, nil
}
