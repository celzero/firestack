// Copyright 2019 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Derived from go-tun2socks's "direct" handler under the Apache 2.0 license.

package intra

import (
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/net/proxy"

	"github.com/eycorsican/go-tun2socks/common/log"
	"github.com/eycorsican/go-tun2socks/core"

	"github.com/Jigsaw-Code/outline-go-tun2socks/intra/dnscrypt"
	"github.com/Jigsaw-Code/outline-go-tun2socks/intra/protect"
	"github.com/Jigsaw-Code/outline-go-tun2socks/intra/settings"
	"github.com/Jigsaw-Code/outline-go-tun2socks/intra/doh"
	"github.com/Jigsaw-Code/outline-go-tun2socks/intra/split"
)

// TCPHandler is a core TCP handler that also supports DOH and splitting control.
type TCPHandler interface {
	core.TCPConnHandler
	SetDNS(doh.Transport)
	SetAlwaysSplitHTTPS(bool)
	EnableSNIReporter(file io.ReadWriter, suffix, country string) error
	blockConn(localConn net.Conn, target *net.TCPAddr) bool
	dnsOverride(net.Conn, *net.TCPAddr) bool
	SetDNSCryptProxy(*dnscrypt.Proxy)
	SetProxyOptions(*settings.ProxyOptions) error
	SetDNSOptions(*settings.DNSOptions) error
}

type tcpHandler struct {
	TCPHandler
	fakedns          net.TCPAddr
	dns              doh.Atomic
	alwaysSplitHTTPS bool
	dialer           *net.Dialer
	blocker          protect.Blocker
	tunMode          *settings.TunMode
	listener         TCPListener
	sniReporter      tcpSNIReporter
	dnscrypt         *dnscrypt.Proxy
	dnsproxy         *net.TCPAddr
	proxy            proxy.Dialer
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
func NewTCPHandler(fakedns net.TCPAddr, dialer *net.Dialer, blocker protect.Blocker,
	tunMode *settings.TunMode, listener TCPListener) TCPHandler {
	return &tcpHandler{
		fakedns:  fakedns,
		dialer:   dialer,
		blocker:  blocker,
		tunMode:  tunMode,
		listener: listener,
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
	if summary.Retry != nil {
		h.sniReporter.Report(*summary)
	}
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

// TODO: Request upstream to make `conn` a `core.TCPConn` so we can avoid a type assertion.
func (h *tcpHandler) Handle(conn net.Conn, target *net.TCPAddr) error {
	if h.blockConn(conn, target) {
		// an error here results in a core.tcpConn.Abort
		return fmt.Errorf("tcp connection firewalled")
	}

	if h.dnsOverride(conn, target) {
		return nil
	}

	var summary TCPSocketSummary
	summary.ServerPort = filteredPort(target)
	start := time.Now()
	var c split.DuplexConn
	var err error

	// TODO: Cancel dialing if c is closed
	// Ref: https://stackoverflow.com/questions/63656117/
	// Ref: https://stackoverflow.com/questions/40328025
	if p := h.proxy; (h.socks5Proxy() || h.httpsProxy()) && p != nil {
		var generic net.Conn
		// deprecated: https://github.com/golang/go/issues/25104
		generic, err = p.Dial(target.Network(), target.String())
		if generic != nil {
			c = generic.(*net.TCPConn)
		}
	} else if summary.ServerPort == 443 {
		if h.alwaysSplitHTTPS {
			c, err = split.DialWithSplit(h.dialer, target)
		} else {
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
	h.sniReporter.SetDNS(dns)
}

func (h *tcpHandler) SetAlwaysSplitHTTPS(s bool) {
	h.alwaysSplitHTTPS = s
}

func (h *tcpHandler) EnableSNIReporter(file io.ReadWriter, suffix, country string) error {
	return h.sniReporter.Configure(file, suffix, country)
}

func (h *tcpHandler) SetDNSCryptProxy(dcrypt *dnscrypt.Proxy) {
	h.dnscrypt = dcrypt
}

func (h *tcpHandler) SetDNSOptions(do *settings.DNSOptions) error {
	dnsaddr, err := net.ResolveTCPAddr("tcp", do.IPPort)
	h.dnsproxy = dnsaddr
	return err
}

func (h *tcpHandler) SetProxyOptions(po *settings.ProxyOptions) error {
	var fproxy proxy.Dialer
	var err error
	if h.socks5Proxy() {
		fproxy, err = proxy.SOCKS5("tcp", po.IPPort, po.Auth, proxy.Direct)
	} else if h.httpsProxy() {
		err = fmt.Errorf("http-proxy not supported")
	} else {
		err = fmt.Errorf("proxy mode not set")
	}
	if err != nil {
		h.proxy = nil
		return err
	}
	h.proxy = fproxy
	return nil
}
