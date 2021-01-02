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

package tunnel

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/eycorsican/go-tun2socks/core"

	"github.com/Jigsaw-Code/outline-go-tun2socks/tunnel/intra"
	"github.com/Jigsaw-Code/outline-go-tun2socks/tunnel/intra/dnscrypt"
	"github.com/Jigsaw-Code/outline-go-tun2socks/tunnel/intra/dnsx"
	"github.com/Jigsaw-Code/outline-go-tun2socks/tunnel/intra/doh"
	"github.com/Jigsaw-Code/outline-go-tun2socks/tunnel/intra/protect"
	"github.com/Jigsaw-Code/outline-go-tun2socks/tunnel/settings"
)

// IntraListener receives usage statistics when a UDP or TCP socket is closed,
// or a DNS query is completed.
type IntraListener interface {
	intra.UDPListener
	intra.TCPListener
	doh.Listener
	dnscrypt.Listener
}

// IntraTunnel represents an Intra session.
type IntraTunnel interface {
	Tunnel
	// Get the DNSTransport (default: nil).
	GetDNS() doh.Transport
	// Set the DNSTransport.  This method must be called before connecting the transport
	// to the TUN device.  The transport can be changed at any time during operation, but
	// must not be nil.
	SetDNS(doh.Transport)
	// Set DNSMode, BlockMode, and ProxyMode.
	SetTunMode(int, int, int)
	// When set to true, Intra will pre-emptively split all HTTPS connections.
	SetAlwaysSplitHTTPS(bool)
	// Enable reporting of SNIs that resulted in connection failures, using the
	// Choir library for privacy-preserving error reports.  `file` is the path
	// that Choir should use to store its persistent state, `suffix` is the
	// authoritative domain to which reports will be sent, and `country` is a
	// two-letter ISO country code for the user's current location.
	EnableSNIReporter(file, suffix, country string) error
	// StartDNSCryptProxy starts a DNSCrypt proxy instance for resolvers
	// (csv of dns-stamps) and relays (csv of dns-stamps).
	StartDNSCryptProxy(string, string, IntraListener) (string, error)
	// StopDNSCryptProxy stops DNSCrypt proxy
	StopDNSCryptProxy() error
	// GetDNSCryptProxy gets DNSCrypt proxy in-use.
	GetDNSCryptProxy() *dnscrypt.Proxy
	// StartTCPProxy starts tcp and udp forwarding proxy as dictated by current TunMode.
	StartProxy(uname string, pwd string, ip string, port string) error
	// GetTCPProxyOptions returns "uname,pwd,ip,port" csv
	GetProxyOptions() string
	// StartDNSProxy starts dns proxy as dictated by current TunMode.
	StartDNSProxy(ip string, port string) error
	// GetDNSOptions returns "ip,port" csv
	GetDNSProxyOptions() string
	// SetBraveDNS sets bravedns with various dns transports
	SetBraveDNS(dnsx.BraveDNS) error
	// GetBraveDNS gets bravedns in-use by various dns transports
	GetBraveDNS() dnsx.BraveDNS
}

type intratunnel struct {
	*tunnel
	tcp          intra.TCPHandler
	udp          intra.UDPHandler
	dns          doh.Transport
	tunmode      *settings.TunMode
	dnscrypt     *dnscrypt.Proxy
	proxyOptions *settings.ProxyOptions
	dnsOptions   *settings.DNSOptions
	bravedns     dnsx.BraveDNS
}

// NewIntraTunnel creates a connected Intra session.
//
// `fakedns` is the DNS server (IP and port) that will be used by apps on the TUN device.
//    This will normally be a reserved or remote IP address, port 53.
// `udpdns` and `tcpdns` are the actual location of the DNS server in use.
//    These will normally be localhost with a high-numbered port.
// `dohdns` is the initial DOH transport.
// `tunWriter` is the downstream VPN tunnel.  IntraTunnel.Disconnect() will close `tunWriter`.
// `dialer` and `config` will be used for all network activity.
// `listener` will be notified at the completion of every tunneled socket.
func NewIntraTunnel(fakedns string, dohdns doh.Transport, tunWriter io.WriteCloser, dialer *net.Dialer,
	blocker protect.Blocker, config *net.ListenConfig, listener IntraListener) (IntraTunnel, error) {
	if tunWriter == nil {
		return nil, errors.New("Must provide a valid TUN writer")
	}
	core.RegisterOutputFn(tunWriter.Write)
	base := &tunnel{tunWriter, core.NewLWIPStack(), true}
	t := &intratunnel{
		tunnel:  base,
		tunmode: settings.DefaultTunMode(),
	}
	if err := t.registerConnectionHandlers(fakedns, dialer, blocker, config, listener); err != nil {
		return nil, err
	}
	t.SetDNS(dohdns)
	return t, nil
}

// Registers Intra's custom UDP and TCP connection handlers to the tun2socks core.
func (t *intratunnel) registerConnectionHandlers(fakedns string, dialer *net.Dialer,
	blocker protect.Blocker, config *net.ListenConfig, listener IntraListener) error {
	// RFC 4787 REQ-5 requires a timeout no shorter than 5 minutes.
	timeout, _ := time.ParseDuration("5m")

	udpfakedns, err := net.ResolveUDPAddr("udp", fakedns)
	if err != nil {
		return err
	}
	t.udp = intra.NewUDPHandler(*udpfakedns, timeout, blocker, t.tunmode, config, listener)
	core.RegisterUDPConnHandler(t.udp)

	tcpfakedns, err := net.ResolveTCPAddr("tcp", fakedns)
	if err != nil {
		return err
	}
	t.tcp = intra.NewTCPHandler(*tcpfakedns, dialer, blocker, t.tunmode, listener)
	core.RegisterTCPConnHandler(t.tcp)
	return nil
}

func (t *intratunnel) SetDNS(dns doh.Transport) {
	bravedns := t.bravedns
	t.dns = dns
	t.udp.SetDNS(dns)
	t.tcp.SetDNS(dns)
	dns.SetBraveDNS(bravedns)
}

func (t *intratunnel) GetDNS() doh.Transport {
	return t.dns
}

func (t *intratunnel) SetTunMode(dnsmode int, blockmode int, proxymode int) {
	t.tunmode.SetMode(dnsmode, blockmode, proxymode)
}

func (t *intratunnel) SetAlwaysSplitHTTPS(s bool) {
	t.tcp.SetAlwaysSplitHTTPS(s)
}

func (t *intratunnel) EnableSNIReporter(filename, suffix, country string) error {
	f, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	return t.tcp.EnableSNIReporter(f, suffix, strings.ToLower(country))
}

func (t *intratunnel) StartDNSProxy(ip string, port string) (err error) {
	d := settings.NewDNSOptions(ip, port)
	if err = t.tcp.SetDNSOptions(d); err == nil {
		t.udp.SetDNSOptions(d)
	}
	if err != nil {
		t.dnsOptions = nil
		return
	}
	t.dnsOptions = d
	return
}

func (t *intratunnel) GetDNSProxyOptions() string {
	return t.dnsOptions.String()
}

func (t *intratunnel) StartDNSCryptProxy(resolvers string, relays string, listener IntraListener) (string, error) {
	var err error
	bravedns := t.bravedns
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
		return "", err
	}
	t.udp.SetDNSCryptProxy(p)
	t.tcp.SetDNSCryptProxy(p)
	p.SetBraveDNS(bravedns)

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
	t.dnscrypt.SetBraveDNS(nil)
	t.dnscrypt = nil
	return err
}

func (t *intratunnel) GetDNSCryptProxy() *dnscrypt.Proxy {
	return t.dnscrypt
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

func (t *intratunnel) SetBraveDNS(b dnsx.BraveDNS) error {
	doh := t.dns
	dnscrypt := t.dnscrypt

	t.bravedns = b

	if doh != nil {
		doh.SetBraveDNS(b)
	}
	if dnscrypt != nil {
		dnscrypt.SetBraveDNS(b)
	}

	return nil
}

func (t *intratunnel) GetBraveDNS() dnsx.BraveDNS {
	return t.bravedns
}
