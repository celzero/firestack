// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//    ISC License
//
//    Copyright (c) 2018-2021
//    Frank Denis <j at pureftpd dot org>

package dnscrypt

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/xdns"

	stamps "github.com/jedisct1/go-dnsstamps"
	"golang.org/x/crypto/ed25519"
)

type registeredserver struct {
	name  string
	stamp stamps.ServerStamp
}

type serverinfo struct {
	Proto              stamps.StampProtoType
	MagicQuery         [8]byte
	ClientPubKey       *[32]byte
	ServerPk           [32]byte
	SharedKey          [32]byte
	CryptoConstruction xdns.CryptoConstruction
	Name               string // id of the server
	HostName           string
	UDPAddr            *net.UDPAddr
	TCPAddr            *net.TCPAddr
	RelayUDPAddrs      []*net.UDPAddr
	RelayTCPAddrs      []*net.TCPAddr
	status             int
	proxies            ipn.Proxies // proxy-provider, may be nil
	relay              ipn.Proxy   // proxy relay to use, may be nil
	dialer             *protect.RDial
	est                core.P2QuantileEstimator
}

var _ dnsx.Transport = (*serverinfo)(nil)

type ServersInfo struct {
	sync.RWMutex
	inner             map[string]*serverinfo
	registeredServers map[string]registeredserver
}

// newServersInfo returns a new servers-info object
func newServersInfo() ServersInfo {
	return ServersInfo{
		registeredServers: make(map[string]registeredserver),
		inner:             make(map[string]*serverinfo),
	}
}

func (serversInfo *ServersInfo) len() int {
	serversInfo.RLock()
	defer serversInfo.RUnlock()

	return len(serversInfo.registeredServers)
}

func (serversInfo *ServersInfo) getAll() []*serverinfo {
	serversInfo.RLock()
	defer serversInfo.RUnlock()

	servers := make([]*serverinfo, 0, len(serversInfo.inner))
	for _, si := range serversInfo.inner {
		if si != nil {
			servers = append(servers, si)
		}
	}
	return servers
}

func (serversInfo *ServersInfo) getOne() (serverInfo *serverinfo) {
	serversInfo.RLock()
	defer serversInfo.RUnlock()

	serversCount := len(serversInfo.inner)
	if serversCount <= 0 {
		return nil
	}
	candidate := rand.Intn(xdns.Min(serversCount, 5))
	i := 0
	for _, si := range serversInfo.inner {
		if i == candidate {
			log.V("dnscrypt: candidate [%v]", si) // may be nil?
			serverInfo = si
			break
		}
		i++
	}

	return serverInfo
}

func (serversInfo *ServersInfo) get(name string) *serverinfo {
	serversInfo.RLock()
	defer serversInfo.RUnlock()
	serversCount := len(name)
	if serversCount <= 0 {
		return nil
	}
	return serversInfo.inner[name]
}

func (serversInfo *ServersInfo) unregisterServer(name string) (int, error) {
	serversInfo.Lock()
	defer serversInfo.Unlock()

	delete(serversInfo.registeredServers, name)
	delete(serversInfo.inner, name)

	return len(serversInfo.registeredServers), nil
}

func (serversInfo *ServersInfo) registerServer(name string, stamp stamps.ServerStamp) {
	newRegisteredServer := registeredserver{name: name, stamp: stamp}
	serversInfo.Lock()
	defer serversInfo.Unlock()

	serversInfo.registeredServers[name] = newRegisteredServer
}

func (serversInfo *ServersInfo) refresh(proxy *DcMulti) ([]string, error) {
	log.D("dnscrypt: refreshing certificates")
	var liveServers []string
	var err error
	for _, registeredServer := range serversInfo.registeredServers {
		if err = serversInfo.refreshServer(proxy, registeredServer.name, registeredServer.stamp); err == nil {
			liveServers = append(liveServers, registeredServer.name)
		} else {
			log.E("dnscrypt: %s not a live server? %w", registeredServer.stamp, err)
		}
	}
	return liveServers, err
}

func (serversInfo *ServersInfo) refreshServer(proxy *DcMulti, name string, stamp stamps.ServerStamp) error {
	newServer, err := fetchServerInfo(proxy, name, stamp)
	if err != nil {
		return err
	}
	if name != newServer.Name {
		return fmt.Errorf("[%s] != [%s]", name, newServer.Name)
	}

	serversInfo.Lock()
	serversInfo.inner[name] = &newServer
	serversInfo.registeredServers[name] = registeredserver{name: name, stamp: stamp}
	serversInfo.Unlock()

	return nil
}

func fetchServerInfo(proxy *DcMulti, name string, stamp stamps.ServerStamp) (serverinfo, error) {
	if stamp.Proto == stamps.StampProtoTypeDNSCrypt {
		return fetchDNSCryptServerInfo(proxy, name, stamp)
	} else if stamp.Proto == stamps.StampProtoTypeDoH {
		return fetchDoHServerInfo(proxy, name, stamp)
	}
	return serverinfo{}, errors.New("unsupported protocol")
}

func fetchDNSCryptServerInfo(proxy *DcMulti, name string, stamp stamps.ServerStamp) (serverinfo, error) {
	if len(stamp.ServerPk) != ed25519.PublicKeySize {
		serverPk, err := hex.DecodeString(strings.Replace(string(stamp.ServerPk), ":", "", -1))
		if err != nil || len(serverPk) != ed25519.PublicKeySize {
			return serverinfo{}, fmt.Errorf("unsupported public key for [%s]: [%s]", name, stamp.ServerPk)
		}
		log.W("dnscrypt: public key [%s] shouldn't be hex-encoded any more", string(stamp.ServerPk))
		stamp.ServerPk = serverPk
	}

	// relayudpaddrs and relaytcpaddrs may be nil, even if err == nil
	relayudpaddrs, relaytcpaddrs := route(proxy)
	// iff tcp relay is unset, unset udp relay too
	if len(relaytcpaddrs) <= 0 {
		relayudpaddrs = nil
	}
	// note: relays are not used to fetch certs due to multiple issues reported by users
	certInfo, err := fetchCurrentDNSCryptCert(proxy, &name, stamp.ServerPk, stamp.ServerAddrStr, stamp.ProviderName)
	if err != nil {
		return serverinfo{}, err
	}
	var tcpaddr *net.TCPAddr
	var udpaddr *net.UDPAddr
	s, p := hostport(stamp.ServerAddrStr)
	if ips, err := dialers.Resolve(s); err == nil && len(ips) > 0 {
		ipp := netip.AddrPortFrom(ips[0], p)
		tcpaddr = net.TCPAddrFromAddrPort(ipp)
		udpaddr = net.UDPAddrFromAddrPort(ipp)
	} else {
		return serverinfo{}, fmt.Errorf("dnscrypt: no ips for [%s]: %v", s, err)
	}
	if udpaddr == nil || tcpaddr == nil {
		return serverinfo{}, errNoServers
	}
	px := proxy.proxies
	var relay ipn.Proxy
	if px != nil {
		relay, _ = px.ProxyFor(name)
	}
	dialer := protect.MakeNsRDial(name, proxy.ctl)
	si := serverinfo{
		Proto:              stamps.StampProtoTypeDNSCrypt,
		MagicQuery:         certInfo.MagicQuery,
		ClientPubKey:       &proxy.proxyPublicKey,
		ServerPk:           certInfo.ServerPk,
		SharedKey:          certInfo.SharedKey,
		CryptoConstruction: certInfo.CryptoConstruction,
		HostName:           stamp.ProviderName,
		Name:               name,
		UDPAddr:            udpaddr,
		TCPAddr:            tcpaddr,
		RelayTCPAddrs:      relaytcpaddrs,
		RelayUDPAddrs:      relayudpaddrs,
		proxies:            px,
		relay:              relay,
		dialer:             dialer,
		est:                core.NewP50Estimator(),
	}
	log.I("dnscrypt: (%s) setup: %s; anonrelay? %t, proxy? %t", name, si.HostName, relaytcpaddrs != nil, relay != nil)
	return si, nil
}

func fetchDoHServerInfo(proxy *DcMulti, name string, stamp stamps.ServerStamp) (serverinfo, error) {
	// FIXME: custom ip-address, user-certs, and cert-pinning not supported
	return serverinfo{}, errors.New("unsupported protocol")
}

func route(proxy *DcMulti) (udpaddrs []*net.UDPAddr, tcpaddrs []*net.TCPAddr) {
	relays := proxy.routes
	if len(relays) <= 0 { // no err, no relays
		return
	}

	udpaddrs = make([]*net.UDPAddr, 0, len(relays))
	tcpaddrs = make([]*net.TCPAddr, 0, len(relays))
	for _, rr := range relays {
		var rrstamp *stamps.ServerStamp
		if len(rr) == 0 {
			log.W("dnscrypt: route: skip empty relay")
			continue
		} else if relayStamp, serr := stamps.NewServerStampFromString(rr); serr == nil {
			rrstamp = &relayStamp
		}

		if rrstamp == nil {
			rrstamp = &stamps.ServerStamp{
				ServerAddrStr: rr, // may be a hostname or ip-address
				Proto:         stamps.StampProtoTypeDNSCryptRelay,
			}
		}

		host, port := hostport(rrstamp.ServerAddrStr)
		if rrstamp != nil && (rrstamp.Proto == stamps.StampProtoTypeDNSCrypt ||
			rrstamp.Proto == stamps.StampProtoTypeDNSCryptRelay) {
			if ips, err := dialers.Resolve(host); err == nil && len(ips) > 0 {
				ipp := netip.AddrPortFrom(ips[0], port) // TODO: randomize?
				tcpaddrs = append(tcpaddrs, net.TCPAddrFromAddrPort(ipp))
				udpaddrs = append(udpaddrs, net.UDPAddrFromAddrPort(ipp))
			} else {
				log.W("dnscrypt: route: zero ips for relay [%s] for server [%s]; err [%v]", rr, host, err)
			}
		} else {
			log.W("dnscrypt: route: invalid relay [%s]", rr)
		}
	}
	return
}

func hostport(x string) (string, uint16) {
	s, port, err := net.SplitHostPort(x)
	if err != nil || len(port) <= 0 {
		log.W("dnscrypt: host-port og(%s); err? %v", x, err)
		s = x
		port = "443" // use default port
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		p = 443 // use default port
	}
	return s, uint16(p)
}

func (s *serverinfo) String() string {
	serverid := s.ID()
	servername := s.GetAddr()
	serveraddr := "notcp"
	relayaddr := "norelay"
	if s.TCPAddr != nil {
		serveraddr = s.TCPAddr.String()
	}
	if s.RelayTCPAddrs != nil {
		relayaddr = chooseAny(s.RelayTCPAddrs).String()
	}

	return serverid + ":" + servername + "/" + serveraddr + "<=>" + relayaddr
}

func (s *serverinfo) ID() string {
	return s.Name
}

func (s *serverinfo) Type() string {
	return dnsx.DNSCrypt
}

func (s *serverinfo) Query(network string, q []byte, summary *x.DNSSummary) (r []byte, err error) {
	r, err = resolve(network, q, s, summary)
	s.status = summary.Status

	if s.est != nil {
		s.est.Add(summary.Latency)
	}

	return
}

func (s *serverinfo) P50() int64 {
	if s.est != nil {
		return s.est.Get()
	} else {
		return 0
	}
}

func (s *serverinfo) GetAddr() string {
	return s.HostName
}

func (s *serverinfo) Status() int {
	return s.status
}

func (s *serverinfo) dialudp(pid string, addr *net.UDPAddr) (net.Conn, error) {
	userelay := s.relay != nil
	useproxy := len(pid) != 0 // pid == dnsx.NetNoProxy => ipn.Base
	if userelay || useproxy {
		return s.dialpx(pid, "udp", addr.String())
	}
	return s.dialer.DialUDP("udp", nil, addr)
}

func (s *serverinfo) dialtcp(pid string, addr *net.TCPAddr) (net.Conn, error) {
	userelay := s.relay != nil
	useproxy := len(pid) != 0 // pid == dnsx.NetNoProxy => ipn.Base
	if userelay || useproxy {
		return s.dialpx(pid, "tcp", addr.String())
	}
	return s.dialer.DialTCP("tcp", nil, addr)
}

func (s *serverinfo) dialpx(pid, proto string, addr string) (net.Conn, error) {
	relay := s.relay
	if relay != nil {
		// addr is always ip:port; hence protect.dialers are not needed
		return relay.Dialer().Dial(proto, addr)
	}
	pxs := s.proxies
	if pxs == nil {
		return nil, dnsx.ErrNoProxyProvider
	}
	px, err := pxs.ProxyFor(pid)
	if err == nil {
		return px.Dialer().Dial(proto, addr) // ref comment above
	}
	return nil, err
}
