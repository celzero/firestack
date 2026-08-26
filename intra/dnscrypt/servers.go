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
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"

	stamps "github.com/jedisct1/go-dnsstamps"
	"golang.org/x/crypto/ed25519"
)

type registeredserver struct {
	name  string
	stamp stamps.ServerStamp
}

type server struct {
	ctx                context.Context
	done               context.CancelFunc
	Proto              stamps.StampProtoType
	MagicQuery         [8]byte
	ClientPubKey       *[32]byte
	ServerPk           [32]byte
	SharedKey          [32]byte
	CryptoConstruction xdns.CryptoConstruction
	Name               string // id of the server
	HostName           string
	UDPAddr            net.UDPAddr
	TCPAddr            net.TCPAddr
	proxies            ipn.ProxyProvider        // proxy-provider, may be nil
	relay              string                   // proxy relay to use, may be nil
	relayref           *core.WeakRef[ipn.Proxy] // preset ref to relay proxy, if any
	est                core.P2QuantileEstimator

	// fields below are mutable

	// populated later; see proxy.refreshRoutes()
	RelayUDPAddrs atomic.Pointer[[]net.UDPAddr] // anonymous relays, if any
	RelayTCPAddrs atomic.Pointer[[]net.TCPAddr] // anonymous relays, if any

	status atomic.Int32 // status of the last query
}

var _ dnsx.Transport = (*server)(nil)

type ServersInfo struct {
	sync.RWMutex
	inner             map[string]*server
	registeredServers map[string]registeredserver
}

// newServersInfo returns a new servers-info object
func newServersInfo() *ServersInfo {
	return &ServersInfo{
		registeredServers: make(map[string]registeredserver),
		inner:             make(map[string]*server),
	}
}

func (serversInfo *ServersInfo) len() int {
	serversInfo.RLock()
	defer serversInfo.RUnlock()

	return len(serversInfo.registeredServers)
}

func (serversInfo *ServersInfo) getAll() []*server {
	serversInfo.RLock()
	defer serversInfo.RUnlock()

	servers := make([]*server, 0)
	for _, si := range serversInfo.inner {
		if si != nil {
			servers = append(servers, si)
		}
	}
	if settings.Debug {
		log.V("dnscrypt: getAll: servers [%d/%d]", len(servers), len(serversInfo.inner))
	}
	return servers
}

func (serversInfo *ServersInfo) getOne() (serverInfo *server) {
	serversInfo.RLock()
	defer serversInfo.RUnlock()

	if len(serversInfo.inner) <= 0 {
		return nil
	}

	// Go map iteration is random. Return the first healthy server encountered.
	for _, si := range serversInfo.inner {
		if si != nil && dnsx.WillErr(si) == nil {
			if settings.Debug {
				log.V("dnscrypt: candidate [%v]", si)
			}
			return si
		}
	}

	return nil
}

func (serversInfo *ServersInfo) get(name string) *server {
	serversInfo.RLock()
	defer serversInfo.RUnlock()
	if len(name) <= 0 {
		return nil
	}
	return serversInfo.inner[name] // may be nil
}

func (serversInfo *ServersInfo) unregisterServer(name string) (int, error) {
	serversInfo.Lock()
	defer serversInfo.Unlock()

	if si, ok := serversInfo.inner[name]; ok {
		go si.Stop()
	}

	delete(serversInfo.registeredServers, name)
	delete(serversInfo.inner, name)

	return len(serversInfo.registeredServers), nil
}

func (serversInfo *ServersInfo) registerServer(name string, stamp stamps.ServerStamp) {
	serversInfo.Lock()
	defer serversInfo.Unlock()

	serversInfo.registeredServers[name] = registeredserver{name: name, stamp: stamp}
}

func (serversInfo *ServersInfo) refresh(proxy *DcMulti) ([]string, error) {
	if settings.Debug {
		log.D("dnscrypt: refreshing certificates")
	}
	var liveServers []string
	var errs []error

	// Get a snapshot of registered servers under lock to prevent race conditions
	serversInfo.RLock()
	copied := make(map[string]registeredserver)
	maps.Copy(copied, serversInfo.registeredServers)
	serversInfo.RUnlock()

	for _, registeredServer := range copied {
		if _, err := serversInfo.refreshServer(proxy, registeredServer.name, registeredServer.stamp); err == nil {
			liveServers = append(liveServers, registeredServer.name)
		} else {
			log.E("dnscrypt: %s not a live server? %w", registeredServer.stamp, err)
			errs = append(errs, err)
		}
	}
	// Only return an error if no servers are live; individual failures are logged.
	if len(liveServers) <= 0 {
		return liveServers, core.OneErr(core.JoinErr(errs...), errNoServers)
	}
	return liveServers, nil
}

func (serversInfo *ServersInfo) refreshServer(proxy *DcMulti, name string, stamp stamps.ServerStamp) (*server, error) {
	newServer, err := fetchServerInfo(proxy, name, stamp)
	if err != nil {
		return nil, err
	}
	if name != newServer.Name {
		return nil, fmt.Errorf("[%s] != [%s]", name, newServer.Name)
	}

	serversInfo.Lock()
	defer serversInfo.Unlock()
	if si, ok := serversInfo.inner[name]; ok {
		go si.Stop()
	}
	serversInfo.inner[name] = newServer
	serversInfo.registeredServers[name] = registeredserver{name: name, stamp: stamp}
	return newServer, nil
}

func fetchServerInfo(proxy *DcMulti, name string, stamp stamps.ServerStamp) (*server, error) {
	switch stamp.Proto {
	case stamps.StampProtoTypeDNSCrypt:
		return fetchDNSCryptServerInfo(proxy, name, stamp)
	case stamps.StampProtoTypeDoH:
		return fetchDoHServerInfo(proxy, name, stamp)
	}
	return nil, log.EE("unsupported protocol for %s", stamp.ServerAddrStr)
}

func fetchDNSCryptServerInfo(proxy *DcMulti, name string, stamp stamps.ServerStamp) (*server, error) {
	if len(stamp.ServerPk) != ed25519.PublicKeySize {
		serverPk, err := hex.DecodeString(strings.ReplaceAll(string(stamp.ServerPk), ":", ""))
		if err != nil || len(serverPk) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("unsupported public key for [%s]: [%s]", name, stamp.ServerPk)
		}
		log.W("dnscrypt: public key [%s] shouldn't be hex-encoded any more", string(stamp.ServerPk))
		stamp.ServerPk = serverPk
	}

	// note: relays are not used to fetch certs due to multiple issues reported by users
	certInfo, err := fetchCurrentDNSCryptCert(proxy, &name, stamp.ServerPk, stamp.ServerAddrStr, stamp.ProviderName)
	if err != nil {
		return nil, err
	}
	var tcpaddr *net.TCPAddr
	var udpaddr *net.UDPAddr
	s, p := hostport(&stamp)
	if ips := dialers.For(s); len(ips) > 0 {
		ipp := netip.AddrPortFrom(ips[0], p)
		tcpaddr = net.TCPAddrFromAddrPort(ipp)
		udpaddr = net.UDPAddrFromAddrPort(ipp)
	} else {
		return nil, fmt.Errorf("dnscrypt: no ips for [%s]", s)
	}
	if udpaddr == nil || tcpaddr == nil {
		return nil, log.EE("%v for %s", errNoServers, stamp.ServerAddrStr)
	}
	px := proxy.proxies
	var relay string
	var relayref *core.WeakRef[ipn.Proxy]
	if px != nil {
		x, _ := px.ProxyFor(name)
		if x != nil {
			relay = x.ID()
			if ref, rerr := px.ProxyRef("relay.dc."+name, relay); rerr == nil {
				relayref = ref
			}
		}
	}

	ctx, done := context.WithCancel(proxy.ctx)
	si := server{
		ctx:                ctx,
		done:               done,
		Proto:              stamps.StampProtoTypeDNSCrypt,
		MagicQuery:         certInfo.MagicQuery,
		ClientPubKey:       &proxy.proxyPublicKey,
		ServerPk:           certInfo.ServerPk,
		SharedKey:          certInfo.SharedKey,
		CryptoConstruction: certInfo.CryptoConstruction,
		HostName:           stamp.ProviderName,
		Name:               name,
		UDPAddr:            *udpaddr, // never nil
		TCPAddr:            *tcpaddr, // never nil
		proxies:            px,
		relay:              relay,
		relayref:           relayref,
		est:                core.NewP50Estimator(ctx),
	}
	si.status.Store(dnsx.Start)
	log.I("dnscrypt: (%s) setup: %s; anonrelay? %t, proxy? %t", name, si.HostName, len(relay) > 0, px != nil)
	return &si, nil
}

func fetchDoHServerInfo(_ *DcMulti, _ string, _ stamps.ServerStamp) (*server, error) {
	// FIXME: custom ip-address, user-certs, and cert-pinning not supported
	return nil, errors.ErrUnsupported
}

func route(proxy *DcMulti) (udpaddrs []net.UDPAddr, tcpaddrs []net.TCPAddr) {
	proxy.Lock()
	relays := proxy.routes
	proxy.Unlock()

	udpaddrs = make([]net.UDPAddr, 0)
	tcpaddrs = make([]net.TCPAddr, 0)

	if len(relays) <= 0 { // no err, no relays
		return
	}

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

		host, port := hostport(rrstamp)
		if rrstamp != nil && (rrstamp.Proto == stamps.StampProtoTypeDNSCrypt ||
			rrstamp.Proto == stamps.StampProtoTypeDNSCryptRelay) {
			if ips := dialers.For(host); len(ips) > 0 {
				ipp := netip.AddrPortFrom(ips[0], port) // TODO: randomize?
				tcpaddrs = append(tcpaddrs, *net.TCPAddrFromAddrPort(ipp))
				udpaddrs = append(udpaddrs, *net.UDPAddrFromAddrPort(ipp))
			} else {
				log.W("dnscrypt: route: zero ips for relay [%s] for server [%s]", rr, host)
			}
		} else {
			log.W("dnscrypt: route: invalid relay [%s]", rr)
		}
	}
	return
}

func hostport(stamp *stamps.ServerStamp) (string, uint16) {
	if stamp == nil {
		return "", 0
	}
	x := stamp.ServerAddrStr
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

func (s *server) String() string {
	if s == nil {
		return "<nil>"
	}

	serverid := s.ID()
	servername := s.getAddr()
	serveraddr := "notcp"
	relayaddr := "norelay"
	serveraddr = s.TCPAddr.String()
	if a := s.RelayTCPAddrs.Load(); a != nil && len(*a) > 0 {
		relayaddr = (*a)[0].String()
	}

	return serverid + ":" + servername + "/" + serveraddr + "<=>" + relayaddr
}

func (s *server) ID() string {
	return s.Name
}

func (s *server) Type() string {
	return dnsx.DNSCrypt
}

func (s *server) Query(network string, q *dns.Msg, smm *x.DNSSummary) (r *dns.Msg, err error) {
	r, err = resolve(network, q, s, smm)
	s.status.Store(smm.Status)

	if s.est != nil {
		s.est.Add(smm.Latency)
	}
	if err != nil {
		smm.Msg = err.Error()
	}

	return
}

func (s *server) P50() int64 {
	if s.est != nil {
		return s.est.Get()
	} else {
		return 0
	}
}

func (s *server) GetAddr() string {
	return s.getAddr()
}

func (s *server) getAddr() string {
	return s.HostName
}

func (s *server) Measure(mid string, n, seconds int32) *x.DNSMeasurement {
	return dnsx.Perf(s, mid, n, seconds)
}

func (s *server) GetRelay() x.Proxy {
	return s.getRelay()
}

func (s *server) Relaying() bool {
	return len(s.relay) > 0
}

func (s *server) getRelay() ipn.Proxy {
	if s.relayref == nil {
		return nil
	}
	if p, valid := s.relayref.Get(); valid {
		return p
	}
	return nil
}

func (s *server) IPPorts() []netip.AddrPort {
	if relay := s.RelayUDPAddrs.Load(); relay != nil && len(*relay) > 0 {
		return addr2ipp(*relay...)
	}
	return addr2ipp(s.UDPAddr)
}

func (s *server) Status() int32 {
	if px := s.getRelay(); px != nil {
		if y, to := dnsx.OverrideStatusFrom(px); y {
			return to
		}
	}
	st := s.status.Load()
	if st == dnsx.Paused {
		// paused status is a pseudo state dependent on underlying relay
		// or requested pid, not a permanent state of this transport.
		s.status.CompareAndSwap(st, dnsx.Unpaused)
		return dnsx.Unpaused
	}
	return st
}

func (s *server) Stop() error {
	if s != nil {
		s.status.Store(dnsx.DEnd)
		s.done() // also call into unregister
	}
	return nil
}

func (s *server) dialudp(pid string, addr *net.UDPAddr) (net.Conn, error) {
	userelay := s.GetRelay() != nil
	useproxy := len(pid) != 0 // pid == dnsx.NetNoProxy => ipn.Base
	if userelay || useproxy {
		return s.dialpx(pid, "udp", addr.String())
	}
	return nil, dnsx.ErrNoProxyProvider
}

func (s *server) dialtcp(pid string, addr *net.TCPAddr) (net.Conn, error) {
	userelay := s.GetRelay() != nil
	useproxy := len(pid) != 0 // pid == dnsx.NetNoProxy => ipn.Base
	if userelay || useproxy {
		return s.dialpx(pid, "tcp", addr.String())
	}
	return nil, dnsx.ErrNoProxyProvider
}

func (s *server) dialpx(pid, proto string, addr string) (net.Conn, error) {
	relay := s.getRelay()
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

// TODO: choose proxy w/ proto "tcp" or "udp"
func (s *server) chooseProxy(fid string, pids ...string) string {
	return dnsx.ChooseHealthyProxy(fid+" dnscrypt."+s.ID(), dnsx.NetTypeTCP, s.IPPorts(), pids, s.proxies)
}

func addr2ipp(u ...net.UDPAddr) (ipps []netip.AddrPort) {
	if len(u) <= 0 {
		return dnsx.NoIPPort
	}
	for _, x := range u {
		ipps = append(ipps, x.AddrPort())
	}
	return // may be nil
}

func newServer(proxy *DcMulti, name string, stamp stamps.ServerStamp) (*server, error) {
	if len(stamp.ServerPk) != ed25519.PublicKeySize {
		serverPk, err := hex.DecodeString(strings.ReplaceAll(string(stamp.ServerPk), ":", ""))
		if err != nil || len(serverPk) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("unsupported public key for [%s]: [%s]", name, stamp.ServerPk)
		}
		stamp.ServerPk = serverPk
	}
	certInfo, err := fetchCurrentDNSCryptCert(proxy, &name, stamp.ServerPk, stamp.ServerAddrStr, stamp.ProviderName)
	if err != nil {
		return nil, err
	}
	s, p := hostport(&stamp)
	var tcpaddr *net.TCPAddr
	var udpaddr *net.UDPAddr
	if ips := dialers.For(s); len(ips) > 0 {
		ipp := netip.AddrPortFrom(ips[0], p)
		tcpaddr = net.TCPAddrFromAddrPort(ipp)
		udpaddr = net.UDPAddrFromAddrPort(ipp)
	} else {
		return nil, fmt.Errorf("dnscrypt: no ips for [%s]", s)
	}
	if udpaddr == nil || tcpaddr == nil {
		return nil, log.EE("%v for %s", errNoServers, stamp.ServerAddrStr)
	}

	ctx, done := context.WithCancel(proxy.ctx)
	si := server{
		ctx:                ctx,
		done:               done,
		Proto:              stamps.StampProtoTypeDNSCrypt,
		MagicQuery:         certInfo.MagicQuery,
		ClientPubKey:       &proxy.proxyPublicKey,
		ServerPk:           certInfo.ServerPk,
		SharedKey:          certInfo.SharedKey,
		CryptoConstruction: certInfo.CryptoConstruction,
		HostName:           stamp.ProviderName,
		Name:               name,
		UDPAddr:            *udpaddr, // never nil
		TCPAddr:            *tcpaddr, // never nil
		proxies:            proxy.proxies,
		relay:              "",  // no relays for free-standing transports
		relayref:           nil, // ditto
		est:                core.NewP50Estimator(ctx),
	}
	si.status.Store(dnsx.Start)
	log.I("dnscrypt: (%s) setup(free-standing): %s", name, si.HostName)
	return &si, nil
}
