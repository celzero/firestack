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
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/xdns"

	stamps "github.com/jedisct1/go-dnsstamps"
	"golang.org/x/crypto/ed25519"
)

type RegisteredServer struct {
	name  string
	stamp stamps.ServerStamp
}

var _ dnsx.Transport = &(ServerInfo{})

type ServerInfo struct {
	dnsx.Transport
	Proto              stamps.StampProtoType
	MagicQuery         [8]byte
	ClientPubKey       *[32]byte
	ServerPk           [32]byte
	SharedKey          [32]byte
	CryptoConstruction xdns.CryptoConstruction
	Name               string
	Timeout            time.Duration
	URL                *url.URL
	HostName           string
	UDPAddr            *net.UDPAddr
	TCPAddr            *net.TCPAddr
	RelayUDPAddr       *net.UDPAddr
	RelayTCPAddr       *net.TCPAddr
	status             int
	est                core.P2QuantileEstimator
}

type ServersInfo struct {
	sync.RWMutex
	inner             map[string]*ServerInfo
	registeredServers map[string]RegisteredServer
	lbStrategy        LBStrategy
}

type LBStrategy interface {
	getCandidate(serversCount int) int
}

type LBStrategyP2 struct{}

func (LBStrategyP2) getCandidate(serversCount int) int {
	return rand.Intn(xdns.Min(serversCount, 5))
}

var DefaultLBStrategy = LBStrategyP2{}

func (serversInfo *ServersInfo) getOne() (serverInfo *ServerInfo) {
	serversInfo.RLock()
	defer serversInfo.RUnlock()

	serversCount := len(serversInfo.inner)
	if serversCount <= 0 {
		return nil
	}
	candidate := serversInfo.lbStrategy.getCandidate(serversCount)
	i := 0
	for _, si := range serversInfo.inner {
		if i == candidate {
			serverInfo = si
			break
		}
		i++
	}
	log.D("Using candidate [%s]", (*serverInfo).Name)

	return serverInfo
}

func (serversInfo *ServersInfo) get(name string) *ServerInfo {
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
	newRegisteredServer := RegisteredServer{name: name, stamp: stamp}
	serversInfo.Lock()
	defer serversInfo.Unlock()

	serversInfo.registeredServers[name] = newRegisteredServer
}

func (serversInfo *ServersInfo) refresh(proxy *Proxy) ([]string, error) {
	log.D("Refreshing certificates")
	var liveServers []string
	var err error
	for _, registeredServer := range serversInfo.registeredServers {
		if err = serversInfo.refreshServer(proxy, registeredServer.name, registeredServer.stamp); err == nil {
			liveServers = append(liveServers, registeredServer.name)
		} else {
			log.E("%s not a live server? %w", registeredServer.stamp, err)
		}
	}
	return liveServers, err
}

func (serversInfo *ServersInfo) refreshServer(proxy *Proxy, name string, stamp stamps.ServerStamp) error {
	newServer, err := fetchServerInfo(proxy, name, stamp)
	if err != nil {
		return err
	}
	if name != newServer.Name {
		return fmt.Errorf("[%s] != [%s]", name, newServer.Name)
	}

	serversInfo.Lock()
	serversInfo.inner[name] = &newServer
	serversInfo.registeredServers[name] = RegisteredServer{name: name, stamp: stamp}
	serversInfo.Unlock()

	return nil
}

func fetchServerInfo(proxy *Proxy, name string, stamp stamps.ServerStamp) (ServerInfo, error) {
	if stamp.Proto == stamps.StampProtoTypeDNSCrypt {
		return fetchDNSCryptServerInfo(proxy, name, stamp)
	} else if stamp.Proto == stamps.StampProtoTypeDoH {
		return fetchDoHServerInfo(proxy, name, stamp)
	}
	return ServerInfo{}, errors.New("unsupported protocol")
}

func fetchDNSCryptServerInfo(proxy *Proxy, name string, stamp stamps.ServerStamp) (ServerInfo, error) {
	if len(stamp.ServerPk) != ed25519.PublicKeySize {
		serverPk, err := hex.DecodeString(strings.Replace(string(stamp.ServerPk), ":", "", -1))
		if err != nil || len(serverPk) != ed25519.PublicKeySize {
			return ServerInfo{}, fmt.Errorf("unsupported public key for [%s]: [%s]", name, stamp.ServerPk)
		}
		log.W("Public key [%s] shouldn't be hex-encoded any more", string(stamp.ServerPk))
		stamp.ServerPk = serverPk
	}

	relayUDPAddr, relayTCPAddr, err := route(proxy, name)
	if err != nil {
		return ServerInfo{}, err
	}
	// note: relays are not used to fetch certs due to multiple issues reported by users
	certInfo, relayTCPAddr, err := FetchCurrentDNSCryptCert(proxy, &name, stamp.ServerPk, stamp.ServerAddrStr, stamp.ProviderName, relayTCPAddr)
	if err != nil {
		return ServerInfo{}, err
	}
	// iff tcp relay is unset, unset udp relay too
	if relayTCPAddr == nil {
		relayUDPAddr = nil
	}
	remoteUDPAddr, err := net.ResolveUDPAddr("udp", stamp.ServerAddrStr)
	if err != nil {
		return ServerInfo{}, err
	}
	remoteTCPAddr, err := net.ResolveTCPAddr("tcp", stamp.ServerAddrStr)
	if err != nil {
		return ServerInfo{}, err
	}
	return ServerInfo{
		Proto:              stamps.StampProtoTypeDNSCrypt,
		MagicQuery:         certInfo.MagicQuery,
		ClientPubKey:       &proxy.proxyPublicKey,
		ServerPk:           certInfo.ServerPk,
		SharedKey:          certInfo.SharedKey,
		CryptoConstruction: certInfo.CryptoConstruction,
		HostName:           stamp.ProviderName,
		Name:               name,
		Timeout:            proxy.timeout,
		UDPAddr:            remoteUDPAddr,
		TCPAddr:            remoteTCPAddr,
		RelayTCPAddr:       relayTCPAddr,
		RelayUDPAddr:       relayUDPAddr,
		est:                core.NewP50Estimator(),
	}, nil
}

func fetchDoHServerInfo(proxy *Proxy, name string, stamp stamps.ServerStamp) (ServerInfo, error) {
	// FIXME: custom ip-address, user-certs, and cert-pinning not supported
	return ServerInfo{}, errors.New("unsupported protocol")
}

func route(proxy *Proxy, name string) (udpaddr *net.UDPAddr, tcpaddr *net.TCPAddr, err error) {
	relayNames := proxy.routes
	if relayNames == nil {
		log.I("dnscrypt: No relay routes found.")
		return
	}

	var relayName string
	if len(relayNames) > 0 {
		candidate := rand.Intn(len(relayNames))
		relayName = relayNames[candidate]
	}
	var relayCandidateStamp *stamps.ServerStamp
	if len(relayName) == 0 {
		err = fmt.Errorf("route declared for [%v] but an empty relay list", name)
		return
	} else if relayStamp, err := stamps.NewServerStampFromString(relayName); err == nil {
		relayCandidateStamp = &relayStamp
	} else if _, err := net.ResolveTCPAddr("tcp", relayName); err == nil {
		relayCandidateStamp = &stamps.ServerStamp{
			ServerAddrStr: relayName,
			Proto:         stamps.StampProtoTypeDNSCryptRelay,
		}
	}
	if relayCandidateStamp == nil {
		err = fmt.Errorf("undefined relay [%v] for server [%v]", relayName, name)
		return
	}
	if relayCandidateStamp.Proto == stamps.StampProtoTypeDNSCrypt ||
		relayCandidateStamp.Proto == stamps.StampProtoTypeDNSCryptRelay {
		tcpaddr, err = net.ResolveTCPAddr("tcp", relayCandidateStamp.ServerAddrStr)
		if err == nil {
			udpaddr, err = net.ResolveUDPAddr("udp", relayCandidateStamp.ServerAddrStr)
		}
	} else {
		err = fmt.Errorf("invalid relay [%v] for server [%v]", relayName, name)
	}
	return
}

// NewServersInfo returns a new servers-info object
func NewServersInfo() ServersInfo {
	return ServersInfo{
		lbStrategy:        DefaultLBStrategy,
		registeredServers: make(map[string]RegisteredServer),
		inner:             make(map[string]*ServerInfo),
	}
}

func (s *ServerInfo) String() string {
	serverid := s.ID()
	servername := s.GetAddr()
	serveraddr := "notcp"
	relayaddr := "norelay"
	if s.TCPAddr != nil {
		serveraddr = s.TCPAddr.String()
	}
	if s.RelayTCPAddr != nil {
		relayaddr = s.RelayTCPAddr.String()
	}

	return serverid + ":" + servername + "/" + serveraddr + "<=>" + relayaddr
}

func (s *ServerInfo) ID() string {
	return s.Name
}

func (s *ServerInfo) Type() string {
	return dnsx.DNSCrypt
}

func (s *ServerInfo) Query(proto string, q []byte, summary *dnsx.Summary) (r []byte, err error) {
	cantruncate := proto == dnsx.NetTypeUDP
	r, err = resolve(q, s, summary, cantruncate)
	s.status = summary.Status
	if s.est != nil {
		s.est.Add(summary.Latency)
	}
	return
}

func (s *ServerInfo) P50() int64 {
	if s.est != nil {
		return s.est.Get()
	} else {
		return 0
	}
}

func (s *ServerInfo) GetAddr() string {
	return s.HostName
}

func (s *ServerInfo) Status() int {
	return s.status
}
