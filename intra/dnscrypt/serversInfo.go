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

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/xdns"

	stamps "github.com/jedisct1/go-dnsstamps"
	"golang.org/x/crypto/ed25519"
)

type RegisteredServer struct {
	name        string
	stamp       stamps.ServerStamp
	description string
}

type ServerInfo struct {
	Proto              stamps.StampProtoType
	MagicQuery         [8]byte
	ServerPk           [32]byte
	SharedKey          [32]byte
	CryptoConstruction xdns.CryptoConstruction
	Name               string
	Timeout            time.Duration
	URL                *url.URL
	HostName           string
	TCPAddr            *net.TCPAddr
	RelayTCPAddr       *net.TCPAddr
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
	log.Debugf("Using candidate [%s]", (*serverInfo).Name)

	return serverInfo
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
	log.Debugf("Refreshing certificates")
	var liveServers []string
	var err error
	for _, registeredServer := range serversInfo.registeredServers {
		if err = serversInfo.refreshServer(proxy, registeredServer.name, registeredServer.stamp); err == nil {
			liveServers = append(liveServers, registeredServer.name)
		}
		if err != nil {
			log.Errorf("%s not a live server? %w", registeredServer.stamp, err)
		}
	}
	return liveServers, err
}

func (serversInfo *ServersInfo) refreshServer(proxy *Proxy, name string, stamp stamps.ServerStamp) error {
	serversInfo.RLock()
	_, isNew := serversInfo.inner[name]
	serversInfo.RUnlock()

	newServer, err := fetchServerInfo(proxy, name, stamp, isNew)
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

func fetchServerInfo(proxy *Proxy, name string, stamp stamps.ServerStamp, isNew bool) (ServerInfo, error) {
	if stamp.Proto == stamps.StampProtoTypeDNSCrypt {
		return fetchDNSCryptServerInfo(proxy, name, stamp, isNew)
	} else if stamp.Proto == stamps.StampProtoTypeDoH {
		return fetchDoHServerInfo(proxy, name, stamp, isNew)
	}
	return ServerInfo{}, errors.New("Unsupported protocol")
}

func fetchDNSCryptServerInfo(proxy *Proxy, name string, stamp stamps.ServerStamp, isNew bool) (ServerInfo, error) {
	if len(stamp.ServerPk) != ed25519.PublicKeySize {
		serverPk, err := hex.DecodeString(strings.Replace(string(stamp.ServerPk), ":", "", -1))
		if err != nil || len(serverPk) != ed25519.PublicKeySize {
			return ServerInfo{}, fmt.Errorf("Unsupported public key for [%s]: [%s]", name, stamp.ServerPk)
		}
		log.Warnf("Public key [%s] shouldn't be hex-encoded any more", string(stamp.ServerPk))
		stamp.ServerPk = serverPk
	}

	relayTCPAddr, err := route(proxy, name)
	if err != nil {
		return ServerInfo{}, err
	}
	certInfo, relayTCPAddr, err := FetchCurrentDNSCryptCert(proxy, &name, proxy.mainProto, stamp.ServerPk, stamp.ServerAddrStr, stamp.ProviderName, isNew, relayTCPAddr)
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
		ServerPk:           certInfo.ServerPk,
		SharedKey:          certInfo.SharedKey,
		CryptoConstruction: certInfo.CryptoConstruction,
		Name:               name,
		Timeout:            proxy.timeout,
		TCPAddr:            remoteTCPAddr,
		RelayTCPAddr:       relayTCPAddr,
	}, nil
}

func fetchDoHServerInfo(proxy *Proxy, name string, stamp stamps.ServerStamp, isNew bool) (ServerInfo, error) {
	// FIXME: custom ip-address, user-certs, and cert-pinning not supported
	return ServerInfo{}, errors.New("Unsupported protocol")
}

func route(proxy *Proxy, name string) (*net.TCPAddr, error) {
	relayNames := proxy.routes
	if relayNames == nil {
		log.Infof("dns-crypt: No relay routes found.")
		return nil, nil
	}

	var relayName string
	if len(relayNames) > 0 {
		candidate := rand.Intn(len(relayNames))
		relayName = relayNames[candidate]
	}
	var relayCandidateStamp *stamps.ServerStamp
	if len(relayName) == 0 {
		return nil, fmt.Errorf("Route declared for [%v] but an empty relay list", name)
	} else if relayStamp, err := stamps.NewServerStampFromString(relayName); err == nil {
		relayCandidateStamp = &relayStamp
	} else if _, err := net.ResolveTCPAddr("tcp", relayName); err == nil {
		relayCandidateStamp = &stamps.ServerStamp{
			ServerAddrStr: relayName,
			Proto:         stamps.StampProtoTypeDNSCryptRelay,
		}
	}
	if relayCandidateStamp == nil {
		return nil, fmt.Errorf("Undefined relay [%v] for server [%v]", relayName, name)
	}
	if relayCandidateStamp.Proto == stamps.StampProtoTypeDNSCrypt ||
		relayCandidateStamp.Proto == stamps.StampProtoTypeDNSCryptRelay {
		relayTCPAddr, err := net.ResolveTCPAddr("tcp", relayCandidateStamp.ServerAddrStr)
		if err != nil {
			return nil, err
		}
		return relayTCPAddr, nil
	}
	return nil, fmt.Errorf("Invalid relay [%v] for server [%v]", relayName, name)
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
	return s.Name + ":" + s.HostName + "/" + s.TCPAddr.String() + "<=>" + s.RelayTCPAddr.String()
}
