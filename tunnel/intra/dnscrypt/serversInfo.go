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

	"github.com/Jigsaw-Code/outline-go-tun2socks/tunnel/intra/xdns"
	"github.com/eycorsican/go-tun2socks/common/log"

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
	inner             []*ServerInfo
	registeredServers []RegisteredServer
	lbStrategy        LBStrategy
}

type LBStrategy interface {
	getCandidate(serversCount int) int
}

type LBStrategyP2 struct{}

func (LBStrategyP2) getCandidate(serversCount int) int {
	return rand.Intn(xdns.Min(serversCount, 2))
}

var DefaultLBStrategy = LBStrategyP2{}

func (serversInfo *ServersInfo) shuffle() {
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(serversInfo.inner), func(i, j int) {
		serversInfo.inner[i], serversInfo.inner[j] = serversInfo.inner[j], serversInfo.inner[i]
	})
}

func (serversInfo *ServersInfo) getOne() *ServerInfo {
	serversInfo.RLock()
	defer serversInfo.RUnlock()

	serversCount := len(serversInfo.inner)
	if serversCount <= 0 {
		return nil
	}
	serversInfo.shuffle()
	candidate := serversInfo.lbStrategy.getCandidate(serversCount)
	serverInfo := serversInfo.inner[candidate]
	log.Debugf("Using candidate [%s]", (*serverInfo).Name)

	return serverInfo
}

func (serversInfo *ServersInfo) unregisterServer(name string) (int, error) {
	serversInfo.Lock()
	defer serversInfo.Unlock()

	var l int = len(serversInfo.registeredServers)
	if l <= 0 {
		return 0, errors.New("zero registered servers")
	}

	var i int = 0
	for _, s := range serversInfo.registeredServers {
		if s.name != name {
			serversInfo.registeredServers[i] = s
			i++
		}
	}
	var j int = 0
	for _, s := range serversInfo.inner {
		if s.Name != name {
			serversInfo.inner[j] = s
			j++
		}
	}

	serversInfo.registeredServers = serversInfo.registeredServers[:i]
	serversInfo.inner = serversInfo.inner[:j]

	return l - i, nil
}

func (serversInfo *ServersInfo) registerServer(name string, stamp stamps.ServerStamp) {
	newRegisteredServer := RegisteredServer{name: name, stamp: stamp}
	serversInfo.Lock()
	defer serversInfo.Unlock()
	for i, oldRegisteredServer := range serversInfo.registeredServers {
		if oldRegisteredServer.name == name {
			serversInfo.registeredServers[i] = newRegisteredServer
			return
		}
	}
	serversInfo.registeredServers = append(serversInfo.registeredServers, newRegisteredServer)
}

func (serversInfo *ServersInfo) refresh(proxy *Proxy) ([]string, error) {
	log.Debugf("Refreshing certificates")
	serversInfo.RLock()
	registeredServers := serversInfo.registeredServers
	serversInfo.RUnlock()
	var liveServers []string
	var err error
	for _, registeredServer := range registeredServers {
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
	isNew := true
	for _, oldServer := range serversInfo.inner {
		if oldServer.Name == name {
			isNew = false
			break
		}
	}
	serversInfo.RUnlock()

	newServer, err := fetchServerInfo(proxy, name, stamp, isNew)
	if err != nil {
		return err
	}
	if name != newServer.Name {
		return fmt.Errorf("[%s] != [%s]", name, newServer.Name)
	}

	// update if not a new server
	isNew = true
	serversInfo.Lock()
	for i, oldServer := range serversInfo.inner {
		if oldServer.Name == name {
			serversInfo.inner[i] = &newServer
			isNew = false
			break
		}
	}

	// append if new server
	if isNew {
		serversInfo.inner = append(serversInfo.inner, &newServer)
		serversInfo.registeredServers = append(serversInfo.registeredServers, RegisteredServer{name: name, stamp: stamp})
	}
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
	return ServersInfo{lbStrategy: DefaultLBStrategy, registeredServers: make([]RegisteredServer, 0)}
}

func (s *ServerInfo) String() string {
	return s.Name + ":" + s.HostName + "/" + s.TCPAddr.String() + "<=>" + s.RelayTCPAddr.String()
}
