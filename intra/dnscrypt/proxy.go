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
	crypto_rand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/xdns"

	clocksmith "github.com/jedisct1/go-clocksmith"
	stamps "github.com/jedisct1/go-dnsstamps"
	"github.com/k-sone/critbitgo"
	"golang.org/x/crypto/curve25519"
)

type Proxy struct {
	dnsx.TransportMult
	sync.RWMutex
	undelegatedSet               *critbitgo.Trie
	proxyPublicKey               [32]byte
	proxySecretKey               [32]byte
	serversInfo                  ServersInfo
	timeout                      time.Duration
	certRefreshDelay             time.Duration
	certRefreshDelayAfterFailure time.Duration
	certIgnoreTimestamp          bool
	mainProto                    string
	registeredServers            map[string]RegisteredServer
	routes                       []string
	liveServers                  []string
	sigterm                      context.CancelFunc
	lastStatus                   int
	lastAddr                     string
}

var (
	errNoCert = errors.New("dnscrypt: error refreshing cert")
)

func exchangeWithTCPServer(serverInfo *ServerInfo, sharedKey *[32]byte, encryptedQuery []byte, clientNonce []byte) ([]byte, error) {
	upstreamAddr := serverInfo.TCPAddr
	if serverInfo.RelayTCPAddr != nil {
		upstreamAddr = serverInfo.RelayTCPAddr
	}
	var pc net.Conn
	pc, err := net.DialTCP("tcp", nil, upstreamAddr)
	if err != nil {
		log.Errorf("failed to dial %s upstream because %v", serverInfo.String(), err)
		return nil, err
	}
	defer pc.Close()
	if err := pc.SetDeadline(time.Now().Add(serverInfo.Timeout)); err != nil {
		log.Errorf("failed to set timeout because %v", err)
		return nil, err
	}
	if serverInfo.RelayTCPAddr != nil {
		prepareForRelay(serverInfo.TCPAddr.IP, serverInfo.TCPAddr.Port, &encryptedQuery)
	}
	encryptedQuery, err = xdns.PrefixWithSize(encryptedQuery)
	if err != nil {
		log.Errorf("failed prefix(encrypted-query) from %s because %v", serverInfo.String(), err)
		return nil, err
	}
	if _, err := pc.Write(encryptedQuery); err != nil {
		log.Errorf("failed to write to remote-addr at %s because %v", serverInfo.String(), err)
		return nil, err
	}
	encryptedResponse, err := xdns.ReadPrefixed(&pc)
	if err != nil {
		log.Errorf("failed to read(encrypted-response) from %s because %v", serverInfo.String(), err)
		return nil, err
	}
	return Decrypt(serverInfo, sharedKey, encryptedResponse, clientNonce)
}

func prepareForRelay(ip net.IP, port int, eq *[]byte) {
	anonymizedDNSHeader := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00}
	relayedQuery := append(anonymizedDNSHeader, ip.To16()...)
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[0:2], uint16(port))
	relayedQuery = append(relayedQuery, tmp[:]...)
	relayedQuery = append(relayedQuery, *eq...)
	*eq = relayedQuery
}

func query(q []byte, si *ServerInfo, trunc bool) (r []byte, qerr error) {
	return queryServer(q, si, trunc)
}

func queryServer(packet []byte, serverInfo *ServerInfo, truncate bool) (response []byte, qerr error) {
	if len(packet) < xdns.MinDNSPacketSize {
		log.Warnf("DNS query size too short, cannot process dnscrypt query.")
		qerr = dnsx.NewBadQueryError(fmt.Errorf("dnscrypt query size too short"))
		return
	}

	intercept := NewIntercept()
	// serverName := "-"
	// needsEDNS0Padding = (serverInfo.Proto == stamps.StampProtoTypeDoH || serverInfo.Proto == stamps.StampProtoTypeTLS)
	needsEDNS0Padding := false

	query, err := intercept.HandleRequest(packet, needsEDNS0Padding)
	state := intercept.state

	saction := state.action
	sr := state.response
	if err != nil || saction == ActionDrop {
		log.Errorf("ActionDrop or err on request %w", err)
		qerr = dnsx.NewBadQueryError(err)
		return
	}
	if saction == ActionSynth {
		if sr != nil {
			log.Debugf("send intercepted synth response")
			response, err = sr.PackBuffer(response)
			// XXX: when the query is blocked and pack-buffer fails
			// doh falls back to forwarding the query instead.
			if err != nil {
				qerr = dnsx.NewBadResponseQueryError(err)
			}
			return
		}
		log.Warnf("missing synth response, forwarding query...")
	}
	if len(query) < xdns.MinDNSPacketSize {
		err = errors.New("dns query size too short, drop dnscrypt query")
		qerr = dnsx.NewBadQueryError(err)
		return
	}
	if len(query) > xdns.MaxDNSPacketSize {
		err = errors.New("dns query size too large, drop dnscrypt query")
		qerr = dnsx.NewBadQueryError(err)
		return
	}

	if serverInfo == nil {
		err = errors.New("server-info nil, drop dnscrypt query")
		qerr = dnsx.NewInternalQueryError(err)
		return
	}

	if serverInfo.Proto == stamps.StampProtoTypeDNSCrypt {
		sharedKey, encryptedQuery, clientNonce, err := Encrypt(serverInfo, query)

		if err != nil {
			log.Warnf("Encryption failure with dnscrypt query to %s.", serverInfo.String())
			qerr = dnsx.NewInternalQueryError(err)
			return
		}

		response, err = exchangeWithTCPServer(serverInfo, sharedKey, encryptedQuery, clientNonce)

		if err != nil {
			log.Warnf("dnscrypt query exchange with %s failed: %v", serverInfo.String(), err)
			qerr = dnsx.NewSendFailedQueryError(err)
			return
		}
	} else if serverInfo.Proto == stamps.StampProtoTypeDoH {
		// FIXME: implement
		qerr = dnsx.NewSendFailedQueryError(errors.New("doh not supported with dnscrypt proxy"))
		return
	} else {
		qerr = dnsx.NewTransportQueryError(fmt.Errorf("dnscrypt: unknown protocol"))
		return
	}

	if len(response) < xdns.MinDNSPacketSize || len(response) > xdns.MaxDNSPacketSize {
		log.Errorf("response packet size from %s too small or too large", serverInfo.String())
		qerr = dnsx.NewBadResponseQueryError(errors.New("response packet size too small or too big"))
		return
	}

	response, err = intercept.HandleResponse(response, truncate)

	if err != nil {
		log.Errorf("failed to intercept %s response %w", serverInfo.String(), err)
		qerr = dnsx.NewBadResponseQueryError(err)
		return
	}

	if state.action == ActionSynth && state.response != nil {
		response, err = state.response.PackBuffer(response)
		// XXX: when the query is blocked and pack-buffer fails doh falls
		// back to forwarding the query instead, but here we don't.
		if err != nil {
			qerr = dnsx.NewBadResponseQueryError(err)
		}
		return
	}

	return
}

// resolve resolves incoming DNS query, data
func resolve(data []byte, serverinfo *ServerInfo, s *dnsx.Summary, trunc bool) (response []byte, err error) {
	before := time.Now()
	response, err = query(data, serverinfo, trunc)
	after := time.Now()

	latency := after.Sub(before)
	status := dnsx.Complete

	var resolver string
	var relay string
	if serverinfo != nil {
		resolver = serverinfo.HostName
		if serverinfo.RelayTCPAddr != nil {
			relay = serverinfo.RelayTCPAddr.IP.String()
		}
	}

	var qerr *dnsx.QueryError
	if errors.As(err, &qerr) {
		status = qerr.Status()
		err = qerr.Unwrap()
	}

	ans := xdns.AsMsg(response)

	s.Latency = latency.Seconds()
	s.RData = xdns.GetInterestingRData(ans)
	s.RCode = xdns.Rcode(ans)
	s.RTtl = xdns.RTtl(ans)
	s.Server = resolver
	s.RelayServer = relay
	s.Status = status

	return response, err
}

// LiveServers returns csv of dnscrypt server-names currently in-use
func (proxy *Proxy) LiveTransports() string {
	if len(proxy.liveServers) <= 0 {
		return ""
	}
	return strings.Join(proxy.liveServers[:], ",")
}

func (proxy *Proxy) refreshOne(uid string) bool {
	r, ok := proxy.registeredServers[uid]
	if !ok {
		return false
	}
	if err := proxy.serversInfo.refreshServer(proxy, r.name, r.stamp); err != nil {
		log.Errorf("dnscrypt: refresh failed %s: %v", r.name, err)
		return false
	}
	return true
}

// Refresh re-registers servers
func (proxy *Proxy) Refresh() (string, error) {
	for _, registeredServer := range proxy.registeredServers {
		proxy.serversInfo.registerServer(registeredServer.name, registeredServer.stamp)
	}
	var err error
	proxy.liveServers, err = proxy.serversInfo.refresh(proxy)
	if len(proxy.liveServers) > 0 {
		proxy.certIgnoreTimestamp = false
	} else if err != nil {
		// ignore error if live-servers are around
		return "", err
	}
	return proxy.LiveTransports(), nil
}

func (proxy *Proxy) Start() (string, error) {
	if proxy.sigterm != nil {
		return "", fmt.Errorf("proxy already started")
	}
	ctx, cancel := context.WithCancel(context.Background())
	proxy.sigterm = cancel
	if _, err := crypto_rand.Read(proxy.proxySecretKey[:]); err != nil {
		return "", err
	}
	curve25519.ScalarBaseMult(&proxy.proxyPublicKey, &proxy.proxySecretKey)
	_, err := proxy.Refresh()
	if len(proxy.serversInfo.registeredServers) > 0 {
		go func(ctx context.Context) {
			for {
				select {
				case <-ctx.Done():
					log.Infof("cert refresh go rountine stopped.")
					return
				default:
					delay := proxy.certRefreshDelay
					if len(proxy.liveServers) == 0 {
						delay = proxy.certRefreshDelayAfterFailure
					}
					clocksmith.Sleep(delay)
					proxy.liveServers, _ = proxy.serversInfo.refresh(proxy)
					if len(proxy.liveServers) > 0 {
						proxy.certIgnoreTimestamp = false
					}
					runtime.GC()
				}
			}
		}(ctx)
	}
	return proxy.LiveTransports(), err
}

func (proxy *Proxy) Stop() error {
	if proxy.sigterm != nil {
		proxy.sigterm()
	}
	proxy.sigterm = nil
	return nil
}

func (proxy *Proxy) AddGateways(routescsv string) (int, error) {
	if len(routescsv) <= 0 {
		return 0, fmt.Errorf("specify atleast one dnscrypt route")
	}

	proxy.Lock()
	defer proxy.Unlock()

	r := strings.Split(routescsv, ",")
	cat := xdns.FindUnique(proxy.routes, r)
	proxy.routes = append(proxy.routes, cat...)
	return len(r), nil
}

func (proxy *Proxy) RemoveGateways(routescsv string) (int, error) {
	if len(routescsv) <= 0 {
		return 0, fmt.Errorf("specify atleast one dnscrypt route")
	}

	proxy.Lock()
	defer proxy.Unlock()

	rm := strings.Split(routescsv, ",")
	l := len(proxy.routes)
	proxy.routes = xdns.FindUnique(rm, proxy.routes)
	return l - len(proxy.routes), nil
}

func (proxy *Proxy) removeOne(uid string) int {
	proxy.Lock()
	defer proxy.Unlock()
	// TODO: handle err
	n, _ := proxy.serversInfo.unregisterServer(uid)
	delete(proxy.registeredServers, uid)
	return n
}

func (proxy *Proxy) Remove(uid string) bool {
	// may be a gateway / relay or a dnscrypt server
	proxy.removeOne(uid)
	proxy.RemoveGateways(uid)
	return true
}

func (proxy *Proxy) RemoveAll(servernamescsv string) (int, error) {
	if len(servernamescsv) <= 0 {
		return 0, fmt.Errorf("specify at least one dnscrypt resolver endpoint")
	}

	servernames := strings.Split(servernamescsv, ",")
	c := 0
	for _, name := range servernames {
		if len(name) == 0 {
			continue
		}
		c = proxy.removeOne(name)
	}

	return c, nil
}

func (proxy *Proxy) addOne(uid, rawstamp string) (string, error) {
	proxy.Lock()
	defer proxy.Unlock()

	stamp, err := stamps.NewServerStampFromString(rawstamp)
	if err != nil {
		return uid, fmt.Errorf("stamp error for [%s] def: [%v]", rawstamp, err)
	}
	if stamp.Proto == stamps.StampProtoTypeDoH {
		// TODO: Implement doh
		return uid, fmt.Errorf("DoH with DNSCrypt client not supported %s", rawstamp)
	}
	proxy.registeredServers[uid] = RegisteredServer{name: uid, stamp: stamp}
	return uid, nil
}

func (proxy *Proxy) Add(t dnsx.Transport) bool {
	// no-op
	return false
}

// AddAll registers additional dnscrypt servers
func (proxy *Proxy) AddAll(serverscsv string) (int, error) {
	if len(serverscsv) <= 0 {
		return 0, fmt.Errorf("specify at least one dnscrypt resolver endpoint")
	}

	servers := strings.Split(serverscsv, ",")
	for i, serverStampPair := range servers {
		if len(serverStampPair) == 0 {
			return i, fmt.Errorf("missing stamp for [%s]", serverStampPair)
		}
		serverStamp := strings.Split(serverStampPair, "#")
		uid := serverStamp[0]
		if uid, err := proxy.addOne(uid, serverStamp[1]); err != nil {
			return i, fmt.Errorf("dnscrypt: error adding [%s]: %v", uid, err)
		}
	}
	return len(servers), nil
}

func (p *Proxy) ID() string {
	return dnsx.DcProxy
}

func (p *Proxy) Type() string {
	return dnsx.DNSCrypt
}

func (p *Proxy) Query(network string, q []byte, summary *dnsx.Summary) (r []byte, err error) {
	cantruncate := network == dnsx.NetTypeUDP
	r, err = resolve(q, p.serversInfo.getOne(), summary, cantruncate)
	p.lastStatus = summary.Status
	p.lastAddr = summary.Server
	return
}

func (p *Proxy) GetAddr() string {
	return p.lastAddr
}

func (p *Proxy) Status() int {
	return p.lastStatus
}

// NewProxy creates a dnscrypt proxy
func NewProxy() *Proxy {
	return &Proxy{
		routes:                       nil,
		registeredServers:            make(map[string]RegisteredServer),
		undelegatedSet:               dnsx.UndelegatedDomainsTrie(),
		certRefreshDelay:             time.Duration(240) * time.Minute,
		certRefreshDelayAfterFailure: time.Duration(10 * time.Second),
		certIgnoreTimestamp:          false,
		timeout:                      time.Duration(20000) * time.Millisecond,
		mainProto:                    "tcp",
		serversInfo:                  NewServersInfo(),
		liveServers:                  nil,
		lastStatus:                   dnsx.Start,
		lastAddr:                     "",
	}
}

func NewTransport(p *Proxy, id, serverstamp string) (dnsx.Transport, error) {
	if p == nil {
		return nil, dnsx.ErrNoDcProxy
	}
	if _, err := p.addOne(id, serverstamp); err == nil {
		if ok := p.refreshOne(id); ok {
			return p.serversInfo.get(id), nil
		} else {
			return nil, errNoCert
		}
	} else {
		return nil, err
	}
}

func NewRelayTransport(p *Proxy, relaystamp string) (dnsx.Transport, error) {
	if p == nil {
		return nil, dnsx.ErrNoDcProxy
	}
	if _, err := p.AddGateways(relaystamp); err == nil {
		return p, nil
	} else {
		return nil, err
	}
}
