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

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/xdns"

	clocksmith "github.com/jedisct1/go-clocksmith"
	stamps "github.com/jedisct1/go-dnsstamps"
	"golang.org/x/crypto/curve25519"
)

// DcMulti is a dnsx.TransportMult supporting dnscrypt servers and relays
type DcMulti struct {
	sync.RWMutex
	proxyPublicKey               [32]byte
	proxySecretKey               [32]byte
	serversInfo                  ServersInfo
	certRefreshDelay             time.Duration
	certRefreshDelayAfterFailure time.Duration
	certIgnoreTimestamp          bool
	registeredServers            map[string]registeredserver
	routes                       []string
	liveServers                  []string
	proxies                      ipn.Proxies
	sigterm                      context.CancelFunc
	lastStatus                   int
	lastAddr                     string
	ctl                          protect.Controller
	dialer                       *protect.RDial
	est                          core.P2QuantileEstimator
}

var _ dnsx.TransportMult = (*DcMulti)(nil)
var timeout20s = 20000 * time.Millisecond

var (
	errNoCert          = errors.New("dnscrypt: error refreshing cert")
	errQueryTooShort   = errors.New("dnscrypt: query size too short")
	errQueryTooLarge   = errors.New("dnscrypt: query size too large")
	errNoServers       = errors.New("dnscrypt: server info nil, drop query")
	errNothing         = errors.New("dnscrypt: specify at least one resolver endpoint")
	errNoDoh           = errors.New("dnscrypt: dns-over-https not supported")
	errNoRoute         = errors.New("dnscrypt: specify atleast one route")
	errUnknownProto    = errors.New("dnscrypt: unknown protocol")
	errInvalidResponse = errors.New("dnscrypt: response too large or too small")
	errNonceUnexpected = errors.New("dnscrypt: unexpected nonce")
	errIncorrectTag    = errors.New("dnscrypt: incorrect tag")
	errIncorrectPad    = errors.New("dnscrypt: incorrect padding")
	errStarted         = errors.New("dnscrypt: already started")
	errNoConn          = errors.New("dnscrypt: no connection")
)

func udpExchange(pid string, serverInfo *serverinfo, sharedKey *[32]byte, encryptedQuery []byte, clientNonce []byte) ([]byte, error) {
	upstreamAddr := serverInfo.UDPAddr
	if serverInfo.RelayUDPAddr != nil {
		upstreamAddr = serverInfo.RelayUDPAddr
	}

	pc, err := serverInfo.dialudp(pid, upstreamAddr)
	if err != nil {
		log.E("dnscrypt: udp: dialing %s err: %v", serverInfo, err)
		return nil, err
	}

	defer pc.Close()
	if err = pc.SetDeadline(time.Now().Add(timeout20s)); err != nil {
		return nil, err
	}
	if serverInfo.RelayUDPAddr != nil {
		prepareForRelay(serverInfo.UDPAddr.IP, serverInfo.UDPAddr.Port, &encryptedQuery)
	}
	// TODO: use a pool
	bptr := core.AllocRegion(xdns.MaxDNSUDPPacketSize)
	encryptedResponse := (*bptr)[:xdns.MaxDNSUDPPacketSize]
	defer func() {
		*bptr = encryptedResponse
		core.Recycle(bptr)
	}()
	for tries := 2; tries > 0; tries-- {
		if _, err := pc.Write(encryptedQuery); err != nil {
			log.E("dnscrypt: udp: [%s] write err; [%v]", serverInfo.Name, err)
			return nil, err
		}
		length, err := pc.Read(encryptedResponse)
		if err == nil {
			encryptedResponse = encryptedResponse[:length]
			break
		} else if tries <= 0 {
			log.E("dnscrypt: udp: [%s] read err; quit [%v]", serverInfo.Name, err)
			return nil, err
		}
		log.D("dnscrypt: udp: [%s] read err; retry [%v]", serverInfo.Name, err)
	}
	return decrypt(serverInfo, sharedKey, encryptedResponse, clientNonce)
}

func tcpExchange(pid string, serverInfo *serverinfo, sharedKey *[32]byte, encryptedQuery []byte, clientNonce []byte) ([]byte, error) {
	upstreamAddr := serverInfo.TCPAddr
	if serverInfo.RelayTCPAddr != nil {
		upstreamAddr = serverInfo.RelayTCPAddr
	}

	pc, err := serverInfo.dialtcp(pid, upstreamAddr)
	if err != nil {
		log.E("dnscrypt: tcp: dialing %s err: %v", serverInfo, err)
		return nil, err
	}
	defer pc.Close()
	if derr := pc.SetDeadline(time.Now().Add(timeout20s)); derr != nil {
		log.E("dnscrypt: tcp: err deadline: %v", derr)
		return nil, derr
	}
	if serverInfo.RelayTCPAddr != nil {
		prepareForRelay(serverInfo.TCPAddr.IP, serverInfo.TCPAddr.Port, &encryptedQuery)
	}
	encryptedQuery, err = xdns.PrefixWithSize(encryptedQuery)
	if err != nil {
		log.E("dnscrypt: tcp: prefix(q) %s err: %v", serverInfo, err)
		return nil, err
	}
	if _, werr := pc.Write(encryptedQuery); werr != nil {
		log.E("dnscrypt: tcp: err write: %v", serverInfo, werr)
		return nil, werr
	}
	encryptedResponse, err := xdns.ReadPrefixed(&pc)
	if err != nil {
		log.E("dnscrypt: tcp: read(enc) %s err %v", serverInfo, err)
		return nil, err
	}
	return decrypt(serverInfo, sharedKey, encryptedResponse, clientNonce)
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

func query(pid string, packet []byte, serverInfo *serverinfo, useudp bool) (response []byte, qerr *dnsx.QueryError) {
	if len(packet) < xdns.MinDNSPacketSize {
		qerr = dnsx.NewBadQueryError(errQueryTooShort)
		return
	}

	intercept := newIntercept()
	// serverName := "-"
	// needsEDNS0Padding = (serverInfo.Proto == stamps.StampProtoTypeDoH || serverInfo.Proto == stamps.StampProtoTypeTLS)
	needsEDNS0Padding := false

	query, err := intercept.handleRequest(packet, needsEDNS0Padding)
	state := intercept.state

	saction := state.action
	sr := state.response
	if err != nil || saction == ActionDrop {
		log.E("dnscrypt: ActionDrop %v", err)
		qerr = dnsx.NewBadQueryError(err)
		return
	}
	if saction == ActionSynth {
		if sr != nil {
			log.D("dnscrypt: send synth response")
			response, err = sr.PackBuffer(response)
			// XXX: when the query is blocked and pack-buffer fails
			// doh falls back to forwarding the query instead.
			if err != nil {
				qerr = dnsx.NewBadResponseQueryError(err)
			}
			return
		}
		log.D("dnscrypt: no synth; forward query [udp? %t]...", useudp)
	}
	if len(query) < xdns.MinDNSPacketSize {
		qerr = dnsx.NewBadQueryError(errQueryTooShort)
		return
	}
	if len(query) > xdns.MaxDNSPacketSize {
		qerr = dnsx.NewBadQueryError(errQueryTooLarge)
		return
	}

	if serverInfo == nil {
		qerr = dnsx.NewInternalQueryError(errNoServers)
		return
	}

	if serverInfo.Proto == stamps.StampProtoTypeDNSCrypt {
		sharedKey, encryptedQuery, clientNonce, cerr := encrypt(serverInfo, query, useudp)

		if cerr != nil {
			log.W("dnscrypt: enc fail forwarding to %s", serverInfo)
			qerr = dnsx.NewInternalQueryError(cerr)
			return
		}

		if useudp {
			response, err = udpExchange(pid, serverInfo, sharedKey, encryptedQuery, clientNonce)
		}
		tcpfallback := useudp && err != nil
		if tcpfallback {
			log.D("dnscrypt: udp failed, trying tcp")
		}
		// if udp errored out, try over tcp; or use tcp if udp is disabled
		if tcpfallback || !useudp {
			useudp = false // switched to tcp
			response, err = tcpExchange(pid, serverInfo, sharedKey, encryptedQuery, clientNonce)
		}

		if err != nil {
			log.W("dnscrypt: querying [udp? %t] failed: %v", serverInfo, useudp, err)
			qerr = dnsx.NewSendFailedQueryError(err)
			return
		}
	} else if serverInfo.Proto == stamps.StampProtoTypeDoH {
		// FIXME: implement
		qerr = dnsx.NewSendFailedQueryError(errNoDoh)
		return
	} else {
		qerr = dnsx.NewTransportQueryError(errUnknownProto)
		return
	}

	if len(response) < xdns.MinDNSPacketSize || len(response) > xdns.MaxDNSPacketSize {
		log.E("dnscrypt: response from %s too small or too large", serverInfo)
		qerr = dnsx.NewBadResponseQueryError(errInvalidResponse)
		return
	}

	response, err = intercept.handleResponse(response, useudp)

	if err != nil {
		log.E("dnscrypt: err intercept response for %s: %w", serverInfo, err)
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
func resolve(network string, data []byte, si *serverinfo, smm *x.DNSSummary) (response []byte, err error) {
	var qerr *dnsx.QueryError

	before := time.Now()

	proto, pid := xdns.Net2ProxyID(network)
	useudp := proto == dnsx.NetTypeUDP

	// si may be nil
	response, qerr = query(pid, data, si, useudp)

	after := time.Now()

	latency := after.Sub(before)
	status := dnsx.Complete

	var resolver string
	var anonrelay string
	if si != nil {
		resolver = si.HostName
		if si.RelayTCPAddr != nil {
			anonrelay = si.RelayTCPAddr.IP.String()
		}
	}

	if qerr != nil {
		status = qerr.Status()
		err = qerr.Unwrap()
	}

	ans := xdns.AsMsg(response)

	smm.Latency = latency.Seconds()
	smm.RData = xdns.GetInterestingRData(ans)
	smm.RCode = xdns.Rcode(ans)
	smm.RTtl = xdns.RTtl(ans)
	smm.Server = resolver
	smm.RelayServer = anonrelay
	smm.Status = status

	noAnonRelay := len(anonrelay) <= 0
	if si != nil && noAnonRelay {
		if si.relay != nil {
			smm.RelayServer = si.relay.GetAddr()
		} else if !dnsx.IsLocalProxy(pid) {
			smm.RelayServer = x.SummaryProxyLabel + pid
		}
	}

	log.V("dnscrypt: len(res): %d, data: %s, via: %s, err? %v", len(response), smm.RData, smm.RelayServer, err)

	return response, err
}

// LiveTransports returns csv of dnscrypt server-names currently in-use
func (proxy *DcMulti) LiveTransports() string {
	if len(proxy.liveServers) <= 0 {
		return ""
	}
	return strings.Join(proxy.liveServers[:], ",")
}

func (proxy *DcMulti) refreshOne(uid string) bool {
	r, ok := proxy.registeredServers[uid]
	if !ok {
		return false
	}
	if err := proxy.serversInfo.refreshServer(proxy, r.name, r.stamp); err != nil {
		log.E("dnscrypt: refresh failed %s: %v", r.name, err)
		return false
	}
	return true
}

// Refresh re-registers servers
func (proxy *DcMulti) Refresh() (string, error) {
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

// Start starts this dnscrypt proxy
func (proxy *DcMulti) Start() (string, error) {
	if proxy.sigterm != nil {
		return "", errStarted
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
					log.I("dnscrypt: cert refresh stopped")
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

// Stop stops this dnscrypt proxy
func (proxy *DcMulti) Stop() error {
	if proxy.sigterm != nil {
		proxy.sigterm()
	}
	proxy.sigterm = nil
	proxy.ctl = nil // a bridge in to client "freed" here
	return nil
}

// AddGateways adds relay servers
func (proxy *DcMulti) AddGateways(routescsv string) (int, error) {
	if len(routescsv) <= 0 {
		return 0, errNoRoute
	}

	proxy.Lock()
	defer proxy.Unlock()

	r := strings.Split(routescsv, ",")
	cat := xdns.FindUnique(proxy.routes, r)
	proxy.routes = append(proxy.routes, cat...)
	return len(r), nil
}

// RemoveGateways removes relay servers
func (proxy *DcMulti) RemoveGateways(routescsv string) (int, error) {
	if len(routescsv) <= 0 {
		return 0, errNoRoute
	}

	proxy.Lock()
	defer proxy.Unlock()

	rm := strings.Split(routescsv, ",")
	l := len(proxy.routes)
	proxy.routes = xdns.FindUnique(rm, proxy.routes)
	return l - len(proxy.routes), nil
}

func (proxy *DcMulti) removeOne(uid string) int {
	proxy.Lock()
	defer proxy.Unlock()
	// TODO: handle err
	n, _ := proxy.serversInfo.unregisterServer(uid)
	delete(proxy.registeredServers, uid)
	return n
}

// Remove removes a dnscrypt server / relay, if any
func (proxy *DcMulti) Remove(uid string) bool {
	// may be a gateway / relay or a dnscrypt server
	proxy.removeOne(uid)
	_, _ = proxy.RemoveGateways(uid)
	return true
}

// RemoveAll removes all dnscrypt servers in the csv
func (proxy *DcMulti) RemoveAll(servernamescsv string) (int, error) {
	if len(servernamescsv) <= 0 {
		return 0, errNothing
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

func (proxy *DcMulti) addOne(uid, rawstamp string) (string, error) {
	proxy.Lock()
	defer proxy.Unlock()

	stamp, err := stamps.NewServerStampFromString(rawstamp)
	if err != nil {
		return uid, fmt.Errorf("dnscrypt: stamp error for [%s] def: [%v]", rawstamp, err)
	}
	if stamp.Proto == stamps.StampProtoTypeDoH {
		// TODO: Implement doh
		return uid, fmt.Errorf("dnscrypt: doh not supported %s", rawstamp)
	}
	proxy.registeredServers[uid] = registeredserver{name: uid, stamp: stamp}
	return uid, nil
}

// Add implements dnsx.TransportMult
func (proxy *DcMulti) Add(t x.DNSTransport) bool {
	// no-op
	return false
}

// Get implements dnsx.TransportMult
func (proxy *DcMulti) Get(id string) (x.DNSTransport, error) {
	// no-op
	return nil, errNoServers
}

// AddAll registers additional dnscrypt servers
func (proxy *DcMulti) AddAll(serverscsv string) (int, error) {
	if len(serverscsv) <= 0 {
		return 0, errNothing
	}

	servers := strings.Split(serverscsv, ",")
	for i, serverStampPair := range servers {
		if len(serverStampPair) == 0 {
			return i, fmt.Errorf("dnscrypt: missing stamp for [%s]", serverStampPair)
		}
		serverStamp := strings.Split(serverStampPair, "#")
		if len(serverStamp) < 2 {
			return i, fmt.Errorf("dnscrypt: invalid stamp for [%s]", serverStampPair)
		}
		uid := serverStamp[0]
		if _, err := proxy.addOne(uid, serverStamp[1]); err != nil {
			return i, fmt.Errorf("dnscrypt: error adding [%s]: %v", uid, err)
		}
	}
	return len(servers), nil
}

// P50 implements dnsx.TransportMult
func (p *DcMulti) P50() int64 {
	return p.est.Get()
}

// ID implements dnsx.TransportMult
func (p *DcMulti) ID() string {
	return dnsx.DcProxy
}

// Type implements dnsx.TransportMult
func (p *DcMulti) Type() string {
	return dnsx.DNSCrypt
}

// Query implements dnsx.TransportMult
func (p *DcMulti) Query(network string, q []byte, summary *x.DNSSummary) (r []byte, err error) {
	r, err = resolve(network, q, p.serversInfo.getOne(), summary)
	p.lastStatus = summary.Status
	p.lastAddr = summary.Server
	p.est.Add(summary.Latency)
	return
}

// GetAddr returns the last server address
func (p *DcMulti) GetAddr() string {
	return p.lastAddr
}

// Status implements dnsx.TransportMult
func (p *DcMulti) Status() int {
	return p.lastStatus
}

// NewDcMult creates a dnscrypt proxy
func NewDcMult(px ipn.Proxies, ctl protect.Controller) *DcMulti {
	return &DcMulti{
		routes:                       nil,
		registeredServers:            make(map[string]registeredserver),
		certRefreshDelay:             240 * time.Minute,
		certRefreshDelayAfterFailure: 10 * time.Second,
		certIgnoreTimestamp:          false,
		serversInfo:                  newServersInfo(),
		liveServers:                  nil,
		lastStatus:                   dnsx.Start,
		proxies:                      px,
		lastAddr:                     "",
		ctl:                          ctl,
		dialer:                       protect.MakeNsRDial(dnsx.DcProxy, ctl),
		est:                          core.NewP50Estimator(),
	}
}

// NewTransport creates and adds a dnscrypt transport to p
func NewTransport(p *DcMulti, id, serverstamp string) (dnsx.Transport, error) {
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

// AddRelayTransport creates and adds a relay server to p
func AddRelayTransport(p *DcMulti, relaystamp string) error {
	if p == nil {
		return dnsx.ErrNoDcProxy
	}
	if _, err := p.AddGateways(relaystamp); err == nil {
		return nil
	} else {
		return err
	}
}
