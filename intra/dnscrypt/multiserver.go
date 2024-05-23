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
	"math/rand"
	"net"
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
	"github.com/miekg/dns"

	stamps "github.com/jedisct1/go-dnsstamps"
	"golang.org/x/crypto/curve25519"
)

// DcMulti is a dnsx.TransportMult supporting dnscrypt servers and relays
type DcMulti struct {
	sync.RWMutex
	proxyPublicKey      [32]byte
	proxySecretKey      [32]byte
	serversInfo         *ServersInfo
	certIgnoreTimestamp bool
	registeredServers   map[string]registeredserver
	routes              []string
	liveServers         []string
	proxies             ipn.Proxies
	sigterm             context.CancelFunc
	lastStatus          int
	lastAddr            string
	ctl                 protect.Controller
	dialer              *protect.RDial
	est                 core.P2QuantileEstimator
}

var (
	certRefreshDelay             = 240 * time.Minute
	certRefreshDelayAfterFailure = 10 * time.Second
)

var _ dnsx.TransportMult = (*DcMulti)(nil)
var timeout8s = 8000 * time.Millisecond

var (
	errNoCert          = errors.New("dnscrypt: error refreshing cert")
	errQueryTooShort   = errors.New("dnscrypt: query size too short")
	errQueryTooLarge   = errors.New("dnscrypt: query size too large")
	errNoServers       = errors.New("dnscrypt: server not found")
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

func chooseAny[T any](s []T) T {
	return s[rand.Intn(len(s))]
}

func udpExchange(pid string, serverInfo *serverinfo, sharedKey *[32]byte, encryptedQuery []byte, clientNonce []byte) (res []byte, relay net.Addr, err error) {
	upstreamAddr := serverInfo.UDPAddr
	relayAddrs := serverInfo.RelayUDPAddrs
	userelay := len(relayAddrs) > 0
	if userelay {
		upstreamAddr = chooseAny(relayAddrs)
		relay = upstreamAddr
	}

	pc, err := serverInfo.dialudp(pid, upstreamAddr)
	pcnil := pc == nil || core.IsNil(pc)
	if err != nil || pcnil { // nilaway: tx.socks5 returns nil conn even if err == nil
		if err == nil {
			err = errNoConn
		}
		log.E("dnscrypt: udp: dialing %s; hasConn? %s(%t); err: %v", serverInfo, pid, pcnil, err)
		return
	}

	defer clos(pc)
	if err = pc.SetDeadline(time.Now().Add(timeout8s)); err != nil {
		return
	}
	if userelay {
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
		if _, err = pc.Write(encryptedQuery); err != nil {
			log.E("dnscrypt: udp: [%s] write err; [%v]", serverInfo.Name, err)
			return
		}
		var length int
		length, err = pc.Read(encryptedResponse)
		if err == nil {
			encryptedResponse = encryptedResponse[:length]
			break
		} else if tries <= 0 {
			log.E("dnscrypt: udp: [%s] read err; quit [%v]", serverInfo.Name, err)
			return
		}
		log.D("dnscrypt: udp: [%s] read err; retry [%v]", serverInfo.Name, err)
	}
	res, err = decrypt(serverInfo, sharedKey, encryptedResponse, clientNonce)
	return
}

func tcpExchange(pid string, serverInfo *serverinfo, sharedKey *[32]byte, encryptedQuery []byte, clientNonce []byte) (res []byte, relay net.Addr, err error) {
	upstreamAddr := serverInfo.TCPAddr
	relayAddrs := serverInfo.RelayTCPAddrs
	userelay := len(relayAddrs) > 0
	if userelay {
		upstreamAddr = chooseAny(relayAddrs)
		relay = upstreamAddr
	}

	pc, err := serverInfo.dialtcp(pid, upstreamAddr)
	pcnil := pc == nil || core.IsNil(pc)
	if err != nil || pcnil { // nilaway: tx.socks5 returns nil conn even if err == nil
		if err == nil {
			err = errNoConn
		}
		log.E("dnscrypt: tcp: dialing %s; hasConn? %s(%t); err: %v", serverInfo, pid, pcnil, err)
		return
	}
	defer clos(pc)
	if err = pc.SetDeadline(time.Now().Add(timeout8s)); err != nil {
		log.E("dnscrypt: tcp: err deadline: %v", err)
		return
	}
	if userelay {
		prepareForRelay(serverInfo.TCPAddr.IP, serverInfo.TCPAddr.Port, &encryptedQuery)
	}
	encryptedQuery, err = xdns.PrefixWithSize(encryptedQuery)
	if err != nil {
		log.E("dnscrypt: tcp: prefix(q) %s err: %v", serverInfo, err)
		return
	}
	if _, err = pc.Write(encryptedQuery); err != nil {
		log.E("dnscrypt: tcp: err write: %v", serverInfo, err)
		return
	}
	encryptedResponse, err := xdns.ReadPrefixed(&pc)
	if err != nil {
		log.E("dnscrypt: tcp: read(enc) %s err %v", serverInfo, err)
		return
	}
	res, err = decrypt(serverInfo, sharedKey, encryptedResponse, clientNonce)
	return
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

func query(pid string, packet *dns.Msg, serverInfo *serverinfo, useudp bool) (ans *dns.Msg, relay net.Addr, qerr *dnsx.QueryError) {
	var response []byte
	if packet == nil || !xdns.HasAnyQuestion(packet) {
		qerr = dnsx.NewBadQueryError(errQueryTooShort)
		return // nil ans
	}

	intercept := newIntercept()
	intercepted, err := intercept.handleRequest(packet)
	state := intercept.state

	saction := state.action
	sr := state.response
	if err != nil || saction == ActionDrop {
		log.E("dnscrypt: ActionDrop %v", err)
		qerr = dnsx.NewBadQueryError(err)
		return // nil ans
	}
	if saction == ActionSynth {
		if sr != nil {
			ans = sr
			log.D("dnscrypt: send synth response")
			return // synth ans
		}
		log.D("dnscrypt: no synth; forward query [udp? %t]...", useudp)
	}

	if serverInfo == nil {
		qerr = dnsx.NewInternalQueryError(errNoServers)
		return // nil ans
	}

	query, err := intercepted.Pack()
	if err != nil {
		log.E("dnscrypt: pack query err: %v", err)
		qerr = dnsx.NewBadQueryError(err)
		return // nil ans
	}

	if serverInfo.Proto == stamps.StampProtoTypeDNSCrypt {
		sharedKey, encryptedQuery, clientNonce, cerr := encrypt(serverInfo, query, useudp)

		if cerr != nil {
			log.W("dnscrypt: enc fail forwarding to %s", serverInfo)
			qerr = dnsx.NewInternalQueryError(cerr)
			return // nil ans
		}

		if useudp {
			response, relay, err = udpExchange(pid, serverInfo, sharedKey, encryptedQuery, clientNonce)
		}
		tcpfallback := useudp && err != nil
		if tcpfallback {
			log.D("dnscrypt: udp failed, trying tcp")
		}
		// if udp errored out, try over tcp; or use tcp if udp is disabled
		if tcpfallback || !useudp {
			useudp = false // switched to tcp
			response, relay, err = tcpExchange(pid, serverInfo, sharedKey, encryptedQuery, clientNonce)
		}

		if err != nil {
			log.W("dnscrypt: querying [udp? %t; tcpfallback?: %t] failed: %v", useudp, tcpfallback, err)
			qerr = dnsx.NewSendFailedQueryError(err)
			return // nil ans
		}
	} else if serverInfo.Proto == stamps.StampProtoTypeDoH {
		// FIXME: implement
		qerr = dnsx.NewSendFailedQueryError(errNoDoh)
		return // nil ans
	} else {
		qerr = dnsx.NewTransportQueryError(errUnknownProto)
		return // nil ans
	}

	if len(response) < xdns.MinDNSPacketSize || len(response) > xdns.MaxDNSPacketSize {
		log.E("dnscrypt: response from %s too small or too large", serverInfo)
		qerr = dnsx.NewBadResponseQueryError(errInvalidResponse)
		return // nil ans
	}

	response, err = intercept.handleResponse(response, useudp)

	if err != nil {
		log.E("dnscrypt: err intercept response for %s: %w", serverInfo, err)
		qerr = dnsx.NewBadResponseQueryError(err)
		return // nil ans
	}

	ans = new(dns.Msg)
	if err = ans.Unpack(response); err != nil {
		log.E("dnscrypt: err unpack response for %s: %w", serverInfo, err)
		qerr = dnsx.NewBadResponseQueryError(err)
		return // nil ans?
	}

	return // ans "response"
}

// resolve resolves incoming DNS query, data
func resolve(network string, data *dns.Msg, si *serverinfo, smm *x.DNSSummary) (ans *dns.Msg, err error) {
	var qerr *dnsx.QueryError
	var anonrelayaddr net.Addr

	before := time.Now()

	proto, pid := xdns.Net2ProxyID(network)
	useudp := proto == dnsx.NetTypeUDP

	// ans, si may be nil
	ans, anonrelayaddr, qerr = query(pid, data, si, useudp)

	after := time.Now()

	latency := after.Sub(before)
	status := dnsx.Complete

	var resolver string
	var anonrelay string
	if si != nil {
		resolver = si.HostName
		if anonrelayaddr != nil { // may be nil
			anonrelay = anonrelayaddr.String()
		}
	}

	if qerr != nil {
		status = qerr.Status()
		err = qerr.Unwrap()
	}

	smm.Latency = latency.Seconds()
	smm.RData = xdns.GetInterestingRData(ans)
	smm.RCode = xdns.Rcode(ans)
	smm.RTtl = xdns.RTtl(ans)
	smm.Server = resolver
	smm.RelayServer = anonrelay // may be empty
	smm.Status = status

	noAnonRelay := len(anonrelay) <= 0
	if si != nil && noAnonRelay {
		if si.relay != nil {
			smm.RelayServer = x.SummaryProxyLabel + si.relay.ID()
		} else if !dnsx.IsLocalProxy(pid) {
			smm.RelayServer = x.SummaryProxyLabel + pid
		}
	}

	log.V("dnscrypt: len(res): %d, data: %s, via: %s, err? %v", xdns.Len(ans), smm.RData, smm.RelayServer, err)

	return // ans, err
}

// LiveTransports returns csv of dnscrypt server-names currently in-use
func (proxy *DcMulti) LiveTransports() string {
	if len(proxy.liveServers) <= 0 {
		return ""
	}
	return strings.Join(proxy.liveServers[:], ",")
}

func (proxy *DcMulti) refreshOne(uid string) bool {
	proxy.RLock()
	r, ok := proxy.registeredServers[uid]
	proxy.RUnlock()

	if !ok {
		return false
	}
	if err := proxy.serversInfo.refreshServer(proxy, r.name, r.stamp); err != nil {
		log.E("dnscrypt: refresh failed %s: %s; err: %v", r.name, stamp2str(r.stamp), err)
		return false
	}
	log.D("dnscrypt: refresh success %s: %s", r.name, stamp2str(r.stamp))
	return true
}

// Refresh re-registers servers
func (proxy *DcMulti) Refresh() (string, error) {
	var servers []*registeredserver
	proxy.RLock()
	for _, s := range proxy.registeredServers {
		sp := &s // stackoverflow.com/a/68247837
		servers = append(servers, sp)
	}
	proxy.RUnlock()

	for _, registeredServer := range servers {
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
	go proxy.refreshRoutes()
	return proxy.LiveTransports(), nil
}

// start starts this dnscrypt proxy
func (proxy *DcMulti) start() error {
	if proxy.sigterm != nil {
		return errStarted
	}
	ctx, cancel := context.WithCancel(context.Background())
	proxy.sigterm = cancel

	if _, err := crypto_rand.Read(proxy.proxySecretKey[:]); err != nil {
		return err
	}
	curve25519.ScalarBaseMult(&proxy.proxyPublicKey, &proxy.proxySecretKey)

	_, err := proxy.Refresh()
	if proxy.serversInfo.len() > 0 {
		go func(ctx context.Context) {
			for {
				select {
				case <-ctx.Done():
					log.I("dnscrypt: cert refresh stopped")
					return
				default:
					hasServers := proxy.serversInfo.len() > 0
					allDead := len(proxy.liveServers) == 0
					delay := certRefreshDelay
					if hasServers && allDead {
						delay = certRefreshDelayAfterFailure
					}
					time.Sleep(delay)
					proxy.liveServers, _ = proxy.serversInfo.refresh(proxy)
					if someAlive := len(proxy.liveServers) > 0; someAlive {
						proxy.certIgnoreTimestamp = false
					}
				}
			}
		}(ctx)
	}
	return err
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

// refreshRoutes re-adds relay routes to all live/tracked servers
func (proxy *DcMulti) refreshRoutes() {
	udp, tcp := route(proxy)
	if len(udp) <= 0 || len(tcp) <= 0 {
		log.I("dnscrypt: refreshRoutes: remove all relays")
	}
	n := 0
	for _, x := range proxy.serversInfo.getAll() {
		if x == nil {
			continue
		}
		// udp, tcp may be empty or nil; which means no relay
		x.RelayUDPAddrs = udp
		x.RelayTCPAddrs = tcp
		n++
	}
	log.I("dnscrypt: refreshRoutes: %d/%d for %d servers", len(udp), len(tcp), n)
}

// AddGateways adds relay servers
func (proxy *DcMulti) AddGateways(routescsv string) (int, error) {
	if len(routescsv) <= 0 {
		return 0, errNoRoute
	}

	proxy.Lock()
	r := strings.Split(routescsv, ",")
	cat := xdns.FindUnique(proxy.routes, r)
	proxy.routes = append(proxy.routes, cat...)
	proxy.Unlock()

	log.I("dnscrypt: added %d/%d; relay? %s", len(cat), len(r), cat)
	if len(cat) > 0 {
		go proxy.refreshRoutes()
	}
	return len(cat), nil
}

// RemoveGateways removes relay servers
func (proxy *DcMulti) RemoveGateways(routescsv string) (int, error) {
	if len(routescsv) <= 0 {
		return 0, errNoRoute
	}

	proxy.Lock()
	rm := strings.Split(routescsv, ",")
	l := len(proxy.routes)
	proxy.routes = xdns.FindUnique(rm, proxy.routes)
	n := len(proxy.routes)
	proxy.Unlock()

	if l != n { // routes changed
		go proxy.refreshRoutes()
	}
	log.V("dnscrypt: removed %d/%d; relays: %s", l-n, l, routescsv)
	return l - n, nil
}

func (proxy *DcMulti) removeOne(uid string) int {
	proxy.Lock()
	delete(proxy.registeredServers, uid)
	proxy.Unlock()

	// TODO: handle err
	n, err := proxy.serversInfo.unregisterServer(uid)
	log.D("dnscrypt: removed %s; %d servers (err? %v)", uid, n, err)
	return n
}

// Remove removes a dnscrypt server / relay, if any
func (proxy *DcMulti) Remove(uid string) bool {
	// may be a gateway / relay or a dnscrypt server
	n := proxy.removeOne(uid)
	nr, nerr := proxy.RemoveGateways(uid)
	log.D("dnscrypt: removed %s; %d servers; %d relays [err %v]", uid, n, nr, nerr)
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

	log.I("dnscrypt: removed %d servers %s", c, servernamescsv)
	return c, nil
}

func (proxy *DcMulti) addOne(uid, rawstamp string) (string, error) {
	stamp, err := stamps.NewServerStampFromString(rawstamp)
	if err != nil {
		return uid, fmt.Errorf("dnscrypt: stamp error for [%s] def: [%v]", rawstamp, err)
	}
	if stamp.Proto == stamps.StampProtoTypeDoH {
		// TODO: Implement doh
		return uid, fmt.Errorf("dnscrypt: doh not supported %s", rawstamp)
	}

	proxy.Lock()
	proxy.registeredServers[uid] = registeredserver{name: uid, stamp: stamp}
	proxy.Unlock()

	log.D("dnscrypt: added [%s] %s", uid, stamp2str(stamp))
	return uid, nil
}

// Add implements dnsx.TransportMult
func (proxy *DcMulti) Add(t x.DNSTransport) bool {
	// no-op
	return false
}

// Get implements dnsx.TransportMult
func (proxy *DcMulti) Get(id string) (x.DNSTransport, error) {
	if t := proxy.serversInfo.get(id); t != nil {
		return t, nil
	}
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
func (p *DcMulti) Query(network string, q *dns.Msg, summary *x.DNSSummary) (r *dns.Msg, err error) {
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

func stamp2str(s stamps.ServerStamp) string {
	return fmt.Sprintf("name:%s, addr:%s, path:%s", s.ProviderName, s.ServerAddrStr, s.Path)
}

// NewDcMult creates a dnscrypt proxy
func NewDcMult(px ipn.Proxies, ctl protect.Controller) *DcMulti {
	dc := &DcMulti{
		routes:              nil,
		registeredServers:   make(map[string]registeredserver),
		certIgnoreTimestamp: false,
		serversInfo:         newServersInfo(),
		liveServers:         nil,
		lastStatus:          dnsx.Start,
		proxies:             px,
		lastAddr:            "",
		ctl:                 ctl,
		dialer:              protect.MakeNsRDial(dnsx.DcProxy, ctl),
		est:                 core.NewP50Estimator(),
	}
	err := dc.start()
	if err != nil {
		log.E("dnscrypt: start failed: %v", err)
	}
	return dc
}

// AddTransport creates and adds a dnscrypt transport to p
func AddTransport(p *DcMulti, id, serverstamp string) (*serverinfo, error) {
	if p == nil {
		return nil, dnsx.ErrNoDcProxy
	}
	if _, err := p.addOne(id, serverstamp); err == nil {
		if ok := p.refreshOne(id); ok {
			log.I("dnscrypt: added %s; %s", id, serverstamp)
			if tr := p.serversInfo.get(id); tr != nil {
				go p.refreshRoutes()
				return tr, nil
			}
			log.W("dnscrypt: failed to add1 %s; %s", id, serverstamp)
			return nil, dnsx.ErrAddFailed
		} else {
			log.W("dnscrypt: failed to add2 %s; %s", id, serverstamp)
			p.removeOne(id)
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
		log.I("dnscrypt: added relay %s", relaystamp)
		return nil
	} else {
		return err
	}
}
