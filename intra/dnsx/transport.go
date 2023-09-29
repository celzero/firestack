// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

const (
	// DNS transport types
	DOH      = "DNS-over-HTTPS"
	DNSCrypt = "DNSCrypt"
	DNS53    = "DNS"
	DOT      = "DNS-over-TLS"
	ODOH     = "Oblivious DNS-over-HTTPS"

	CT = "Cache" // cached transport prefix

	// special singleton DNS transports (IDs)
	System    = "System"    // network/os provided dns
	Local     = "mdns"      // mdns
	Default   = "Default"   // default (fallback) dns
	Preferred = "Preferred" // user preferred dns, primary for alg
	BlockFree = "BlockFree" // no local blocks; if not set, default is used
	BlockAll  = "BlockAll"  // all blocks
	Alg       = "Alg"       // dns application-level gateway
	DcProxy   = "DcProxy"   // dnscrypt.Proxy as a transport

	invalidQname = "invalid.query"

	// preferred network to use with t.Query
	NetTypeUDP = "udp"
	NetTypeTCP = "tcp"

	// preferred forwarding network, if any
	// ipn.Base is treated as a no-proxy
	NetNoProxy = "Base"
	ttl10m     = 10 * time.Minute

	// pseudo transport ID to tag dns64 responses
	d64prefix = "d64."
)

var (
	ErrNoDcProxy          = errors.New("no dnscrypt-proxy")
	ErrNoProxyProvider    = errors.New("no proxy provider")
	ErrNoProxyDNS         = errors.New("no proxy dns")
	ErrAddFailed          = errors.New("add failed")
	errNoSuchTransport    = errors.New("missing transport")
	errBlockFreeTransport = errors.New("block free transport")
	errNoRdns             = errors.New("no rdns")
	errTransportNotMult   = errors.New("not a multi-transport")
	errMissingQueryName   = errors.New("no query name")
)

type Conn = protect.Conn

// Transport represents a DNS query transport.  This interface is exported by gobind,
// so it has to be very simple.
type Transport interface {
	// uniquely identifies this transport
	ID() string
	// one of DNS53, DOH, DNSCrypt, System
	Type() string
	// Given a DNS query (including ID), returns a DNS response with matching
	// ID, or an error if no response was received.  The error may be accompanied
	// by a SERVFAIL response if appropriate.
	Query(network string, q []byte, summary *Summary) ([]byte, error)
	// Median round-trip time for this transport, in millis.
	P50() int64
	// Return the server host address used to initialize this transport.
	GetAddr() string
	// State of the transport after previous query (see: queryerror.go)
	Status() int
}

type Mult interface {
	// Add adds a transport to this multi-transport.
	Add(t Transport) bool
	// Remove removes a transport from this multi-transport.
	Remove(id string) bool
	// Start starts a multi-transport, returns number of live-servers and errors if any.
	Start() (string, error)
	// Get returns a transport from this multi-transport.
	Get(id string) (Transport, error)
	// Stop stops this multi-transport.
	Stop() error
	// Refresh re-registers transports and returns a csv of active ones.
	Refresh() (string, error)
	// LiveTransports returns a csv of active transports.
	LiveTransports() string
}

// TransportMult is a hybrid: transport and a multi-transport.
type TransportMult interface {
	Mult
	Transport
}

type Resolver interface {
	Mult
	RdnsResolver
	NatPt

	AddSystemDNS(t Transport) bool
	RemoveSystemDNS() int

	// special purpose pre-defined transports
	// Gateway implements a DNS ALG transport
	Gateway() Gateway
	// GetMult returns multi-transport, if available
	GetMult(id string) (TransportMult, error)

	IsDnsAddr(network, ipport string) bool
	Forward(q []byte) ([]byte, error)
	Serve(conn Conn)
}

type resolver struct {
	sync.RWMutex
	NatPt
	tunmode      *settings.TunMode
	tcpaddrs     []*net.TCPAddr
	udpaddrs     []*net.UDPAddr
	systemdns    []Transport
	transports   map[string]Transport
	gateway      Gateway
	localdomains RadixTree
	rdnsl        *rethinkdnslocal
	rdnsr        *rethinkdns
	listener     DNSListener
}

var _ Resolver = (*resolver)(nil)

func NewResolver(fakeaddrs string, tunmode *settings.TunMode, l DNSListener, pt NatPt) Resolver {
	r := &resolver{
		NatPt:        pt,
		listener:     l,
		transports:   make(map[string]Transport),
		tunmode:      tunmode,
		localdomains: newUndelegatedDomainsTrie(),
		systemdns:    make([]Transport, 0),
	}
	r.gateway = NewDNSGateway(r)

	log.I("dns: new! gw? %t", r.gateway != nil)
	r.loadaddrs(fakeaddrs)
	return r
}

func (r *resolver) Gateway() Gateway {
	return r.gateway
}

// Implements RdnsResolver
func (r *resolver) SetRdnsLocal(t, rd, conf, filetag string) error {
	if len(t) <= 0 || len(rd) <= 0 {
		log.I("transport: unset rdns local")
		r.rdnsl = nil
		return nil
	}
	rlocal, err := newRDNSLocal(t, rd, conf, filetag)
	r.rdnsl = rlocal
	return err
}

// Implements RdnsResolver
func (r *resolver) SetRdnsRemote(filetag string) error {
	if len(filetag) <= 0 {
		log.I("transport: unset rdns remote")
		r.rdnsr = nil
		return nil
	}
	rremote, err := newRDNSRemote(filetag)
	r.rdnsr = rremote
	return err
}

// Implements RdnsResolver
func (r *resolver) GetRdnsLocal() RDNS {
	rlocal := r.rdnsl
	if rlocal != nil {
		// a non-ftrie version for across the jni boundary
		return rlocal.rethinkdns
	}
	return nil
}

// Implements RdnsResolver
func (r *resolver) GetRdnsRemote() RDNS {
	return r.rdnsr
}

func (r *resolver) AddSystemDNS(t Transport) bool {
	defer r.addSystemDnsIfAbsent(t)
	r.Lock()
	r.systemdns = append(r.systemdns, t)
	r.Unlock()
	return true
}

func (r *resolver) RemoveSystemDNS() int {
	defer r.Remove(System)
	r.Lock()
	d := len(r.systemdns)
	r.systemdns = make([]Transport, 0)
	r.Unlock()

	return d
}

// Implements Resolver
func (r *resolver) Add(t Transport) (ok bool) {
	if t == nil {
		return false
	}

	switch t.Type() {
	case DNS53, DNSCrypt, DOH, DOT, ODOH:
		// DNSCrypt transports are also registered with DcProxy
		// Alg transports are also registered with Gateway
		// Remove cleans those up
		r.Remove(t.ID())

		// these IDs are reserved for internal use
		if isReserved(t.ID()) {
			log.I("dns: updating reserved transport %s@%s", t.ID(), t.GetAddr())
		}

		ct := NewCachingTransport(t, ttl10m)

		r.Lock()
		r.transports[t.ID()] = t   // regular
		r.transports[ct.ID()] = ct // cached
		r.Unlock()

		log.I("dns: add transport %s@%s", t.ID(), t.GetAddr())

		return true
	default:
		log.E("dns: unknown transport(%s) type: %s", t.ID(), t.Type())
	}
	return false
}

func (r *resolver) GetMult(id string) (TransportMult, error) {
	r.RLock()
	defer r.RUnlock()

	if t, ok := r.transports[id]; ok {
		if tm, ok := t.(TransportMult); ok {
			return tm, nil
		}
		return nil, errTransportNotMult
	}
	return nil, errNoSuchTransport
}

func (r *resolver) dcProxy() (TransportMult, error) {
	return r.GetMult(DcProxy)
}

func (r *resolver) addSystemDnsIfAbsent(t Transport) (ok bool) {
	r.RLock()
	_, ok = r.transports[t.ID()]
	r.RUnlock()
	if !ok {
		ok = r.Add(t)
		go r.registerSystemDns64(t)
	}
	return ok
}

func (r *resolver) registerSystemDns64(ur Transport) (ok bool) {
	return r.Add64(UnderlayResolver, ur)
}

func (r *resolver) Get(id string) (Transport, error) {
	if t := r.determineTransport(id); t == nil {
		return nil, errNoSuchTransport
	} else {
		return t, nil
	}
}

func (r *resolver) Remove(id string) (ok bool) {

	// these IDs are reserved for internal use
	if isReserved(id) {
		log.I("dns: removing reserved transport %s", id)
	}

	ctid := CT + id
	var ok1, ok2 bool
	var t Transport

	r.Lock()
	if t, ok1 = r.transports[id]; ok1 {
		delete(r.transports, id)
		delete(r.transports, ctid)
	}
	r.Unlock()

	if tm, err := r.dcProxy(); err == nil {
		tm.Remove(id)
		tm.Remove(ctid)
	}

	ok = ok1 || ok2
	if ok {
		log.I("dns: remove(%t) transport %s@%s", ok, t.ID(), t.GetAddr())
	} else {
		log.I("dns: remove(%t) transport %s", ok, id)
	}
	return
}

func (r *resolver) IsDnsAddr(network, ipport string) bool {
	if len(ipport) <= 0 {
		return false
	}
	return r.isDns(network, ipport)
}

func (r *resolver) Forward(q []byte) ([]byte, error) {
	starttime := time.Now()
	summary := &Summary{
		QName:  invalidQname,
		Status: Start,
	}
	// always call up to the listener
	defer func() {
		go r.listener.OnResponse(summary)
	}()

	msg, err := unpack(q)
	if err != nil {
		log.W("dns: udp: not a dns packet %v", err)
		summary.Latency = time.Since(starttime).Seconds()
		summary.Status = BadQuery
		return nil, err
	}

	// figure out transport to use
	qname := qname(msg)
	qtyp := qtype(msg)
	summary.QName = qname
	summary.QType = qtyp
	id := r.requiresSystemOrLocal(qname)
	var sid, pid string
	if len(id) > 0 {
		log.I("dns: udp: suggest dns(%s) for %s", id, qname)
	}
	pref := r.listener.OnQuery(qname, qtyp, id)
	id, sid, pid, _ = preferencesFrom(pref)
	t := r.determineTransport(id)
	if t == nil {
		summary.Latency = time.Since(starttime).Seconds()
		summary.Status = TransportError
		return nil, errNoSuchTransport
	}
	var t2 Transport
	if r.useSecondary(id, sid) {
		t2 = r.determineTransport(sid)
	}

	gw := r.Gateway()

	// block skipped if the transport is alg/block-free
	res1, blocklists, err := r.blockQ(t, t2, msg)
	if err == nil {
		b, e := res1.Pack()
		summary.Latency = time.Since(starttime).Seconds()
		summary.Status = Complete
		summary.Blocklists = blocklists
		summary.RData = xdns.GetInterestingRData(res1)
		log.V("dns: udp: query blocked %s by %s", qname, blocklists)
		return b, e
	} else {
		log.V("dns: udp: query NOT blocked %s; why? %v", qname, err)
	}

	summary.Type = t.Type()
	summary.ID = t.ID()
	var res2 []byte

	netid := NetTypeUDP
	if r.allowProxy(t, t2) {
		netid = xdns.NetAndProxyID(netid, pid)
	}

	// with t2 as the secondary transport, which could be nil
	res2, err = gw.q(t, t2, netid, q, summary)

	algerr := isAlgErr(err) // not set when gw.translate is off
	if algerr {
		log.W("dns: udp: alg error %s for %s", err, qname)
	}
	// in the case of an alg transport, if there's no-alg,
	// err is set which should be ignored if res2 is not nil
	if err != nil && !algerr {
		// summary latency, ips, response, status already set by transport t
		return res2, err
	}
	ans1, err := unpack(res2)
	if err != nil {
		summary.Status = BadResponse
		return res2, err
	}

	ans2, blocklistnames := r.blockA(t, t2, msg, ans1, summary.Blocklists)

	isnewans := ans2 != nil
	if isnewans {
		// overwrite if new answer
		ans1 = ans2
		res2, _ = ans2.Pack()
		// summary latency, response, status, ips also set by transport t
		summary.RData = xdns.GetInterestingRData(ans2)
		summary.RCode = xdns.Rcode(ans2)
		summary.RTtl = xdns.RTtl(ans2)
		summary.Status = Complete
	}
	hasblocklists := len(blocklistnames) > 0
	if hasblocklists {
		summary.Blocklists = blocklistnames
	}
	ansblocked := xdns.AQuadAUnspecified(ans1)
	if !ansblocked {
		d64 := r.D64(t.ID(), res2, t) // d64 is disabled by default
		if len(d64) >= xdns.MinDNSPacketSize {
			r.withDNS64SummaryIfNeeded(d64, summary)
			return d64, nil
		} // else: d64 is nil on no D64 or error
	} // else: answer is blocked, no dns64

	log.V("dns: udp: query %s; new-ans? %t, blocklists? %t, blocked? %t", qname, isnewans, hasblocklists, ansblocked)

	return res2, nil
}

func (r *resolver) Serve(c Conn) {
	r.accept(c)
}

func (r *resolver) withDNS64SummaryIfNeeded(d64 []byte, s *Summary) {
	if !settings.Debug {
		return
	}
	msg, err := unpack(d64)
	if err != nil {
		return // should not happen
	}
	// append dns64 rdata to summary
	if rdata := xdns.GetInterestingRData(msg); len(rdata) > 0 {
		if len(s.RData) > 0 {
			s.RData = s.RData + "," + rdata
		} else {
			s.RData = rdata
		}
	}
	if len(s.Server) > 0 {
		s.Server = d64prefix + s.Server
	}

}

func (r *resolver) useSecondary(id, _ string) bool {
	return id != Local
}

// administrator password: Admin@123
func (r *resolver) determineTransport(id string) Transport {
	r.RLock()
	defer r.RUnlock()

	if id == Local { // mdns never cached
		return r.transports[Local]
	}

	if id == Alg {
		// if no firewall is setup, alg isn't possible
		if r.tunmode.BlockMode == settings.BlockModeNone {
			return r.transports[CT+Default]
		}
		t, ok := r.transports[CT+BlockFree]
		if !ok {
			t, ok = r.transports[CT+Preferred]
		}
		if !ok {
			t = r.transports[CT+Default]
		}
		return t
	}

	if t, ok := r.transports[id]; ok {
		return t
	}

	// if none of the reserved transports are available, use the default
	if isReserved(id) {
		return r.transports[CT+Default]
	}

	return nil
}

// Perform a query using the transport, and send the response to the writer.
func (r *resolver) forwardQuery(q []byte, c io.Writer) error {
	starttime := time.Now()
	summary := &Summary{
		QName:  invalidQname,
		Status: Start,
	}
	// always call up to the listener
	defer func() {
		go r.listener.OnResponse(summary)
	}()

	msg, err := unpack(q)
	if err != nil {
		log.W("dns: not a valid packet %v", err)
		summary.Latency = time.Since(starttime).Seconds()
		summary.Status = BadQuery
		return err
	}

	// figure out transport to use
	qname := qname(msg)
	qtyp := qtype(msg)
	summary.QName = qname
	summary.QType = qtyp
	id := r.requiresSystemOrLocal(qname)
	var sid, pid string
	if len(id) > 0 {
		log.I("dns: tcp: suggest system-dns %s for %s", id, qname)
	}
	pref := r.listener.OnQuery(qname, qtyp, id)
	id, sid, pid, _ = preferencesFrom(pref)
	// retrieve transport
	t := r.determineTransport(id)
	if t == nil {
		summary.Latency = time.Since(starttime).Seconds()
		summary.Status = TransportError
		return errNoSuchTransport
	}
	var t2 Transport = nil
	if r.useSecondary(id, sid) {
		t2 = r.determineTransport(sid)
	}

	gw := r.Gateway()

	// block query if needed (skipped for alg/block-free)
	res1, blocklists, err := r.blockQ(t, t2, msg)
	if err == nil {
		b, e := res1.Pack()
		summary.Latency = time.Since(starttime).Seconds()
		summary.Status = Complete
		summary.Blocklists = blocklists
		summary.RData = xdns.GetInterestingRData(res1)
		writeto(c, b, len(b))
		log.V("dns: udp: query blocked %s by %s", qname, blocklists)
		return e
	} else {
		log.V("dns: tcp: query NOT blocked %s; why? %v", qname, err)
	}

	summary.Type = t.Type()
	summary.ID = t.ID()
	var res2 []byte
	netid := NetTypeTCP
	if r.allowProxy(t, t2) {
		netid = xdns.NetAndProxyID(netid, pid)
	}

	// with t2 as secondary transport, which may be nil
	res2, err = gw.q(t, t2, netid, q, summary)

	algerr := isAlgErr(err) // not set when gw.translate is off
	if algerr {
		log.W("dns: tcp: alg error %s for %s", err, qname)
	}
	// in the case of an alg transport, if there's no-alg,
	// err is set which should be ignored if res2 is not nil
	if err != nil && !algerr {
		// summary latency, ips, response, status already set by transport t
		return err
	}
	ans1, qerr := unpack(res2)
	if qerr != nil {
		summary.Status = BadResponse
		return qerr
	}

	ans2, blocklistnames := r.blockA(t, t2, msg, ans1, summary.Blocklists)

	isnewans := ans2 != nil
	if isnewans {
		// overwrite if new answer
		ans1 = ans2
		res2, qerr = ans2.Pack()
		if qerr != nil {
			summary.Status = BadResponse
			return qerr
		}
		// summary latency, response, status, ips also set by transport t
		summary.RData = xdns.GetInterestingRData(ans2)
		summary.RCode = xdns.Rcode(ans2)
		summary.RTtl = xdns.RTtl(ans2)
		summary.Status = Complete
	}
	hasblocklists := len(blocklistnames) > 0
	if hasblocklists {
		summary.Blocklists = blocklistnames
	}
	ansblocked := xdns.AQuadAUnspecified(ans1)
	// override original resp with dns64 if needed
	if !ansblocked {
		d64 := r.D64(t.ID(), res2, t) // d64 is disabled by default
		if len(d64) > xdns.MinDNSPacketSize {
			r.withDNS64SummaryIfNeeded(d64, summary)
			res2 = d64
		} // else: d64 is nil on no D64 or error
	} // else answer is blocked, no dns64

	log.V("dns: tcp: query %s; new-ans? %t, blocklists? %t, blocked? %t", qname, isnewans, hasblocklists, ansblocked)

	rlen := len(res2)
	n, err := writeto(c, res2, rlen)
	if err != nil {
		summary.Status = InternalError
		return err
	}
	if n != rlen {
		summary.Status = InternalError
		return fmt.Errorf("dns: incomplete write: n(%d) != r(%d)", n, rlen)
	}
	return qerr
}

// Perform a query using the transport, send the response to the writer,
// and close the writer if there was an error.
func (r *resolver) forwardQueryAndCheck(q []byte, c io.WriteCloser) {
	if err := r.forwardQuery(q, c); err != nil {
		log.W("dns: query forwarding err: %v", err)
		c.Close()
	}
}

// Accept a DNS-over-TCP socket from a stub resolver, and connect the socket
// to this DNSTransport.
func (r *resolver) accept(c io.ReadWriteCloser) {
	defer c.Close()

	qlbuf := make([]byte, 2)
	for {
		n, err := c.Read(qlbuf)
		if n == 0 {
			log.D("dns: tcp: query socket shutdown")
			break
		}
		if err != nil {
			log.W("dns: tcp: err reading from socket: %v", err)
			break
		}
		// TODO: inform the listener?
		if n < 2 {
			log.W("dns: tcp: incomplete query length")
			break
		}
		qlen := binary.BigEndian.Uint16(qlbuf)
		q := make([]byte, qlen)
		n, err = c.Read(q)
		if err != nil {
			log.W("dns: tcp: err reading query: %v", err)
			break
		}
		if n != int(qlen) {
			log.W("dns: tcp: incomplete query: %d < %d", n, qlen)
			break
		}
		go r.forwardQueryAndCheck(q, c)
	}
	// TODO: Cancel outstanding queries.
}

func isReserved(id string) (ok bool) {
	return id == Alg || id == DcProxy || id == BlockAll || id == Preferred || id == BlockFree || id == System
}

func (r *resolver) allowProxy(ts ...Transport) bool {
	allow := true
	deny := false
	for _, t := range ts {
		if t == nil {
			continue
		}
		if t.ID() == Default || t.ID() == System || t.ID() == Local {
			return deny
		}
	}
	return allow
}

func unpack(q []byte) (*dns.Msg, error) {
	msg := &dns.Msg{}
	err := msg.Unpack(q)
	return msg, err
}

func qname(msg *dns.Msg) string {
	n := xdns.QName(msg)
	n, _ = xdns.NormalizeQName(n)
	return n
}

func qtype(msg *dns.Msg) int {
	return int(xdns.QType(msg))
}

func (r *resolver) loadaddrs(csvaddr string) {
	r.fakeTcpAddr(csvaddr)
	r.fakeUdpAddr(csvaddr)
}

func writeto(w io.Writer, b []byte, l int) (int, error) {
	prependsz := 2
	rlbuf := make([]byte, l+prependsz)
	binary.BigEndian.PutUint16(rlbuf, uint16(l))
	copy(rlbuf[prependsz:], b)
	// Use a combined write to ensure atomicity.
	// Otherwise, writes from two responses could be interleaved.
	n, err := w.Write(rlbuf)
	return max(0, n-prependsz), err
}

func (r *resolver) Start() (string, error) {
	if dc, err := r.dcProxy(); err == nil {
		return dc.Start()
	}
	return "", ErrNoDcProxy
}

func (r *resolver) Stop() error {
	if gw := r.Gateway(); gw != nil {
		gw.stop()
	}
	if dc, err := r.dcProxy(); err == nil {
		return dc.Stop()
	}
	// nothing to stop / no error
	return nil
}

func (r *resolver) refresh() {
	r.RLock()
	defer r.RUnlock()

	for _, t := range r.transports {
		// re-adding creates NEW cached transports
		// which is akin to a cache flush
		go r.Add(t)
	}
}

func (r *resolver) Refresh() (string, error) {
	go r.refresh()
	s := map2csv(r.transports)
	if dc, err := r.dcProxy(); err == nil {
		if x, err := dc.Refresh(); err == nil {
			s += "," + x
		}
	}
	return trimcsv(s), nil
}

func (r *resolver) LiveTransports() string {
	s := map2csv(r.transports)
	if dc, err := r.dcProxy(); err == nil {
		x := dc.LiveTransports()
		if len(x) > 0 {
			s += x
		}
	}
	return trimcsv(s)
}

func preferencesFrom(s *NsOpts) (id1, id2, pid, ips string) {
	x := strings.Split(s.TIDCSV, ",")
	l := len(x)
	if l <= 0 { // cannot happen
		// no-op
	} else if l == 1 {
		id1 = x[0] // id for transport t1
	} else if l == 2 {
		id1, id2 = x[0], x[1] // ids for transport t1, t2
	} else {
		log.W("dns: pref: too many tids; upto 2, got %d", l)
		id1, id2 = x[0], x[1] // ids for transport t1, t2
	}
	if len(s.PID) > 0 {
		pid = s.PID // id for proxy
	} else {
		pid = NetNoProxy
	}
	ips = s.IPCSV // comma-separated list of IPs
	return
}

func map2csv(ts map[string]Transport) string {
	s := ""
	for _, t := range ts {
		s += t.ID() + ","
	}
	return trimcsv(s)
}

func trimcsv(s string) string {
	return strings.Trim(s, ",")
}
