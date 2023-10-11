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
	IpMapper  = "IpMapper"  // dns resolver for dns resolvers

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
	sync.RWMutex // protects transports
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
	rmu          sync.RWMutex // protects rdnsr and rdnsl
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
	r.gateway = NewDNSGateway(r, pt)

	log.I("dns: new! gw? %t", r.gateway != nil)
	r.loadaddrs(fakeaddrs)
	return r
}

func (r *resolver) Gateway() Gateway {
	return r.gateway
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
	t, ok := r.transports[id]
	defer r.RUnlock()

	if ok {
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
	if len(sid) > 0 {
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

	netid := xdns.NetAndProxyID(NetTypeUDP, pid)

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

	log.V("dns: udp: query %s; new-ans? %t, blocklists? %t, blocked? %t", qname, isnewans, hasblocklists, ansblocked)

	return res2, nil
}

func (r *resolver) Serve(c Conn) {
	r.accept(c)
}

func (r *resolver) determineTransport(id string) Transport {
	if len(id) <= 0 {
		return nil
	}

	var id0, id1 string
	if id == Local || id == CT+Local { // mdns never cached
		id0 = Local
	} else if id == Alg {
		// if no firewall is setup, alg isn't possible
		if r.tunmode.BlockMode == settings.BlockModeNone {
			id0 = CT + Default
		}
		id0 = CT + BlockFree
		id1 = CT + Preferred
	} else {
		id0 = id
	}

	var t0, t1, tf Transport
	r.RLock()
	t0 = r.transports[id0]
	if len(id1) > 0 {
		t1 = r.transports[id1]
	}
	tf = r.transports[CT+Default]
	r.RUnlock()

	if t0 != nil {
		return t0
	} else if t1 != nil {
		return t1
	} else if useFallback(id0) {
		return tf
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
	if len(sid) > 0 {
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
	netid := xdns.NetAndProxyID(NetTypeTCP, pid)

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

func isReserved(id string) bool {
	switch id {
	case Default, System, Local, Alg, DcProxy, BlockAll, Preferred, BlockFree:
		return true
	case CT + Default, CT + System, CT + Local, CT + Alg, CT + DcProxy, CT + BlockAll, CT + Preferred, CT + BlockFree:
		return true
	}
	return false
}

func useFallback(id string) bool {
	switch id {
	case System, Local, Alg, Preferred, BlockFree:
		return true
	case CT + System, CT + Local, CT + Alg, CT + Preferred, CT + BlockFree:
		return true
	}
	return false
}

func overrideTransports(ids ...string) string {
	for _, t := range ids {
		if t == Local {
			return Local
		}
	}
	return ""
}

func allowProxy(ids ...string) bool {
	allow := true
	deny := false
	for _, id := range ids {
		switch id {
		case Default, System, Local:
			return deny
		case CT + Default, CT + System, CT + Local:
			return deny
		}
	}
	return allow
}

func skipBlock(tr ...Transport) bool {
	for _, t := range tr {
		if t == nil {
			continue
		}
		switch t.ID() {
		case BlockFree, Alg:
			return true
		case CT + BlockFree, CT + Alg:
			return true
		}
	}
	return false
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
		log.W("dns: pref: no tids")
		// no-op
	} else if l == 1 {
		id1 = x[0] // id for transport t1
	} else if l == 2 {
		id1, id2 = x[0], x[1] // ids for transport t1, t2
	} else {
		log.W("dns: pref: too many tids; upto 2, got %d", l)
		id1, id2 = x[0], x[1] // ids for transport t1, t2
	}
	if sup := overrideTransports(id1, id2); len(sup) > 0 && l >= 2 {
		log.D("dns: pref: %s overrides transports %s, %s", sup, id1, id2)
		id1 = sup
		id2 = ""
	}
	if len(s.PID) > 0 && allowProxy(id1, id2) {
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
