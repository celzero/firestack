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
	"net/netip"
	"strings"
	"sync"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

const (
	// DNS transport types
	DOH      = x.DOH
	DNSCrypt = x.DNSCrypt
	DNS53    = x.DNS53
	DOT      = x.DOT
	ODOH     = x.ODOH

	CT = x.CT

	Goos      = x.Goos
	System    = x.System
	Local     = x.Local
	Default   = x.Default
	Preferred = x.Preferred
	BlockFree = x.BlockFree
	BlockAll  = x.BlockAll
	Alg       = x.Alg
	DcProxy   = x.DcProxy
	IpMapper  = x.IpMapper

	invalidQname = "invalid.query"

	// preferred network to use with t.Query
	NetTypeUDP = "udp"
	NetTypeTCP = "tcp"
	// preferred forwarding network, if any
	// ipn.Base is treated as a no-proxy
	NetNoProxy   = "Base"
	NetExitProxy = "Exit" // same as ipn.Exit

	ttl10m = 10 * time.Minute

	// pseudo transport ID to tag dns64 responses
	d64prefix = "d64."
)

var (
	ErrNotDefaultTransport = errors.New("not a default transport")
	ErrNoDcProxy           = errors.New("no dnscrypt-proxy")
	ErrNoProxyProvider     = errors.New("no proxy provider")
	ErrNoProxyDNS          = errors.New("no proxy dns")
	ErrAddFailed           = errors.New("add failed")
	errNoSuchTransport     = errors.New("missing transport")
	errBlockFreeTransport  = errors.New("block free transport")
	errNoRdns              = errors.New("no rdns")
	errTransportNotMult    = errors.New("not a multi-transport")
	errMissingQueryName    = errors.New("no query name")
)

// Transport represents a DNS query transport.  This interface is exported by gobind,
// so it has to be very simple.
type Transport interface {
	x.DNSTransport
	// Given a DNS query (including ID), returns a DNS response with matching
	// ID, or an error if no response was received.  The error may be accompanied
	// by a SERVFAIL response if appropriate.
	Query(network string, q []byte, summary *x.DNSSummary) ([]byte, error)
}

// TransportMult is a hybrid: transport and a multi-transport.
type TransportMult interface {
	x.DNSTransportMult
	Transport
}

type Resolver interface {
	x.DNSTransportMult
	RdnsResolver
	NatPt

	AddSystemDNS(t Transport) bool
	RemoveSystemDNS() int

	// special purpose pre-defined transports
	// Gateway implements a DNS ALG transport
	Gateway() Gateway
	// GetMult returns multi-transport, if available
	GetMult(id string) (TransportMult, error)

	IsDnsAddr(ipport string) bool
	// Lookup performs resolution on Default DNSes
	LocalLookup(q []byte) ([]byte, error)
	// Forward performs resolution on any DNS transport
	Forward(q []byte) ([]byte, error)
	// Serve reads DNS query from conn and writes DNS answer to conn
	Serve(proto string, conn protect.Conn)
}

type resolver struct {
	sync.RWMutex // protects transports
	NatPt
	tunmode      *settings.TunMode
	dnsaddrs     []netip.AddrPort
	systemdns    []Transport
	transports   map[string]Transport
	gateway      Gateway
	localdomains x.RadixTree
	rdnsl        *rethinkdnslocal
	rdnsr        *rethinkdns
	rmu          sync.RWMutex // protects rdnsr and rdnsl
	listener     x.DNSListener
}

var _ Resolver = (*resolver)(nil)

func NewResolver(fakeaddrs string, tunmode *settings.TunMode, dtr x.DNSTransport, l x.DNSListener, pt NatPt) Resolver {
	r := &resolver{
		NatPt:        pt,
		listener:     l,
		transports:   make(map[string]Transport),
		tunmode:      tunmode,
		localdomains: newUndelegatedDomainsTrie(),
		systemdns:    make([]Transport, 0),
	}
	r.gateway = NewDNSGateway(r, pt)
	r.loadaddrs(fakeaddrs)
	if dtr.ID() != Default {
		log.W("dns: not default; ignoring", dtr.ID(), dtr.GetAddr())
	} else if tr, ok := dtr.(Transport); !ok {
		log.W("dns: not a transport; ignoring", dtr.ID(), dtr.GetAddr())
	} else {
		ctr := NewCachingTransport(tr, ttl10m)
		r.Lock()
		r.transports[tr.ID()] = tr // regular
		if ctr != nil {
			r.transports[ctr.ID()] = ctr // cached
		} else {
			log.W("dns: no caching transport for %s", tr.ID())
		}
		r.Unlock()
	}
	log.I("dns: new! gw? %t; default? %s", r.gateway != nil, dtr.GetAddr())

	return r
}

func (r *resolver) Gateway() Gateway {
	return r.gateway
}

func (r *resolver) Translate(b bool) {
	r.gateway.translate(b)
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
func (r *resolver) Add(dt x.DNSTransport) (ok bool) {
	if dt == nil {
		return false
	}
	t, ok := dt.(Transport)
	if !ok { // unlikely
		return false
	}
	if t.ID() == Default || cachedTransport(t) {
		log.W("dns: cannot re-add default/cached transports; ignoring: ", t.GetAddr())
		return false
	}

	switch t.Type() {
	case DNS53, DNSCrypt, DOH, DOT, ODOH:
		// DNSCrypt transports are also registered with DcProxy
		// Alg transports are also registered with Gateway
		// Remove cleans those up
		r.Remove(t.ID())
		r.Remove(CT + t.ID())

		// these IDs are reserved for internal use
		if isReserved(t.ID()) {
			log.I("dns: updating reserved transport %s@%s", t.ID(), t.GetAddr())
		}

		ct := NewCachingTransport(t, ttl10m)

		r.Lock()
		r.transports[t.ID()] = t // regular
		if ct != nil {
			r.transports[ct.ID()] = ct // cached
		}
		r.Unlock()

		log.I("dns: add transport %s@%s; cache? %t", t.ID(), t.GetAddr(), ct != nil)

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

func (r *resolver) Get(id string) (x.DNSTransport, error) {
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

	r.Lock()
	delete(r.transports, id)
	delete(r.transports, ctid)
	r.Unlock()

	log.I("dns: removed transport %s", id)

	if tm, err := r.dcProxy(); err == nil {
		tm.Remove(id)
		tm.Remove(ctid)
	}

	return
}

func (r *resolver) IsDnsAddr(ipport string) bool {
	if len(ipport) <= 0 {
		return false
	}
	return r.isDns(ipport)
}

func (r *resolver) LocalLookup(q []byte) ([]byte, error) {
	return r.forward(q, CT+Default) // incl dns64 and/or alg
}

func (r *resolver) Forward(q []byte) ([]byte, error) {
	return r.forward(q)
}

func (r *resolver) forward(q []byte, chosenids ...string) (res0 []byte, err0 error) {
	starttime := time.Now()
	summary := &x.DNSSummary{
		QName:  invalidQname,
		Status: Start,
	}
	// always call up to the listener
	defer func() {
		if err0 != nil {
			summary.Msg = err0.Error()
		} else {
			summary.Msg = noerr.Error()
		}
		go r.listener.OnResponse(summary)
	}()

	msg, err := unpack(q)
	if err != nil {
		log.W("dns: fwd: not a dns packet %v", err)
		summary.Latency = time.Since(starttime).Seconds()
		summary.Status = BadQuery
		return nil, err
	}

	// figure out transport to use
	qname := qname(msg)
	qtyp := qtype(msg)
	summary.QName = qname
	summary.QType = qtyp

	if len(qname) <= 0 { // unexpected; github.com/celzero/rethink-app/issues/1210
		summary.Latency = time.Since(starttime).Seconds()
		summary.Status = BadQuery
		return nil, errMissingQueryName
	}

	// pref := r.listener.OnQuery(qname, qtyp)
	pref := new(x.DNSOpts)
	id, sid, pid, _ := r.preferencesFrom(qname, pref, chosenids...)
	t := r.determineTransport(id)

	log.V("dns: fwd: query %s [prefs:%v]; id? %s, sid? %s, pid? %s", qname, pref, id, sid, pid)

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
		log.V("dns: fwd: query blocked %s by %s", qname, blocklists)
		return b, e
	} else {
		log.V("dns: fwd: query NOT blocked %s; why? %v", qname, err)
	}

	summary.Type = t.Type()
	summary.ID = t.ID()
	var res2 []byte

	netid := xdns.NetAndProxyID(NetTypeUDP, pid)

	// with t2 as the secondary transport, which could be nil
	res2, err = gw.q(t, t2, netid, q, summary)

	algerr := isAlgErr(err) // not set when gw.translate is off
	if algerr {
		log.W("dns: fwd: alg error %s for %s", err, qname)
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
		res2, err = ans2.Pack()
		if err != nil {
			summary.Status = BadResponse
			return res2, err
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

	log.V("dns: fwd: query %s; new-ans? %t, blocklists? %t, blocked? %t", qname, isnewans, hasblocklists, ansblocked)

	return res2, nil
}

func (r *resolver) Serve(proto string, c protect.Conn) {
	switch proto {
	case NetTypeTCP:
		r.accept(c)
	case NetTypeUDP:
		r.reply(c)
	default:
		log.W("dns: unknown proto: %s", proto)
	}
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
			id0 = CT + Preferred
		} else {
			id0 = CT + BlockFree
			id1 = CT + Preferred
		}
	} else if id == System || id == CT+System || id == Goos || id == CT+Goos {
		// fallback on Goos if System is unavailable
		// but unlike "System", "Goos" does not support
		// other than A / AAAA queries
		// cf: undelegated.go:requiresGoosOrLocal()
		if id == CT+System || id == CT+Goos {
			id0 = CT + System
			id1 = CT + Goos
		} else {
			id0 = System
			id1 = Goos
		}
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

// dnstcp queries the transport and writes answers to w, prefixed by length.
func (r *resolver) dnstcp(q []byte, w io.WriteCloser) error {
	ans, err := r.forward(q)

	rlen := len(ans)
	if rlen <= 0 && err != nil {
		w.Close() // close on client err
		return err
	}

	if n, err := writePrefixed(w, ans, rlen); err != nil {
		w.Close() // close on write back err
		return err
	} else if n != rlen {
		// do not close on incomplete writes
		return fmt.Errorf("dns: tcp: incomplete write: n(%d) != r(%d)", n, rlen)
	}
	return nil // ok
}

// dnsudp queries the transport and writes answers to w.
func (r *resolver) dnsudp(q []byte, w io.WriteCloser) error {
	ans, err := r.forward(q)

	rlen := len(ans)
	if rlen <= 0 && err != nil {
		w.Close() // close on client err
		return err
	}

	if n, err := w.Write(ans); err != nil {
		w.Close() // close on write back err
		return err
	} else if n != rlen {
		// do not close on incomplete writes
		return fmt.Errorf("dns: udp: incomplete write: n(%d) != r(%d)", n, rlen)
	}

	return nil // ok
}

// reply DNS-over-UDP from a stub resolver.
func (r *resolver) reply(c io.ReadWriteCloser) {
	defer c.Close()

	start := time.Now()
	cnt := 0
	for {
		qptr := core.Alloc()
		q := *qptr
		q = q[:cap(q)]
		free := func() {
			*qptr = q
			core.Recycle(qptr)
		}

		switch x := c.(type) {
		case core.UDPConn:
			tm := time.Now().Add(ttl2m)
			_ = x.SetDeadline(tm)
		}

		n, err := c.Read(q)

		do := func() {
			_ = r.dnsudp(q[:n], c)
			free()
		}

		if err != nil {
			ms := int(time.Since(start).Seconds() * 1000)
			log.D("dns: udp: done; tot: %d, t: %ds, err: %v", cnt, ms, err)
			free()
			break
		}
		go do()
		cnt++
	}
}

// Accept a DNS-over-TCP socket from a stub resolver, and connect the socket
// to this DNSTransport.
func (r *resolver) accept(c io.ReadWriteCloser) {
	defer c.Close()

	start := time.Now()
	cnt := 0
	qlbuf := make([]byte, 2)
	for {
		n, err := c.Read(qlbuf)
		if n == 0 {
			log.D("dns: tcp: query socket shutdown")
			break
		}
		if err != nil {
			log.W("dns: tcp: err reading from socket: %v", err)
			break // close on read errs
		}
		// TODO: inform the listener?
		if n < 2 {
			log.W("dns: tcp: incomplete query length")
			break // close on incorrect lengths
		}
		qlen := binary.BigEndian.Uint16(qlbuf)

		qptr := core.AllocRegion(int(qlen))
		q := *qptr
		q = q[:cap(q)]
		free := func() {
			*qptr = q
			core.Recycle(qptr)
		}

		n, err = c.Read(q)
		if err != nil {
			log.D("dns: tcp: done; err: %v", err)
			free()
			break // close on read errs
		}
		do := func() {
			_ = r.dnstcp(q[:n], c)
			free()
		}

		if n != int(qlen) {
			log.W("dns: tcp: incomplete query: %d < %d", n, qlen)
			free()
			break // close on incomplete reads
		}
		go do()
		cnt++
	}
	ms := int(time.Since(start).Seconds() * 1000)
	log.D("dns: tcp: done; tot: %d, t: %ds", cnt, ms)
	// TODO: Cancel outstanding queries.
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
		// skip cached transports
		if !cachedTransport(t) {
			// re-adding creates NEW cached transports
			// which is akin to a cache flush
			go r.Add(t)
		}
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

func (r *resolver) preferencesFrom(qname string, s *x.DNSOpts, chosenids ...string) (id1, id2, pid, ips string) {
	var x []string
	if s == nil { // should never happen; but it has during testing
		log.W("dns: pref: no ns opts for %s", qname)
		x = nil
	} else {
		x = strings.Split(s.TIDCSV, ",")
		ips = s.IPCSV // comma-separated list of IPs
	}
	l := len(x)
	if x == nil || l <= 0 { // x may be nil
		log.W("dns: pref: no tids for %s", qname)
		// no-op
	} else if l == 1 {
		id1 = x[0] // id for transport t1
	} else if l == 2 {
		id1, id2 = x[0], x[1] // ids for transport t1, t2
	} else {
		log.W("dns: pref: too many tids; upto 2, got %d", l)
		id1, id2 = x[0], x[1] // ids for transport t1, t2
	}

	if len(chosenids) > 0 { // chosen ID overrides all
		if len(chosenids[0]) > 0 {
			id1 = chosenids[0]
		}
		if len(chosenids) > 1 && len(chosenids[1]) > 0 {
			id2 = chosenids[1]
		}
		log.D("dns: pref: use chosen tr(%s, %s) for %s", id1, id2, qname)
	} else if isAnyBlockAll(id1, id2) { // just one transport, BlockAll, if set
		id1 = BlockAll
		id2 = ""
	} else if reqid := r.requiresGoosOrLocal(qname); len(reqid) > 0 { // use approp transport given a qname
		log.D("dns: pref: use suggested tr(%s) for %s", reqid, qname)
		id1 = reqid
		id2 = ""
	}
	if isAnyLocal(id1, id2) { // use one transport, Local, if set
		id1 = Local
		id2 = ""
	}
	if len(s.PID) > 0 {
		pid = overrideProxyIfNeeded(s.PID, id1, id2)
	} else {
		pid = NetNoProxy
	}
	return
}

func (r *resolver) loadaddrs(csvaddr string) {
	r.addDnsAddrs(csvaddr)
}

func writePrefixed(w io.Writer, b []byte, l int) (int, error) {
	const pre = 2
	sz := l + pre
	bptr := core.AllocRegion(sz)
	buf := *bptr
	buf = buf[:cap(buf)]

	defer func() {
		*bptr = buf
		core.Recycle(bptr)
	}()

	binary.BigEndian.PutUint16(buf, uint16(l))
	// Use a combined write (pre+b) to ensure atomicity.
	// Otherwise, writes from two responses could be interleaved.
	copy(buf[pre:], b)
	n, err := w.Write(buf[:sz])
	return max(0, n-pre), err
}

func IsLocalProxy(pid string) bool {
	return len(pid) <= 0 || pid == NetNoProxy || pid == NetExitProxy
}

func isReserved(id string) bool {
	switch id {
	case Default, Goos, System, Local, Alg, DcProxy, BlockAll, Preferred, BlockFree:
		return true
	case CT + Default, CT + Goos, CT + System, CT + Local, CT + Alg, CT + DcProxy, CT + BlockAll, CT + Preferred, CT + BlockFree:
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

func isTransportID(match string, ids ...string) bool {
	for _, t := range ids {
		if t == match {
			return true
		}
	}
	return false
}

func isAnyBlockAll(ids ...string) bool {
	return isTransportID(BlockAll, ids...)
}

func isAnyLocal(ids ...string) bool {
	return isTransportID(Local, ids...)
}

func overrideProxyIfNeeded(pid string, ids ...string) string {
	for _, id := range ids {
		switch id {
		// note: Goos is anyway hard-coded to use NetExitProxy
		case Default, Goos: // exit
			return NetExitProxy
		case CT + Default, CT + Goos: // exit
			return NetExitProxy
		case System, Local: // base
			return NetNoProxy
		case CT + System, CT + Local: // base
			return NetNoProxy
		}
	}
	return pid // as-is
}

func skipBlock(tr ...Transport) bool {
	for _, t := range tr {
		if t == nil {
			continue
		}
		switch t.ID() {
		case Default, BlockFree, Alg:
			return true
		case CT + Default, CT + BlockFree, CT + Alg:
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
