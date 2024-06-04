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
	"github.com/celzero/firestack/intra/dialers"
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
	Preset    = x.Preset
	BlockFree = x.BlockFree
	Bootstrap = x.Bootstrap
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
	NetNoProxy   = x.Base
	NetExitProxy = x.Exit

	ttl10m = 10 * time.Minute

	// pseudo transport ID to tag dns64 responses
	AlgDNS64 = "dns64"
)

var (
	selfprefix    = protect.UidSelf + "."
	systemprefix  = protect.UidSystem + "."
	algprefix     = "alg."
	cacheprefix   = "cached."
	d64prefix     = "64."
	defaultprefix = "d."
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
	Query(network string, q *dns.Msg, summary *x.DNSSummary) (*dns.Msg, error)
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

	// special purpose pre-defined transports
	// Gateway implements a DNS ALG transport
	Gateway() Gateway
	// GetMult returns multi-transport, if available
	GetMult(id string) (TransportMult, error)

	IsDnsAddr(ipport string) bool
	// Lookup performs resolution on Default and/or Goos DNSes
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
	transports   map[string]Transport
	gateway      Gateway
	localdomains x.RadixTree
	rdnsl        *rethinkdnslocal
	rdnsr        *rethinkdns
	rmu          sync.RWMutex // protects rdnsr and rdnsl
	listener     x.DNSListener
}

var _ Resolver = (*resolver)(nil)

func NewResolver(fakeaddrs string, tunmode *settings.TunMode, dtr x.DNSTransport, l x.DNSListener, pt NatPt) *resolver {
	r := &resolver{
		NatPt:        pt,
		listener:     l,
		transports:   make(map[string]Transport),
		tunmode:      tunmode,
		localdomains: newUndelegatedDomainsTrie(),
	}
	r.gateway = NewDNSGateway(r, pt)
	r.loadaddrs(fakeaddrs)
	if dtr.ID() != Default {
		log.W("dns: not default; ignoring %s @ %s", dtr.ID(), dtr.GetAddr())
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

// Implements Resolver
func (r *resolver) Add(dt x.DNSTransport) (ok bool) {
	if dt == nil || core.IsNil(dt) {
		log.D("dns: cannot add nil transports")
		return false
	}
	t, ok := dt.(Transport)
	if !ok { // unlikely
		return false
	}
	if t.ID() == Default || cachedTransport(t) {
		log.W("dns: cannot re-add default/cached transports; ignoring: %s", t.GetAddr())
		return false
	}

	switch t.Type() {
	case DNS53, DNSCrypt, DOH, DOT, ODOH:
		ct := NewCachingTransport(t, ttl10m)
		tid := t.ID()
		r.Lock()
		r.transports[tid] = t // regular
		if ct != nil {
			r.transports[ct.ID()] = ct // cached
		}
		r.Unlock()

		if tid == System {
			core.Go("r.Add64", func() { r.Add64(t) })
		}

		core.Go("r.onAdd", func() { r.listener.OnDNSAdded(tid) })
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

func (r *resolver) Get(id string) (x.DNSTransport, error) {
	if t := r.determineTransport(id); t == nil || core.IsNil(t) {
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

	_, hasTransport := r.transports[id]
	if hasTransport {
		if id == System {
			core.Go("r.Remove64", func() { r.Remove64(id) })
		}
		r.Lock()
		delete(r.transports, id)
		delete(r.transports, CT+id)
		r.Unlock()

		log.I("dns: removed transport %s", id)
	}

	if tm, err := r.dcProxy(); err == nil { // remove from dc-proxy, if any
		hasTransport = tm.Remove(id) || hasTransport
		hasTransport = tm.Remove(CT+id) || hasTransport
	}

	if hasTransport {
		core.Go("r.onRemove", func() { r.listener.OnDNSRemoved(id) })
	}

	return hasTransport
}

func (r *resolver) IsDnsAddr(ipport string) bool {
	if len(ipport) <= 0 {
		return false
	}
	return r.isDns(ipport)
}

func (r *resolver) LocalLookup(q []byte) ([]byte, error) {
	defaultIsSystemDNS := false
	if dtr, _ := r.Get(Default); dtr != nil {
		// todo: a better way to determine whether Default is SystemDNS
		// Default is usually SystemDNS if it is of type DNS53
		defaultIsSystemDNS = dtr.Type() == DNS53
	}

	// including dns64 and/or alg
	ans, err := r.forward(q, CT+Default)
	if defaultIsSystemDNS {
		return ans, err
	} // else: retry with Goos/System, if needed

	// msg may be nil
	if msg := xdns.AsMsg(ans); err != nil || xdns.IsNXDomain(msg) || !xdns.HasRcodeSuccess(msg) {
		log.I("dns: nxdomain via Default (err? %v); using Goos for %s", err, xdns.QName(msg))
		return r.forward(q, CT+Goos) // Goos is System; see: determineTransport
	} // else: rcode success and nil err; do not fallback on Goos/System
	return ans, nil
}

func (r *resolver) Forward(q []byte) ([]byte, error) {
	return r.forward(q)
}

func (r *resolver) forward(q []byte, chosenids ...string) (res0 []byte, err0 error) {
	starttime := time.Now()
	summary := &x.DNSSummary{
		QName:  invalidQname,
		Status: Start,
		Msg:    noerr.Error(),
	}
	// always call up to the listener
	defer func() {
		if err0 != nil {
			summary.Msg = err0.Error()
		} // else: preserve msg from Transport.Query
		if settings.Debug {
			summary.Latency = time.Since(starttime).Seconds()
		}
		core.Go("r.onResponse", func() { r.listener.OnResponse(summary) })
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

	pref := r.listener.OnQuery(qname, qtyp)
	id, sid, pid, presetIPs := r.preferencesFrom(qname, uint16(qtyp), pref, chosenids...)
	t := r.determineTransport(id)

	log.V("dns: fwd: query %s [prefs:%v]; id? %s, sid? %s, pid? %s, ips? %v", qname, pref, id, sid, pid, presetIPs)

	if t == nil || core.IsNil(t) {
		summary.Latency = time.Since(starttime).Seconds()
		summary.Status = TransportError
		return nil, errNoSuchTransport
	}
	var t2 Transport
	if len(sid) > 0 {
		t2 = r.determineTransport(sid)
	}

	gw := r.Gateway()

	res1, blocklists, err := r.blockQ(t, t2, msg) // skips if the t, t2 are alg/block-free
	if err == nil {
		if pref.NOBLOCK { // only add blocklists and do not actually block
			summary.Blocklists = blocklists
		} else {
			b, e := res1.Pack()
			summary.Latency = time.Since(starttime).Seconds()
			summary.Status = Complete
			summary.Blocklists = blocklists
			summary.RData = xdns.GetInterestingRData(res1)
			log.V("dns: fwd: query blocked %s by %s", qname, blocklists)

			return b, e
		}
	} else {
		log.V("dns: fwd: query NOT blocked %s; why? %v", qname, err)
	}

	summary.Type = t.Type()
	summary.ID = t.ID()
	var res2 []byte
	var ans1 *dns.Msg

	netid := xdns.NetAndProxyID(NetTypeUDP, pid)

	// with t2 as the secondary transport, which could be nil
	ans1, err = gw.q(t, t2, presetIPs, netid, msg, summary)

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
	// very unlikely that ans1 is nil but err is not
	if ans1 == nil {
		summary.Status = NoResponse // TODO: servfail?
		return res2, errors.Join(err, errNoAnswer)
	}

	res2, err = ans1.Pack()
	if err != nil {
		summary.Status = BadResponse // TODO: servfail?
		return res2, err
	}

	ans2, blocklistnames := r.blockA(t, t2, msg, ans1, summary.Blocklists)

	isnewans := ans2 != nil
	// do not block, only add blocklists if NOBLOCK is set
	if !pref.NOBLOCK && isnewans {
		// overwrite if new answer
		ans1 = ans2
		res2, err = ans2.Pack()
		if err != nil {
			summary.Status = BadResponse // TODO: servfail?
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
	} else if canUseDefaultDNS(id0) {
		return tf
	}

	return nil
}

// dnstcp queries the transport and writes answers to w, prefixed by length.
func (r *resolver) dnstcp(q []byte, w io.WriteCloser) error {
	ans, err := r.forward(q)

	rlen := len(ans)
	if rlen <= 0 && err != nil {
		clos(w) // close on client err
		return err
	}

	if n, err := writePrefixed(w, ans, rlen); err != nil {
		clos(w) // close on write back err
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
		clos(w) // close on client err
		return err
	}

	if n, err := w.Write(ans); err != nil {
		clos(w) // close on write back err
		return err
	} else if n != rlen {
		// do not close on incomplete writes
		return fmt.Errorf("dns: udp: incomplete write: n(%d) != r(%d)", n, rlen)
	}

	return nil // ok
}

// reply DNS-over-UDP from a stub resolver.
func (r *resolver) reply(c protect.Conn) {
	defer clos(c)

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

		tm := time.Now().Add(ttl2m)
		_ = c.SetDeadline(tm)

		n, err := c.Read(q)

		do := func() {
			_ = r.dnsudp(q[:n], c)
			free()
		}

		if err != nil {
			millis := int(time.Since(start).Seconds() * 1000)
			log.D("dns: udp: done; tot: %d, t: %dms, err: %v", cnt, millis, err)
			free()
			break
		}
		core.Go("r.reply.do", do)
		cnt++
	}
}

// Accept a DNS-over-TCP socket from a stub resolver, and connect the socket
// to this DNSTransport.
func (r *resolver) accept(c io.ReadWriteCloser) {
	defer clos(c)

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
		core.Go("r.accept.do", do)
		cnt++
	}
	ms := int(time.Since(start).Seconds() * 1000)
	log.D("dns: tcp: done; tot: %d, t: %ds", cnt, ms)
	// TODO: Cancel outstanding queries.
}

func (r *resolver) Stop() error {
	core.Go("r.onStop", func() { r.listener.OnDNSStopped() })

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
			curt := t
			// re-adding creates NEW cached transports
			// which is akin to a cache flush
			core.Go("r.Add", func() { r.Add(curt) })
		}
	}
}

func (r *resolver) Refresh() (string, error) {
	log.I("dns: refresh transports")

	go r.refresh()
	go dialers.Clear()
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

func (r *resolver) preferencesFrom(qname string, qtyp uint16, s *x.DNSOpts, chosenids ...string) (id1, id2, pid string, ips []*netip.Addr) {
	var x []string
	if s == nil { // should never happen; but it has during testing
		log.W("dns: pref: no ns opts for %s", qname)
		x = nil
	} else {
		x = strings.Split(s.TIDCSV, ",")
		if y := strings.Split(s.IPCSV, ","); len(y) > 0 {
			ips = make([]*netip.Addr, 0, len(y))
			for _, a := range y {
				if len(a) <= 0 {
					continue
				}
				ip, err := netip.ParseAddr(a)
				if err != nil || !ip.IsValid() {
					log.W("dns: pref: skip bad ip %s for %s", a, qname)
					continue
				}
				ips = append(ips, &ip) // unmap?
			}
		}
		if len(ips) > 0 {
			ip4s, ip6s := splitIPFamilies(ips)
			if xdns.IsAQType(qtyp) {
				ips = ip4s
			} else if xdns.IsAAAAQType(qtyp) {
				ips = ip6s
			} else if xdns.IsHTTPSQType(qtyp) || xdns.IsSVCBQType(qtyp) {
				// ips are substituted in after answers are received
				// so qtype checks are not sufficient
				// see: synthesizeOrQuery
			} else {
				ips = nil // mismatch in query type and ip family
			}
		}
	}

	if len(ips) > 0 { // skip blocks if ips are set (even if unspecified ips)
		log.D("dns: pref: preset ips (no block) %v for %s", ips, qname)
		s.NOBLOCK = true
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
	} else if isAnyBlockAll(id1, id2) || isAnyIPUnspecified(ips) { // just one transport, BlockAll, if set
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

// RegisterAddrs registers IP ports with all dialers for a given hostname.
// If id is dnsx.Bootstrap, the hostname is "protected" from re-resolutions.
// hostname is a domain name, and as a special case, can be protect.UidSelf or protect.UidSystem.
func RegisterAddrs(id, hostname string, ipps []string) (ok bool) {
	id, _ = strings.CutPrefix(id, CT)
	if id == Bootstrap || id == System || id == Default || id == Local {
		log.I("dnsx: bootstrap! %s -> %v", hostname, ipps)
		_, ok = dialers.NewProtected(hostname, ipps)
	} else {
		_, ok = dialers.New(hostname, ipps)
	}
	return
}

func isReserved(id string) bool {
	switch id {
	case Default, Goos, System, Local, Alg, DcProxy, BlockAll, Preferred, Bootstrap, BlockFree:
		return true
	case CT + Default, CT + Goos, CT + System, CT + Local, CT + Alg, CT + DcProxy, CT + BlockAll, CT + Bootstrap, CT + Preferred, CT + BlockFree:
		return true
	}
	return false
}

func canUseDefaultDNS(id string) bool {
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

func isAnyIPUnspecified(ips []*netip.Addr) bool {
	for _, ip := range ips {
		if ip.IsUnspecified() {
			return true
		}
	}
	return false
}

func isAnyLocal(ids ...string) bool {
	return isTransportID(Local, ids...)
}

func overrideProxyIfNeeded(pid string, ids ...string) string {
	for _, id := range ids {
		switch id {
		// note: Goos is anyway hard-coded to use NetExitProxy
		case Bootstrap, Default, Goos: // exit
			return NetExitProxy
		case CT + Bootstrap, CT + Default, CT + Goos: // exit
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
		case Default, BlockFree, Alg, Bootstrap:
			return true
		case CT + Default, CT + BlockFree, CT + Alg, CT + Bootstrap:
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

func PrefixFor(id string) string {
	switch id {
	case CT:
		return cacheprefix
	case System, CT + System:
		return systemprefix
	case Bootstrap, CT + Bootstrap:
		return selfprefix
	case Alg, CT + Alg:
		return algprefix
	case AlgDNS64, CT + AlgDNS64:
		return d64prefix
	case Default, CT + Default:
		return defaultprefix
	}
	return ""
}

func cachedTransport(t Transport) bool {
	return strings.HasSuffix(t.ID(), CT) || strings.HasPrefix(t.GetAddr(), cacheprefix)
}

func clos(c io.Closer) {
	core.CloseOp(c, core.CopRW)
}
