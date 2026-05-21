// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/protect/ipmap"
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

	// DNS decorators
	CT = x.CT

	// DNS transport IDs
	Goos      = x.Goos
	System    = x.System
	Local     = x.Local
	Default   = x.Default
	Preferred = x.Preferred
	Preset    = x.Preset
	Fixed     = x.Fixed
	BlockFree = x.BlockFree
	Bootstrap = x.Bootstrap
	BlockAll  = x.BlockAll
	Alg       = x.Alg
	DcProxy   = x.DcProxy
	Plus      = x.Plus
	IpMapper  = x.IpMapper
	NoDNS     = ""

	// DNS request origin indicator:
	// OriginInternal flags requests by firestack or its owner uid.
	OriginInternal = x.OriginInternal
	// OriginTunnel flags requests by tunnel read (presumably from another app,
	// or firestack or its owner uid if Loopback mode is turned on).
	OriginTunnel = x.OriginTunnel

	invalidQname = "invalid.query"

	// preferred network to use with t.Query
	NetTypeUDP = "udp"
	NetTypeTCP = "tcp"
	// preferred forwarding network, if any
	// ipn.Base is treated as a no-proxy
	NetBaseProxy = x.Base
	NetAutoProxy = x.Auto
	NetNoProxy   = x.Block
	NetExitProxy = x.Exit

	ttl10m = 10 * time.Minute

	listenerTimeout = 3 * time.Second

	// pseudo transport ID to tag dns64 responses
	AlgDNS64 = "dns64"
)

var (
	selfprefix    = protect.UidSelf + "."
	systemprefix  = protect.UidSystem + "."
	algprefix     = "alg."
	cacheprefix   = "cached."
	plusprefix    = "plus."
	d64prefix     = "64."
	defaultprefix = "d."
	presetprefix  = "pre."
	fixedprefix   = "fix."
	echPrefix     = "ech."
	noPkiPrefix   = "nopki."

	NoIPPort []netip.AddrPort = nil
)

var (
	ErrNotDefaultTransport     = errors.New("dns: not a default transport")
	ErrNoDcProxy               = errors.New("dns: no dnscrypt-proxy")
	ErrNoProxyProvider         = errors.New("dns: no proxy provider")
	ErrNoProxyDNS              = errors.New("dns: no proxy")
	ErrAddFailed               = errors.New("dns: add failed")
	errNoSuchTransport         = errors.New("dns: missing transport")
	errTransportEnd            = errors.New("dns: transport ended")
	errTransportPaused         = errors.New("dns: transport paused")
	errOnQueryTimeout          = errors.New("dns: timeout fetching prefs")
	errOnUpstreamAnswerTimeout = errors.New("dns: timeout fetching prefs for upstream answer")
	errBlockFreeTransport      = errors.New("dns: block free transport")
	errNoRdns                  = errors.New("dns: no rdns")
	errTransportNotMult        = errors.New("dns: not a multi-transport")
	errTransportNotMDNS        = errors.New("dns: not an mdns transport")
	errMissingQueryName        = errors.New("dns: no query name")
	errResolverClosed          = errors.New("dns: closed for business")
)

type MDNSTransport interface {
	Transport
	RefreshProto(protos string)
}

// Transport represents a DNS query transport.  This interface is exported by gobind,
// so it has to be very simple.
type Transport interface {
	x.DNSTransport
	// Given a DNS query (including ID), returns a DNS response with matching
	// ID, or an error if no response was received.  The error may be accompanied
	// by a SERVFAIL response if appropriate.
	Query(network string, q *dns.Msg, summary *x.DNSSummary) (*dns.Msg, error)
	// IPPorts returns all ip:ports of this server.
	IPPorts() []netip.AddrPort
	// Stop closes the transport.
	Stop() error
}

// TransportMult is a hybrid: transport and a multi-transport.
type TransportMult interface {
	TransportMultInternal
	Transport
}

type TransportMultInternal interface {
	x.DNSTransportMult
	TransportProviderInternal
}

type TransportMultProviderInternal interface {
	x.DNSTransportMultProvider
	// GetMultInternal returns multi-transport, if available
	GetMultInternal(id string) (TransportMult, error)
}

type TransportProviderInternal interface {
	x.DNSTransportProvider
	// GetInternal returns the internal transport interface for the given ID.
	GetInternal(id string) (Transport, error)
}

type Resolver interface {
	TransportProviderInternal
	TransportMultProviderInternal
	TransportMultInternal
	ResolverSelf
	RdnsResolver
	NatPt

	// IsDnsAddr returns true if the ip:port is resolver's fake endpoint
	IsDnsAddr(ipport netip.AddrPort) bool
	// Serve reads DNS query from conn and writes DNS answer to conn
	Serve(proto string, conn protect.Conn, uid string) (rx, tx int64, errs []error)

	// special purpose pre-defined transports:

	// Gateway implements a DNS ALG transport
	Gateway() Gateway
	// MDNS returns the mdns transport, if available; error otherwise.
	MDNS() (MDNSTransport, error)

	// StopAll stops all transports.
	StopAll()

	// S reveals internal state for debugging
	S() string
}

type resolver struct {
	sync.RWMutex // protects transports
	NatPt
	ctx          context.Context
	done         context.CancelFunc
	dnsaddrs     []netip.AddrPort
	transports   map[string]Transport
	gateway      Gateway
	localdomains x.RadixTree
	listener     x.DNSListener
	smms         chan *x.DNSSummary

	once   sync.Once
	closed atomic.Bool

	// mutable fields
	rmu   sync.RWMutex // protects rdnsr and rdnsl
	rdnsl *rethinkdnslocal
	rdnsr *rethinkdns
}

var _ Resolver = (*resolver)(nil)
var _ x.DNSResolver = (*resolver)(nil)

func NewResolver(pctx context.Context, fakeaddrs string, dtr x.DNSTransport, l x.DNSListener, pt NatPt) *resolver {
	ctx, cancel := context.WithCancel(pctx)
	r := &resolver{
		ctx:          ctx,
		done:         cancel,
		NatPt:        pt,
		listener:     l,
		smms:         make(chan *x.DNSSummary, 64),
		transports:   make(map[string]Transport),
		localdomains: ipmap.UndelegatedDomainsTrie,
	}
	r.loadaddrs(fakeaddrs)
	r.gateway = NewDNSGateway(ctx, r.dnsaddrs, r, pt)
	if dtr.ID() != Default {
		log.W("dns: not default; ignoring %s @ %s", dtr.ID(), dtr.GetAddr())
	} else if tr, ok := dtr.(Transport); !ok {
		log.W("dns: not a transport; ignoring", dtr.ID(), dtr.GetAddr())
	} else {
		ctr := NewCachingTransport(tr, ttl10m)
		r.Lock()
		r.transports[idstr(tr)] = tr // regular
		if ctr != nil {
			r.transports[idstr(ctr)] = ctr // cached
		} else {
			log.W("dns: no caching transport for %s", tr.ID())
		}
		r.Unlock()
	}
	log.I("dns: new! gw? %t; default? %s", r.gateway != nil, dtr.GetAddr())

	core.Go("r.Listener", r.sendSummaries)
	context.AfterFunc(ctx, r.StopAll)
	return r
}

// sendSummaries sends summaries to the listener.
// Must be run in a goroutine.
func (r *resolver) sendSummaries() {
	for smm := range r.smms {
		r.listener.OnResponse(smm)
	}
}

func (r *resolver) queueSummary(smm *x.DNSSummary) {
	if smm == nil {
		return
	}
	select {
	case <-r.ctx.Done():
		log.W("dns: fwd: smms closed; dropping %s", smm)
	default:
		select {
		case <-r.ctx.Done():
		case r.smms <- smm:
		default:
			log.W("dns: fwd: smms full; dropping %s", smm)
		}
	}
}

func (r *resolver) Gateway() Gateway {
	return r.gateway
}

func (r *resolver) MDNS() (MDNSTransport, error) {
	r.RLock()
	defer r.RUnlock()
	if t, ok := r.transports[Local]; ok {
		if mdnst, ok := t.(MDNSTransport); ok {
			return mdnst, nil
		}
		return nil, errTransportNotMDNS
	}
	return nil, errNoSuchTransport
}

func (r *resolver) Translate(tr, fix bool) {
	r.gateway.translate(tr, fix)
}

// stopIfExistsLocked stops the transport if it exists,
// then deletes it from the map.
func (r *resolver) stopIfExistsLocked(id string) {
	if t, ok := r.transports[id]; ok && t != nil {
		core.Go("r.gateway.stopTid", func() {
			err := t.Stop()
			r.gateway.onStopped(id)
			log.VV("dns: stop: %s; err? %v", id, err)
		})
		delete(r.transports, id)
	}
}

// Implements Resolver
func (r *resolver) Add(dt x.DNSTransport) (ok bool) {
	if r.closed.Load() {
		log.W("dns: add: closed for business")
		return false
	}
	if dt == nil || core.IsNil(dt) {
		log.D("dns: cannot add nil transports")
		return false
	}
	t, ok := dt.(Transport)
	if !ok { // unlikely
		return false
	}
	tid := idstr(t)
	if tid == Default || cachedTransport(t) {
		log.W("dns: cannot re-add default/cached transports; ignoring: %s", t.GetAddr())
		return false
	}

	// add transports that are prefixed with "Plus" to the plus()
	// multi-transport, while the supervisor plus() multi-transport
	// itself must be added to r.transports (below)
	if tid != Plus && isPlus(tid) {
		plus, err := r.plus()
		if err != nil {
			log.W("dns: plus: cannot add %s; %v", tid, err)
			return false
		}
		plus.Add(t) // onDNSAdded listener is not called
		return true
	}

	caching := false
	switch t.Type() {
	case DNS53, DNSCrypt, DOH, DOT, ODOH:
		r.Lock()
		// stop existing transport if different
		if oldt := r.transports[tid]; t != oldt {
			r.stopIfExistsLocked(tid)
			r.transports[tid] = t
		}
		// always recreate caching transport
		if ct := NewCachingTransport(t, ttl10m); ct != nil {
			ctid := idstr(ct)
			r.stopIfExistsLocked(ctid)
			r.transports[ctid] = ct
			caching = true
		}
		r.Unlock()

		if tid == System || tid == Goos {
			// TODO: add other resolvers?
			// always add64 after having added the system transport
			core.Gx("r.Add64", func() { r.Add64(tid) })
		}

		core.Go("r.onAdd", func() { r.listener.OnDNSAdded(tid) })
		log.I("dns: add transport %s@%s; caching? %t",
			t.ID(), t.GetAddr(), caching)

		return true
	default:
		log.E("dns: unknown transport(%s) type: %s", t.ID(), t.Type())
	}
	return false
}

func (r *resolver) GetMult(id string) (x.DNSTransportMult, error) {
	return r.GetMultInternal(id)
}

func (r *resolver) GetMultInternal(id string) (TransportMult, error) {
	if r.closed.Load() {
		return nil, errResolverClosed
	}
	r.RLock()
	t, ok := r.transports[id]
	r.RUnlock()

	if ok {
		if tm, ok := t.(TransportMult); ok {
			return tm, nil
		}
		return nil, errTransportNotMult
	}
	return nil, errNoSuchTransport
}

func (r *resolver) dcProxy() (TransportMult, error) {
	return r.GetMultInternal(DcProxy)
}

func (r *resolver) plus() (TransportMult, error) {
	return r.GetMultInternal(Plus)
}

func (r *resolver) GetInternal(id string) (Transport, error) {
	if r.closed.Load() {
		return nil, errResolverClosed
	}

	if t := r.determineTransport(id); t == nil || core.IsNil(t) {
		return nil, errNoSuchTransport
	} else {
		return t, nil
	}
}

func (r *resolver) S() string {
	return r.gateway.S()
}

func (r *resolver) Get(id string) (x.DNSTransport, error) {
	return r.GetInternal(id)
}

func (r *resolver) Remove(tid string) (ok bool) {
	if r.closed.Load() {
		log.W("dns: remove: closed for business")
		return false
	}

	id := tid
	// these IDs are reserved for internal use
	if isReserved(id) {
		log.I("dns: removing reserved transport %s", id)
	}

	r.RLock()
	_, hasTransport := r.transports[id]
	r.RUnlock()

	if hasTransport {
		if id == System || id == Goos {
			core.Gx("r.Remove64", func() { r.Remove64(id) })
		}
		r.Lock()
		r.stopIfExistsLocked(id)
		r.stopIfExistsLocked(CT + id)
		r.Unlock()

		log.I("dns: removed transport %s", id)
	}

	if tm, err := r.dcProxy(); err == nil { // remove from dc-proxy, if any
		hasTransport = tm.Remove(tid) || hasTransport
		hasTransport = tm.Remove(CT+id) || hasTransport
	}

	if tm, err := r.plus(); err == nil { // remove from plus, if any
		hasTransport = tm.Remove(tid) || hasTransport
		hasTransport = tm.Remove(CT+id) || hasTransport
	}

	if hasTransport {
		core.Go("r.onRemove", func() { r.listener.OnDNSRemoved(id) })
	}

	return hasTransport
}

func (r *resolver) IsDnsAddr(ipport netip.AddrPort) bool {
	return r.isDns(ipport)
}

// LookupFor2 implements ResolverSelf.
func (r *resolver) LookupFor2(q []byte, uid string, tids ...string) ([]byte, string, error) {
	if len(q) <= 0 {
		return nil, NoDNS, errNoQuestion
	}
	if uid == core.UNKNOWN_UID_STR {
		uid = protect.UidSelf
	}
	// if len(tids) == 0, use transport from preferences
	return r.forward(q, OriginInternal, uid, tids...)
}

// LookupFor implements ResolverSelf.
func (r *resolver) LookupFor(q []byte, uid string) ([]byte, string, error) {
	if len(q) <= 0 {
		return nil, NoDNS, errNoQuestion
	}

	// prechose tids preferred & fixed when uid is set to 0, -1, or 1051 (common
	// android system components that send DNS requests on behalf of actual apps/uids)
	// to use "fixed" transport to later uncover the actual requesting app/uid during
	// tcp/udp flows (specifically, with preflow)
	if (uid == core.UNKNOWN_UID_STR || uid == core.DNS_UID_STR || uid == core.ANDROID_UID_STR) && r.gateway.fixedTransport() {
		return r.forward(q, OriginInternal, uid, Preferred, Fixed)
	}

	return r.forward(q, OriginInternal, uid)
}

// LocalLookup implements ResovlerSelf.
func (r *resolver) LocalLookup(q []byte) ([]byte, string, error) {
	if r.closed.Load() {
		return nil, NoDNS, errResolverClosed
	}

	loopingBack := settings.Loopingback.Load()
	defaultIsSystemDNS := r.isDefaultSystemDNS()

	// including dns64 and/or alg
	ans, tid, err := r.forward(q, OriginInternal, protect.UidSelf, Default)
	if !defaultIsSystemDNS || loopingBack {
		return ans, tid, err
	} // else: retry with Goos/System, if needed

	// msg may be nil
	if msg := xdns.AsMsg(ans); err != nil || xdns.IsNXDomain(msg) || !xdns.HasRcodeSuccess(msg) {
		log.I("dns: nxdomain via Default (err? %v); attempting Goos for %s", err, xdns.QName(msg))
		ans, tid, err = r.forward(q, OriginInternal, protect.UidSelf, Goos) // Goos is System; see: determineTransport
	} // else: rcode success and nil err; do not fallback on Goos/System

	return ans, tid, err
}

func (r *resolver) forward(q []byte, who, uid string, chosenids ...string) (res0 []byte, tid0 string, err0 error) {
	starttime := time.Now()
	ogsmm := &x.DNSSummary{
		ID:     NoDNS,
		UID:    uid, // may be overwritten to by Cacher via fillSummary
		QName:  invalidQname,
		Status: Start,
		Msg:    errNop.Error(),
	}

	msg, err := unpack(q)
	if err != nil {
		log.W("dns: fwd: for %s; %d not a dns packet %v", uid, len(q), err)
		ogsmm.Latency = time.Since(starttime).Seconds()
		ogsmm.Status = BadQuery
		ogsmm.Msg = err.Error()
		r.queueSummary(ogsmm)
		return nil, NoDNS, err
	}

	// figure out transport to use
	qname := qname(msg)
	qtyp := qtype(msg)
	ogsmm.QName = qname
	ogsmm.QType = qtyp
	ogsmm.Targets = qname

	if len(qname) <= 0 { // unexpected; github.com/celzero/rethink-app/issues/1210
		ogsmm.Latency = time.Since(starttime).Seconds()
		ogsmm.Status = BadQuery
		ogsmm.Msg = errMissingQueryName.Error()
		r.queueSummary(ogsmm)
		return nil, NoDNS, errMissingQueryName
	}

	pref, oqcompleted := core.Grx("r.onQuery", func(_ context.Context) (*x.DNSOpts, error) {
		return r.listener.OnQuery(who, uid, qname, qtyp), nil
	}, listenerTimeout)
	if !oqcompleted || pref == nil {
		log.W("dns: fwd: for %s; no preferences (%t) for %s:%d", uid, pref == nil, qname, qtyp)
		ogsmm.Latency = time.Since(starttime).Seconds()
		ogsmm.Status = ClientError
		ogsmm.Msg = errOnQueryTimeout.Error()
		r.queueSummary(ogsmm)
		return nil, NoDNS, errOnQueryTimeout
	}

	prefuid := pref.UID
	senduid := uid // may be prefuid when oguid is unknown
	run := 0
	if ogsmm.UID == core.UNKNOWN_UID_STR {
		ogsmm.UID = prefuid
		senduid = prefuid
	}

	smm := copySummary(ogsmm)

	// TODO? do not use defer func() and do copy: go.dev/play/p/oGUJepa3VUo
	defer func() {
		r.queueSummary(smm) // always call up to the listener
	}()

runagain:
	run++
	*smm = *copySummary(ogsmm)

	log.V("dns: fwd: 1 for %s (%s); query %s:%d, r%d; [prefs:%v; chosen:%v]", uid, who, qname, qtyp, run, pref, chosenids)

	id, sid, pids, presetIPs := r.preferencesFrom(qname, uint16(qtyp), pref, chosenids...)

	t := r.determineTransport(id)         // id may be empty if pref is nil
	t2 := r.determineTransport(sid)       // sid may be empty
	hasT1 := t != nil && !core.IsNil(t)   // primary transport
	hasT2 := t2 != nil && !core.IsNil(t2) // secondary transport

	log.V("dns: fwd: 2 for %s; query %s:%d, r%d; [prefs:%v; chosen:%v]; id? %s (%t), sid? %s (%t), pid? %s, ips? %v",
		uid, qname, qtyp, run, pref, chosenids, id, hasT1, sid, hasT2, pids, presetIPs)

	if !hasT1 {
		if !hasT2 {
			smm.Latency = time.Since(starttime).Seconds()
			smm.Status = TransportError
			smm.Msg = strings.Join(append(chosenids, id, sid, errNoSuchTransport.Error()), ";")
			return nil, NoDNS, errNoSuchTransport
		}
		t = t2
		t2 = nil
	}

	smm.Type = t.Type()
	smm.ID = idstr(t)

	res1, blocklists, err := r.blockQ(t, t2, msg) // skips if the t, t2 are alg/block-free
	if err == nil {
		if pref.NOBLOCK { // only add blocklists and do not actually block
			smm.Blocklists = blocklists
		} else { // block the query
			b, e := res1.Pack()
			smm.Latency = time.Since(starttime).Seconds()
			smm.Status = Complete
			smm.Blocklists = blocklists
			smm.RData = xdns.GetInterestingRData(res1)
			if e != nil {
				smm.Msg = e.Error()
			} else {
				smm.Msg = errNop.Error()
			}
			log.V("dns: fwd: 3 %s for %s; r%d, query blocked %s:%d by %s", smm.ID, uid, run, qname, qtyp, blocklists)
			return b, smm.ID, e
		}
	} else {
		log.V("dns: fwd: 4 %s for %s; r%d, query NOT blocked %s:%d; why? %v", smm.ID, uid, run, qname, qtyp, err)
	}

	var res2 []byte
	var nonalg, ans1 *dns.Msg // alg'd answer

	// t, t2 could be different from user-selected sid & pid
	// when sid and pid fallback on Default or System DNS
	// in which case, selected proxy must be overriden
	netid := xdns.NetAndProxyID(NetTypeUDP, pids)

	// with t2 as the secondary transport, which could be nil
	nonalg, ans1, err = r.gateway.q(t, t2, presetIPs, netid, uid, msg, smm)

	if smm.Latency <= 0 {
		smm.Latency = time.Since(starttime).Seconds()
	}
	smm.UID = senduid // reset uid as it may have been cleared by cacher

	if nonalg == nil || err != nil { // TODO: servfail?
		if isAlgErr(err) { // alg errs not set when gw.translate is off
			log.W("dns: fwd: 5 %s for %s; r%d, alg error %s for %s:%d", smm.ID, uid, run, err, qname, qtyp)
			smm.Status = NoResponse
		} else if smm.Status == Start {
			smm.Status = InternalError
		}
		err = core.OneErr(err, errNoAnswer)
		smm.Msg = err.Error()
		// both err and res2 are set when res2 has rcode error or servfail
		// summary latency, ips, response, status already set by transport t
		return res2, smm.ID, err
	}

	err = nil        // discard alg errs if any
	if ans1 == nil { // ans1 is nil when alg is disabled
		ans1 = nonalg
	}

	res2, err = ans1.Pack()
	if err != nil {
		smm.Status = BadResponse // TODO: servfail?
		smm.Msg = err.Error()
		return res2, smm.ID, err
	}

	smm.Targets = xdns.GetTargets(ans1)

	ans2, blockedtarget, blocklistnames := r.blockA(t, t2, msg, nonalg, smm.Blocklists)

	isnewans := ans2 != nil
	hasblocklists := len(blocklistnames) > 0
	hasmsg := len(smm.Msg) > 0

	if hasblocklists { // blocklists added even if pref.NOBLOCK is set
		smm.Blocklists = blocklistnames
		smm.BlockedTarget = blockedtarget
	}
	if !hasmsg {
		smm.Msg = errNop.Error() // no error
	}
	// do not block, only add blocklists if NOBLOCK is set
	if !pref.NOBLOCK && isnewans {
		// overwrite if new answer
		ans1 = ans2
		// summary latency, response, status, ips also set by transports
		smm.RTtl = xdns.RTtl(ans2)
		smm.RCode = xdns.Rcode(ans2)
		smm.RData = xdns.GetInterestingRData(ans2)
		smm.Status = Complete
		res2, err = ans2.Pack()
		if err != nil {
			smm.RTtl = 0
			smm.RCode = dns.RcodeFormatError
			smm.Status = BadResponse // TODO: servfail?
			smm.Msg = err.Error()
		}

		log.V("dns: fwd: 6 for %s[%s]; query %s:%d, r%d, smm[data: %s, status: %d] blocked",
			smm.ID, uid, qname, qtyp, run, smm.RData, smm.Status)
		return res2, smm.ID, err
	}

	realips := Netip2Csv(xdns.IPs(nonalg))
	ansblocked := xdns.AQuadAUnspecified(ans1)

	if settings.Debug {
		log.V("dns: fwd: 7 for %s[%s]; query %s:%d, r%d, ips: %s; smm[data: %s, status: %d]; new-ans? %t, blocklists? %t, blocked? %t",
			smm.ID, uid, qname, qtyp, run, realips, smm.RData, smm.Status, isnewans, hasblocklists, ansblocked)
	}

	if run == 1 {
		pref2, ouacompleted := core.Grx("r.onUA."+qname, func(_ context.Context) (*x.DNSOpts, error) {
			return r.listener.OnUpstreamAnswer(smm, pref.Copy(), realips), nil
		}, listenerTimeout)
		if !ouacompleted {
			log.W("dns: fwd: 8 for %s[%s]; preferences2 missing for %s:%d; ips? %s", smm.ID, uid, qname, qtyp, realips)
			smm.Status = ClientError
			smm.Msg = errOnUpstreamAnswerTimeout.Error()
			smm.ID = NoDNS
			return nil, NoDNS, errOnUpstreamAnswerTimeout
		}

		if pref2 != nil && len(pref2.TIDCSV) > 0 && pref2.TIDCSV != pref.TIDCSV {
			pref = pref2
			goto runagain // re-run with new pids
		}

		log.V("dns: fwd: 9 for %s[%s], r%d; preferences2 skipped for %s:%d [ips? %s]: %v",
			smm.ID, uid, run, qname, qtyp, realips, pref2)
	}

	// return transport ID match w/ ID used by alg.go:registerLocked (alg/nat/ptr caches)
	// as ipmapper uses this ID (tid0) subsequently to undoAlg
	return res2, smm.ID, nil
}

// Serve implements Resolver.
func (r *resolver) Serve(proto string, c protect.Conn, uid string) (rx, tx int64, errs []error) {
	if r.closed.Load() {
		err := log.EE("dns: serve: closed for business")
		errs = append(errs, err)
		return
	}

	// if Serve (which is called by common.go:dnsOverride) calls in with a uid
	// that is not UNKNOWN_UID_STR, then we know that the query is from an app
	// and we can presume per app split tunnel is working as expected.
	if len(uid) > 0 && uid != core.ANDROID_UID_STR && uid != core.UNKNOWN_UID_STR && uid != core.DNS_UID_STR {
		r.gateway.splitTunnel()
	}

	switch proto {
	case NetTypeTCP:
		rx, tx, errs = r.accept(c, uid)
	case NetTypeUDP:
		rx, tx, errs = r.reply(c, uid)
	default:
		err := log.EE("dns: unknown proto: %s", proto)
		errs = append(errs, err)
	}
	return
}

func (r *resolver) determineTransport(id string) Transport {
	if len(id) <= 0 {
		return nil
	}
	if id == Default || id == CT+Default {
		r.RLock()
		d := r.transports[Default]
		r.RUnlock()
		return d
	}

	var id0, id1 string
	if id == Local || id == CT+Local { // mdns never cached
		id0 = Local
	} else if id == Alg {
		// if no firewall is setup, alg isn't possible
		if settings.BlockMode.Load() == settings.BlockModeNone {
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
	} else if isPlus(id) {
		id0 = Plus // replace a plus transport with its mult equivalent
	} else if isAnyBlockFree(id) && canUseDefaultDNS(BlockFree) {
		// use Preferred when BlockFree is not available. BlockFree is only
		// added for RDNS endpoints; for other transports, the same transport
		// acts as "BlockFree" provided DNSOpts.NOBLOCK is set to true.
		id0 = BlockFree
		// may technically "leak" DNS queries when Split DNS is true
		// and an app's queries are forced through Preferred
		id1 = Preferred
		if strings.HasPrefix(id, CT) {
			id0 = CT + id0
			id1 = CT + id1
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
	tf = r.transports[Default]
	r.RUnlock()

	// id1 may be CT+Default which doesn't exist and so tf (Default) must be used
	isanydefault := isAnyDefault(id0, id1)
	mayusedefault := canUseDefaultDNS(id0)
	if t0 != nil && (t1 == nil || !mayusedefault || activeTransport(t0)) {
		return t0
	} else if t1 != nil && (!mayusedefault || activeTransport(t1)) {
		log.W("dns: fwd: %s missing or inactive; using %s instead", id0, id1)
		return t1
	} else if tf != nil && (mayusedefault || isanydefault) {
		log.W("dns: fwd: %s & %s missing or inactive; using default", id0, id1)
		return tf // todo: assert tf != nil?
	}

	return nil
}

// dnstcp queries the transport and writes answers to w, prefixed by length.
func (r *resolver) dnstcp(q []byte, w io.WriteCloser, uid string) (written int, err error) {
	ans, _, err := r.forward(q, OriginTunnel, uid)

	rlen := len(ans)
	if rlen <= 0 && err != nil {
		clos(w) // close on client err
		return
	}

	if written, err = writePrefixed(w, ans, rlen); err != nil {
		clos(w) // close on write back err
	} else if written != rlen { // do not close on incomplete writes
		err = fmt.Errorf("dns: tcp: for %s incomplete write: n(%d) != r(%d)", uid, written, rlen)
	}
	return
}

// dnsudp queries the transport and writes answers to w.
func (r *resolver) dnsudp(q []byte, w io.WriteCloser, uid string) (written int, err error) {
	ans, _, err := r.forward(q, OriginTunnel, uid)

	rlen := len(ans)
	if rlen <= 0 && err != nil {
		clos(w) // close on client err
		return
	}

	if written, err = w.Write(ans); err != nil {
		clos(w) // close on write back err
	} else if written != rlen {
		// do not close on incomplete writes
		err = fmt.Errorf("dns: udp: for %s incomplete write: n(%d) != r(%d)", uid, written, rlen)
	}

	return
}

// reply DNS-over-UDP from a stub resolver.
func (r *resolver) reply(c protect.Conn, uid string) (rx, tx int64, errs []error) {
	defer clos(c)

	var rxv, txv atomic.Int64

	var wg sync.WaitGroup
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

		if n, err := c.Read(q); err != nil {
			log.VV("dns: udp: for %s done; tot: %d, t: %s, err: %v",
				uid, cnt, core.FmtTimeAsPeriod(start), err)
			free()
			break
		} else {
			core.Gx("r.reply.do", func() {
				wg.Add(1)
				defer wg.Done()
				defer free()
				m, err := r.dnsudp(q[:n], c, uid)
				logeif(err != nil)("dns: udp: for %s err! tot: %d, t: %s, %v",
					uid, cnt, core.FmtTimeAsPeriod(start), err)
				rxv.Add(int64(m))
				txv.Add(int64(n))
				errs = append(errs, err)
			})
		}
		cnt++
	}
	wg.Wait()
	rx = rxv.Load()
	tx = txv.Load()
	log.VV("dns: udp: for %s done; tot: %d (rx: %d, tx: %d), t: %s", uid, cnt, rx, tx, core.FmtTimeAsPeriod(start))
	return
}

// Accept a DNS-over-TCP socket from a stub resolver, and connect the socket
// to this DNSTransport.
func (r *resolver) accept(c io.ReadWriteCloser, uid string) (rx, tx int64, errs []error) {
	defer clos(c)

	var rxv, txv atomic.Int64

	var wg sync.WaitGroup
	start := time.Now()
	cnt := 0
	qlbuf := make([]byte, 2)
	for {
		n, err := c.Read(qlbuf)
		if n == 0 {
			log.D("dns: tcp: for %s query socket shutdown", uid)
			break
		}
		if err != nil {
			log.W("dns: tcp: for %s err reading from socket: %v", uid, err)
			break // close on read errs
		}
		// TODO: inform the listener?
		if n < 2 {
			log.W("dns: tcp: for %s incomplete query length", uid)
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
			log.D("dns: tcp: for %s done; err: %v", uid, err)
			free()
			break // close on read errs
		}
		if n != int(qlen) {
			free()
			log.W("dns: tcp: for %s incomplete query: %d < %d; tot: %d, t: %s",
				uid, n, qlen, cnt, core.FmtTimeAsPeriod(start))
			break // close on incomplete reads
		}
		core.Gx("r.accept.do", func() {
			wg.Add(1)
			defer wg.Done()
			defer free()
			m, err := r.dnstcp(q[:n], c, uid)
			logeif(err != nil)("dns: tcp: for %s err! tot: %d, t: %s, %v",
				uid, cnt, core.FmtTimeAsPeriod(start), err)
			errs = append(errs, err)
			txv.Add(int64(n))
			rxv.Add(int64(m))
		})
		cnt++
	}
	wg.Wait()
	rx = rxv.Load()
	tx = txv.Load()
	log.VV("dns: tcp: for %s done; tot: %d (rx: %d, tx: %d), t: %s", uid, cnt, rx, tx, core.FmtTimeAsPeriod(start))
	// TODO: Cancel outstanding queries.
	return
}

// StopAll implements TransportMult.
// StopAll stops all transports and closes the resolver.
func (r *resolver) StopAll() {
	r.once.Do(func() {
		defer core.Go("r.onStop", func() { r.listener.OnDNSStopped() })
		r.done()

		if dc, err := r.dcProxy(); err == nil {
			_ = dc.Stop()
		}

		if p, err := r.plus(); err == nil {
			_ = p.Stop()
		}

		// Stop all transports in a separate goroutine to avoid blocking
		core.Go("r.stopAllTransports", func() {
			r.Lock()
			for _, tr := range r.transports {
				_ = tr.Stop()
				// r.gateway.onStopped(id) is not required
				// as the entire setup is closed and going away
			}
			clear(r.transports)
			r.Unlock()
		})

		close(r.smms) // close listener chan
	})
}

func (r *resolver) all() []Transport {
	r.RLock()
	defer r.RUnlock()
	out := make([]Transport, 0, len(r.transports))
	for _, t := range r.transports {
		out = append(out, t)
	}
	return out
}

func (r *resolver) refresh() {
	for _, t := range r.all() {
		// clear caches of cached transports:
		if ct := asCachedTransport(t); ct != nil {
			ct.Clear() // one at a time ...
		}
	}
}

func (r *resolver) Refresh() (string, error) {
	return r.refreshAll()
}

func (r *resolver) refreshAll() (string, error) {
	if r.closed.Load() {
		return "", errResolverClosed
	}

	log.I("dns: refresh transports")

	core.Gx("r.refresh", r.refresh)
	core.Gx("r.refresh.clearcache", dialers.Clear)
	s := tr2csv(r.all())
	if dc, err := r.dcProxy(); err == nil {
		if x, err := dc.Refresh(); err == nil {
			s += "," + x
		}
	}
	if p, err := r.plus(); err == nil {
		if x, err := p.Refresh(); err == nil {
			s += "," + x
		}
	}
	return trimcsv(s), nil
}

func (r *resolver) LiveTransports() string {
	if r.closed.Load() {
		log.W("dns: liveTransports: closed for business")
		return ""
	}
	s := tr2csv(r.all())
	if dc, err := r.dcProxy(); err == nil {
		x := dc.LiveTransports()
		s += "," + x
	}
	if p, err := r.plus(); err == nil {
		x := p.LiveTransports()
		s += "," + x
	}
	return trimcsv(s)
}

func (r *resolver) preferencesFrom(qname string, qtyp uint16, s *x.DNSOpts, chosenids ...string) (id1, id2, pidcsv string, ips []netip.Addr) {
	var x []string  // primary
	var xx []string // secondary
	if s == nil {   // should never happen; but it has during testing (on End())
		log.W("dns: pref: no ns opts for %s", qname)
		return // no-op
	} else {
		x = strings.Split(s.TIDCSV, ",")
		xx = strings.Split(s.TIDSECCSV, ",")
		if y := strings.Split(s.IPCSV, ","); len(y) > 0 {
			ips = make([]netip.Addr, 0, len(y))
			for _, a := range y {
				a = strings.TrimSpace(a)
				if len(a) <= 0 {
					continue
				}
				ip, err := netip.ParseAddr(a)
				if err != nil || !ip.IsValid() {
					log.W("dns: pref: skip bad ip %s for %s", a, qname)
					continue
				}
				ips = append(ips, ip) // unmap?
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

	if len(x) <= 0 { // x may be nil
		log.W("dns: pref: no tids for %s", qname)
		// no-op
	} else {
		// TODO: fallback on all id1s
		id1 = r.chooseOne(x...)
		id2 = r.chooseOne(xx...) // mostly, just 0 or 1 secondary
	}

	if !firstEmpty(chosenids) && len(chosenids) > 0 {
		// chosen ID overrides all except:
		if (isPlus(id1) || isPlus(id2)) && isAnyDefault(chosenids...) {
			// Plus overrides Default
			id1 = Plus
			id2 = ""
			log.D("dns: pref: use Plus instead of Default for %s", qname)
		} else {
			id1 = chosenids[0] // never empty
			id2 = ""           // wipe out id2 if not set; use just id1
			if len(chosenids) > 1 {
				id2 = chosenids[1] // may be empty, but that's ok
			}
			log.D("dns: pref: use chosen tr(%s, %s) for %s", id1, id2, qname)
		}
	} else if isAnyIPUnspecified(ips) || isAnyBlockAll(x...) {
		// BlockAll must appear in primary TIDCSV
		id1 = BlockAll // just one transport, BlockAll, if set
		id2 = ""
	} else if reqid := r.requiresGoosOrLocal(qname); len(reqid) > 0 {
		// use approp transport given a qname
		log.D("dns: pref: use suggested tr(%s) for %s", reqid, qname)
		id1 = reqid
		id2 = ""
	} else if isAnyFixed(x...) || isAnyFixed(xx...) {
		if id1 != Fixed && id1 != CT+Fixed { // Fixed must always be the primary transport
			id2 = id1
			id1 = Fixed
		}
		if len(id2) <= 0 {
			id2 = Preferred
		}
		log.VV("dns: pref: use fixed tr(%s, %s) for %s", id1, id2, qname)
		// s.NOBLOCK must be respected
		// s.PIDCSV must be respected
	}
	if len(ips) > 0 {
		log.D("dns: pref: preset ips (no block) %v for %s", ips, qname)
		s.NOBLOCK = true // skip blocks if ips are set (even if unspecified ips)
		id2 = ""         // no secondary transport
	}
	if isAnyLocal(id1, id2) { // use one transport, Local, if set
		id1 = Local
		id2 = ""
	}
	if isAnyBlockFree(id1, id2) {
		if !s.NOBLOCK {
			log.W("dns: pref: tr for %s; override NOBLOCK", id1, id2, qname)
			s.NOBLOCK = true
		}
	}

	if len(s.PIDCSV) > 0 {
		pidcsv = overrideProxyIfNeeded(s.PIDCSV, id1, id2)
	} else {
		pidcsv = NetNoProxy
	}
	return
}

func (r *resolver) requiresGoosOrLocal(qname string) (id string) {
	if strings.HasSuffix(qname, ".local") || xdns.IsMDNSQuery(qname) {
		id = Local
	} else if !settings.SystemDNSForUndelegatedDomains.Load() {
		// todo: remove this once we let users "pin" domains to resolvers
		// github.com/celzero/rethink-app/issues/1153
		// skip override when preventing DNS capture on port53 is turned off
	} else if len(qname) > 0 && r.localdomains.HasAny(qname) {
		id = Goos // system is primary; see: transport.go:determineTransports()
	}
	return
}

func (r *resolver) chooseOne(ids ...string) (theone string) {
	if len(ids) <= 0 {
		return ""
	}
	if isAnyPlus(ids...) { // prefer Plus, if set
		return Plus
	}
	if len(ids) == 1 {
		return ids[0]
	}

	trs := make([]Transport, 0, len(ids))
	r.RLock()
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if t := r.transports[id]; t != nil {
			trs = append(trs, t)
		}
	}
	r.RUnlock()

	best, preferred, recoverables, errored, ended := Categorize(trs)
	if settings.Debug {
		defer func() {
			loged(len(theone) <= 0)("dns: pref: chose: %s from best(%v) prefer(%v) recov(%v) err(%v) dead(%v)",
				theone, best, preferred, recoverables, errored, ended)
		}()
	}

	if len(best) > 0 {
		return idstr(best[0])
	} else if len(preferred) > 0 {
		return idstr(preferred[0])
	} else if len(recoverables) > 0 {
		return idstr(core.ChooseOne(recoverables))
	} else if len(errored) > 0 {
		return idstr(core.ChooseOne(errored))
	}
	log.E("dns: pref: no transports for %v [all ended? %v]", ids, ended)
	return ""
}

func Categorize(ts []Transport) (best []Transport, preferred []Transport, recoverables []Transport, errored []Transport, ended []Transport) {
	for _, t := range ts {
		switch t.Status() {
		case Complete:
			best = append(best, t)
		case Start, NoResponse, BadQuery:
			preferred = append(preferred, t)
		case BadResponse:
			preferred = append(preferred, t)
		case InternalError, TransportError:
			recoverables = append(recoverables, t)
		case DEnd, Paused, Unknown: // discard non-active transports
			ended = append(ended, t)
		default: // ClientError, SendFailed
			errored = append(errored, t)
		}
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

// meta proxies like pid == Auto are not considered local.
func IsLocalProxy(pid string) bool {
	return len(pid) <= 0 ||
		pid == NetBaseProxy ||
		pid == NetExitProxy ||
		pid == NetNoProxy
}

// return true ipn.Auto
func IsAutoProxy(pid string) bool {
	return pid == NetAutoProxy
}

// RegisterAddrs registers IP ports with all dialers for a given hostname.
// If id is dnsx.Bootstrap, the hostname is "protected" from re-resolutions.
// hostname is a domain name, and as a special case, can be protect.UidSelf or protect.UidSystem.
func RegisterAddrs(id, hostname string, ipps []string) (ok bool) {
	var ipset *ipmap.IPSet
	var addrs []netip.Addr
	id, _ = strings.CutPrefix(id, CT)
	if isProtected(id) {
		log.I("dns: protected %s! %s => %v", id, hostname, ipps)
		ipset, ok = dialers.NewProtected(hostname, ipps)
	} else {
		log.I("dns: regular %s! %s => %v", id, hostname, ipps)
		ipset, ok = dialers.New(hostname, ipps)
	}
	if ipset != nil {
		addrs = ipset.Addrs()
	}
	log.I("dns: reg regular/protected done %s! %s[+%v] => %v", id, hostname, ipps, addrs)
	return
}

func Fastest(a, b Transport) int {
	if a == nil || b == nil {
		return 0 // unlikely
	}
	return int(a.P50() - b.P50())
}

func IsEncrypted(t Transport) bool {
	return t != nil && isEncrypted(t.Type())
}

func isEncrypted(t string) bool {
	return t == DOT || t == DOH || t == DNSCrypt || t == ODOH
}

func isProtected(id string) bool {
	return id == Bootstrap || id == System || id == Default || id == Local || isPlus(id)
}

func isReserved(id string) bool {
	switch id {
	case Default, Goos, System, Local, Alg, Plus, DcProxy, BlockAll, Preferred, Bootstrap, BlockFree, Fixed, Preset:
		return true
	case CT + Default, CT + Goos, CT + System, CT + Local, CT + Alg, CT + Plus, CT + DcProxy, CT + BlockAll,
		CT + Bootstrap, CT + Preferred, CT + BlockFree, CT + Fixed, CT + Preset:
		return true
	}
	return false
}

func canUseDefaultDNS(id string) bool {
	switch id {
	// system can never be subst by default; only by Goos
	case System, CT + System:
		return false
	// no other transport can do what mdns does
	case Local, CT + Local:
		return false
	case Alg, Preferred, Plus, BlockFree:
		return settings.DefaultDNSAsFallback.Load()
	case CT + Alg, CT + Preferred, CT + Plus, CT + BlockFree:
		return settings.DefaultDNSAsFallback.Load()
	}
	return false
}

// Also accounts for prefixes such as CT+ID
func isTransportID(match string, ids ...string) bool {
	return slices.Contains(ids, match)
}

func isAnyBlockAll(ids ...string) bool {
	return isTransportID(BlockAll, ids...)
}

func isAnyBlockFree(ids ...string) bool {
	return isTransportID(BlockFree, ids...)
}

func isAnyFixed(ids ...string) bool {
	return isTransportID(Fixed, ids...)
}

func isAnyIPUnspecified(ips []netip.Addr) bool {
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

func isAnyPlus(ids ...string) bool {
	return slices.ContainsFunc(ids, isPlus)
}

func isAnyDefault(ids ...string) bool {
	return isTransportID(Default, ids...)
}

func CanUseProxy(id string) bool {
	switch id {
	case Goos, CT + Goos, Local, CT + Local, System, CT + System:
		return false
	case Preset, CT + Preset:
		return false
	case Default, CT + Default, Bootstrap, CT + Bootstrap:
		// note that, if Default is System DNS, then upstream.go
		// will not proxy even if CanUseProxy returns true, and pid is set.
		return canProxyDefault()
	}
	return true
}

func overrideProxyIfNeeded(pid string, ids ...string) string {
	for _, id := range ids {
		switch id {
		// notes:
		// 1. Goos is anyway hard-coded to use NetExitProxy.
		// 2. Plus simply delegates queries to underlying servers,
		// which may or may not use proxies.
		case Goos, Local: // exit
			return NetExitProxy
		case CT + Goos, CT + Local: // exit
			return NetExitProxy
		case System, Preset: // base
			return NetBaseProxy
		case CT + System, CT + Preset: // base
			return NetBaseProxy
		case Default, CT + Default, Bootstrap, CT + Bootstrap: // may be proxy
			return proxyForDefault(pid)
		}
	}
	return pid // as-is
}

func skipBlock(tr ...Transport) bool {
	for _, t := range tr {
		if t == nil {
			continue
		}
		switch idstr(t) { // Plus/CT+Plus to skip blocks conditionally?
		case BlockFree, Alg:
			return true
		case CT + BlockFree, CT + Alg:
			return true
		case Default, CT + Default, Bootstrap, CT + Bootstrap:
			return canBlockDefault()
		}
	}
	return false
}

func (r *resolver) isDefaultSystemDNS() (y bool) {
	if dtr, _ := r.GetInternal(Default); dtr != nil {
		// todo: a better way to determine whether Default is SystemDNS
		// Default is usually SystemDNS if it is of type DNS53
		y = dtr.Type() == DNS53
	}
	return
}

func canBlockDefault() bool {
	// TODO: check for gateway.split?
	return settings.Loopingback.Load()
}

func canProxyDefault() bool {
	// TODO: check for gateway.split?
	// TODO: do not allow proxying when Default is mapped to Goos/System
	return settings.Loopingback.Load()
}

func proxyForDefault(pid string) string {
	if canProxyDefault() {
		return pid
	}
	return NetBaseProxy
}

func skipInternalCache(tids ...string) bool {
	return isAnyBlockAll(tids...)
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

func tr2csv(ts []Transport) string {
	s := ""
	for _, t := range ts {
		if activeTransport(t) {
			s += idstr(t) + ","
		}
	}
	return trimcsv(s)
}

func trimcsv(s string) string {
	return strings.Trim(s, ",")
}

func CryptoPrefix(nopki, ech bool) string {
	if !settings.Debug {
		return ""
	}

	if nopki {
		return noPkiPrefix
	}
	if ech {
		return echPrefix
	}
	return ""
}

func TransportPrefix(id string) string {
	if !settings.Debug {
		return ""
	}

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
	case Plus, CT + Plus:
		return plusprefix
	case Preset:
		return presetprefix
	case Fixed:
		return fixedprefix
	}
	return ""
}

func asCachedTransport(t Transport) Cacher {
	if ct, ok := t.(Cacher); ok {
		return ct
	}
	return nil
}

func cachedTransport(t Transport) bool {
	return strings.HasSuffix(idstr(t), CT) ||
		strings.HasPrefix(t.GetAddr(), cacheprefix)
}

func WillErr(t Transport) *QueryError {
	switch t.Status() {
	case DEnd:
		return NewEndQueryError()
	case Paused:
		return NewPausedQueryError()
	}
	return nil
}

func isPlus(id string) bool {
	return strings.HasPrefix(id, Plus) || strings.HasPrefix(id, CT+Plus)
}

func activeTransport(t Transport) bool {
	st := t.Status()
	return st != DEnd && st != Paused && st != Unknown
}

func clos(c io.Closer) {
	core.CloseOp(c, core.CopRW)
}

func firstEmpty(arr []string) bool {
	return len(arr) <= 0 || len(arr[0]) <= 0
}
