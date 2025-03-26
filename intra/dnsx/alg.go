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
	"hash/fnv"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

const (
	timeout = 15 * time.Second
	ttl2m   = 2 * time.Minute // 2m ttl for alg/nat ip

	key4 = ":a"
	key6 = ":aaaa"

	notransport = "NoTransport"

	maxiter = 100 // max number alg/nat evict iterations
)

type iptype int

const (
	typalg iptype = iota
	typreal
	typsecondary
)

var (
	// 100.64.x.x
	rfc6598    = []uint8{100, 64, 0, 1}
	rfc8215a   = []uint16{0x64, 0xff9b, 0x1, 0xda19, 0x100, 0x0, 0x0, 0x0}
	rfc3068ip4 = netip.AddrFrom4([4]uint8{192, 88, 99, 114})
	rfc3068ip6 = netip.AddrFrom16([16]byte{0x20, 0x02, 0xF1, 0x3D, 0x00, 0x01, 0xDA, 0x19, 0x01, 0x92, 0x00, 0x88, 0x00, 0x99, 0x01, 0x14})
	// [192.88.99.114, 2002:f13d:1:da19:192:88:99:114] go.dev/play/p/-0MJenRF5pm
	fixedRealIPs = []netip.Addr{rfc3068ip4, rfc3068ip6}

	zeroaddr = netip.Addr{}
	anyaddr4 = netip.IPv4Unspecified()
	anyaddr6 = netip.IPv6Unspecified()

	errAlgNoTransport    = errors.New("no alg transport")
	errAlgNotAvail       = errors.New("no valid alg ips")
	errAlgCannotRegister = errors.New("cannot register alg ip")
	errAlgCannotSubst    = errors.New("cannot substitute alg ip")
)

func isAlgErr(err error) bool {
	return (err == errAlgCannotRegister || err == errAlgNotAvail || err == errAlgCannotSubst)
}

type Gateway interface {
	// given an alg or real ip, retrieves assoc real ips as csv, if any
	X(maybeAlg netip.Addr, uid string, tids ...string) (realips []netip.Addr, undidAlg bool)
	// given an alg or real ip, retrieves assoc dns names as csv, if any
	PTR(maybeAlg netip.Addr, force bool) (domaincsv string, didForce bool)
	// given domain, retrieve assoc alg ips or real ips as csv, if any
	RESOLV(domain, uid string) []netip.Addr
	// given an alg or real ip, retrieve assoc blocklists as csv, if any
	RDNSBL(maybeAlg netip.Addr) (blocklistcsv string)
	// translate overwrites ip answers to alg ip & fixed ip answers
	translate(yes bool)
	// splitTunnel sets per-app split tunneling on/off
	splitTunnel()
	// Query using t1 as primary transport and t2 as secondary and preset as pre-determined ip answers
	q(t1, t2 Transport, preset []netip.Addr, network, uid string, q *dns.Msg, s *x.DNSSummary) (*dns.Msg, error)
	// onStopped is called when a transport tid is stopped. Gateway invalidates its local caches, if any.
	onStopped(tid string)
	// clear obj state
	stop()
}

type secans struct {
	ips []netip.Addr
	smm *x.DNSSummary
	pri bool // is secans got from primary transport?
}

func (sec *secans) initIfNeeded() {
	// ptr reciever updates all secans in-place:
	// go.dev/play/p/wjBd1TC59zN
	if sec.ips == nil {
		sec.ips = []netip.Addr{}
	}
	if sec.smm == nil {
		sec.smm = new(x.DNSSummary)
	}
}

type expaddr struct {
	ips []netip.Addr
	ttl time.Time
}

func (a expaddr) all() []netip.Addr {
	return a.get(xall)
}

func (a expaddr) alive() []netip.Addr {
	return a.get(xalive)
}

// fresh returns false if a has expired or if a is zero-value.
func (a expaddr) fresh() bool {
	return !a.ttl.IsZero() && time.Now().Before(a.ttl)
}

func (a expaddr) after(b expaddr) bool {
	if a.ttl.IsZero() {
		return b.ttl.IsZero()
	}
	return a.ttl.After(b.ttl)
}

func (a expaddr) get(s xaddrstatus) []netip.Addr {
	if a.ips == nil {
		return nil
	}
	if s == xalive && !a.fresh() {
		return nil
	}
	return a.ips
}

type xips struct {
	// protects pri, aux
	pmu *sync.RWMutex
	// resolved v6 or v4 by tid; may be nil
	pri map[string]expaddr
	// resolved by secondary tid for a uid, v6 or v4; may be nil
	aux map[string]expaddr
}

type xaddrstatus bool

const (
	xalive xaddrstatus = true
	xall   xaddrstatus = false
)

type xaddrtyp uint8

const (
	xpri xaddrtyp = 0
	xsec xaddrtyp = 1
)

func (xat xaddrtyp) String() string {
	switch xat {
	case xpri:
		return "pri"
	case xsec:
		return "sec"
	default:
		return "???"
	}
}

func (xst xaddrstatus) String() string {
	if xst {
		return "alive"
	}
	return "all"
}

func makeXipStatus(alive bool) xaddrstatus {
	return xaddrstatus(alive)
}

// NewXips returns a new xips object with primary and secondary ips.
// May return nil if tid is empty.
func NewXips(tid, uid string, pri, sec []netip.Addr, ttl time.Time) *xips {
	if len(tid) <= 0 {
		panic("alg: xips: tid cannot be empty")
	}

	x := &xips{
		pmu: new(sync.RWMutex),
		pri: make(map[string]expaddr),
		aux: make(map[string]expaddr), // sec may be nil
	}
	// id == "" for dnsx.NoDNS, in which case pri should be empty
	if len(pri) > 0 { // pri may be nil
		x.pri[tid] = expaddr{pri, ttl}
	}
	if len(uid) <= 0 {
		uid = core.UNKNOWN_UID_STR
	}
	if len(sec) > 0 { // sec may be same as pri
		x.aux[tid+uid] = expaddr{sec, ttl}
	}
	return x
}

func flatten[K comparable, V any](m map[K]V, upto uint) []V {
	outv := make([]V, 0, upto)
	for _, v := range m {
		if upto != 0 && uint(len(outv)) >= upto {
			break
		}
		outv = append(outv, v)
	}
	return outv
}

// primary ips from all tids
func (p *xips) primary(s xaddrstatus) (out []netip.Addr) {
	return p.ips(xpri, s)
}

// secondary ips for all tids+uids
func (p *xips) sec(s xaddrstatus) (out []netip.Addr) {
	// as far as secondary is concerned, only live ips matter;
	// expired ips should not be used for allow/deny decisions.
	return p.ips(xsec, s)
}

// secondary ip by a given tid+uid pair
func (p *xips) secof(tid, uid string) (out []netip.Addr) {
	// as far as secondary is concerned, only live ips matter;
	// expired ips should not be used for allow/deny decisions.
	return p.ipsFor(tid, uid, xsec, xalive)
}

func (p *xips) ips(t xaddrtyp, s xaddrstatus) (out []netip.Addr) {
	p.pmu.RLock()
	defer p.pmu.RUnlock()

	g := p.pri
	if t == xsec {
		g = p.aux
	}
	const all = 0
	for _, v := range flatten(g, all) {
		out = append(out, v.get(s)...)
	}
	return
}

// realips returns all live primary ips for a given uid
func (p *xips) realips(uid string, s xaddrstatus) (pri []netip.Addr) {
	if p == nil {
		return nil
	}

	pri = p.primary(s)

	zz := p.zz(uid)
	if (s == xalive && len(pri) > 0) && zz {
		// if aux had unspecified ips, then append those to
		// primary ips. if aux has proper ips or no ips,
		// those are made redundant by primary.
		pri = append(pri, anyaddr4, anyaddr6)
	}
	log.VV("alg: xips: x(%s): zz(%s)? %t; %v", s, uid, zz, pri)
	return pri // may be nil / empty
}

func (p *xips) zz(uid string) bool {
	if p == nil {
		return false
	}
	return anyUnspecified(p.secof(notransport, uid))
}

// realipsFor returns all live primary ips for a given tid+uid pair
func (p *xips) realipsFor(tid, uid string, s xaddrstatus) (pri []netip.Addr) {
	return p.ipsFor(tid, uid, xpri, s)
}

func (p *xips) ipsFor(tid, uid string, t xaddrtyp, s xaddrstatus) (out []netip.Addr) {
	if p == nil {
		return nil
	}

	if t == xpri && (tid == notransport || tid == NoDNS || len(tid) <= 0) {
		out = p.realips(uid, s)
		log.VV("alg: xips: xof(%s,%s): no tid? %s[%s]; returning all %v", t, s, tid, uid, out)
		return
	}

	p.pmu.RLock()
	defer p.pmu.RUnlock()

	if t == xsec { // ignore alive for secondary
		if len(uid) <= 0 {
			uid = core.UNKNOWN_UID_STR
		}
		if tid == notransport || tid == NoDNS || len(tid) <= 0 {
			for k, v := range p.aux {
				if strings.HasSuffix(k, uid) {
					out = append(out, v.get(s)...)
				}
			}
		} else if v, ok := p.aux[tid+uid]; ok {
			out = v.get(s)
		}
	} else if s == xalive {
		out = p.pri[tid].alive()
	} else {
		out = p.pri[tid].all()
	}

	log.VV("alg: xips: xof(%s,%s): tid %s + uid %s; %v", t, s, tid, uid, out)
	return
}

func (p *xips) rmv(tid string) (done bool) {
	if p == nil {
		return
	}
	if len(tid) <= 0 || tid == NoDNS || tid == notransport {
		return
	}

	i, j := 0, 0
	p.pmu.Lock()
	defer p.pmu.Unlock()
	if xaddr := p.pri[tid]; xaddr.fresh() {
		i++
		xaddr.ttl = time.Now() // mark as expired
		p.pri[tid] = xaddr
	}
	for k, v := range p.aux {
		if strings.HasPrefix(k, tid) && v.fresh() {
			j++
			done = done || true
			v.ttl = time.Now() // mark as expired
			p.aux[k] = v
		}
	}
	log.VV("alg: xips: rmv(%s): pri(%d), sec(%d); ok? %t", tid, i, j, done)
	return i > 0 || j > 0
}

// block returns true if any secondary ip is unspecified
func anyUnspecified(ips []netip.Addr) bool {
	// unspecified ips expected to be in aux
	// primary must never have unspecified ips
	for _, ip := range ips {
		if ip.IsUnspecified() {
			return true
		}
	}
	return false
}

// each iterates over each primary ip
func (p *xips) each(f func(ip netip.Addr)) {
	for _, ip := range p.primary(xall) {
		f(ip)
	}
	for _, ip := range p.sec(xall) {
		f(ip)
	}
}

func (p *xips) merge(q *xips) {
	if p == nil || q == nil {
		return
	}

	p.pmu.Lock() // write lock on p
	defer p.pmu.Unlock()
	q.pmu.RLock() // read lock on q
	defer q.pmu.RUnlock()

	for qk, qv := range q.pri {
		if pv, ok := p.pri[qk]; !ok || !pv.fresh() {
			p.pri[qk] = qv // copy v from q
		} else {
			ips := copyUniq(pv.alive(), qv.alive())
			ttl := pv.ttl
			if !pv.after(qv) {
				// ips from aa & v both get assigned the latest ttl
				// which is strictly incorrect, but for accounting
				// purposes (that is, algip->realip translations),
				// it is preferable to keep as many realips around
				// as possible (even at the slight cost of correctness).
				ttl = qv.ttl
			}
			p.pri[qk] = expaddr{ips, ttl}
		}
	}

	for qk, qv := range q.aux {
		if pv, ok := p.aux[qk]; !ok || !pv.fresh() {
			p.pri[qk] = qv
		} else {
			ips := copyUniq(pv.alive(), qv.alive())
			ttl := pv.ttl
			if !pv.after(qv) {
				ttl = qv.ttl
			}
			p.pri[qk] = expaddr{ips, ttl}
		}
	}
}

type baseans struct {
	ips        *xips     // all ip answers, v6+v4; may be nil
	domains    []string  // all domain names in an answer (incl qname)
	blocklists string    // csv blocklists containing qname per active config at the time
	ttl        time.Time // ttl for this alg translation
}

// fresh returns false if a has expired or if a is nil
func (a *baseans) fresh() bool {
	if a == nil {
		return false
	}
	return !a.ttl.IsZero() && a.ttl.After(time.Now())
}

type algans struct {
	algip netip.Addr // generated answer, v6 or v4
	*baseans
}

func (a *algans) extend(by time.Duration) {
	a.ttl = time.Now().Add(by)
}

func (a *algans) after(b *algans) bool {
	if a.ttl.IsZero() {
		return b.ttl.IsZero()
	}
	return a.ttl.After(b.ttl)
}

func (a *algans) merge(b *algans) {
	if a == nil || b == nil {
		return
	}
	if a.ips != nil {
		a.ips.merge(b.ips)
	} else {
		a.ips = b.ips
	}
	a.domains = copyUniq(a.domains, b.domains)
	a.blocklists = b.blocklists // TODO: merge?
	if b.after(a) {
		a.ttl = b.ttl
	}
}

// TODO: Keep a context here so that queries can be canceled.
type dnsgateway struct {
	sync.RWMutex                         // protects alg, nat, octets, hexes
	alg          map[string]*algans      // domain+type => ans
	nat          map[netip.Addr]*baseans // algip => baseans
	ptr          map[netip.Addr]*baseans // primaryip => baseans
	octets       []uint8                 // ip4 octets, 100.x.y.z
	hexes        []uint16                // ip6 hex, 64:ff9b:1:da19:0100.x.y.z

	// fields below are never reassigned

	rdns  RdnsResolver // local and remote rdns blocks
	dns64 NatPt        // dns64/nat64
	chash bool         // use consistent hashing to generate alg ips

	// fields below are mutable

	mod   atomic.Bool // modify realip to algip
	split atomic.Bool // per-app split tunneling
}

var _ Gateway = (*dnsgateway)(nil)

// NewDNSGateway returns a DNS ALG, ready for use.
func NewDNSGateway(pctx context.Context, outer RdnsResolver, dns64 NatPt) (t *dnsgateway) {
	alg := make(map[string]*algans)
	nat := make(map[netip.Addr]*baseans)
	ptr := make(map[netip.Addr]*baseans)

	t = &dnsgateway{
		alg:    alg,
		nat:    nat,
		ptr:    ptr,
		rdns:   outer,
		dns64:  dns64,
		octets: rfc6598,
		hexes:  rfc8215a,
		chash:  true,
	}

	context.AfterFunc(pctx, t.stop)
	log.I("alg: setup done")
	return
}

func (t *dnsgateway) translate(yes bool) {
	prev := t.mod.Swap(yes)
	log.I("alg: translate? prev(%t) > now(%t)", prev, yes)
}

func (t *dnsgateway) splitTunnel() {
	if t.split.Load() {
		return
	}
	t.split.Store(true)
	log.I("alg: splitTunnel turned on")
}

func (t *dnsgateway) onStopped(tid string) {
	if len(tid) <= 0 {
		return
	}

	ach := make(chan *xips, len(t.alg))
	defer close(ach)

	go func() {
		n := 0
		for x := range ach {
			if x.rmv(tid) {
				n++
			}
		}
		log.I("alg: onStopped(%s): removed %d alg<>realip translations", tid, n)
	}()

	t.RLock()
	defer t.RUnlock()
	for _, algans := range t.alg {
		if algans != nil {
			ach <- algans.ips
		}
	}
}

// Implements Gateway
func (t *dnsgateway) stop() {
	t.Lock()
	defer t.Unlock()

	clear(t.alg)
	clear(t.nat)
	clear(t.ptr)
	t.octets = rfc6598
	t.hexes = rfc8215a
}

func (t *dnsgateway) fromInternalCache(tid, uid string, q *dns.Msg, typ iptype) (ans *dns.Msg, err error) {
	if skipInternalCache(tid) {
		return nil, errSkipInternalCache
	}
	a, aaaa := xdns.HasAQuestion(q), xdns.HasAAAAQuestion(q)
	if !a || !aaaa {
		return nil, errNilCacheResponse
	}

	domain := qname(q)

	t.RLock()
	cached4s, cached6s, stale, _ := t.resolvLocked(domain, typ, tid, uid)
	t.RUnlock()

	var cachedips []netip.Addr
	if a && len(cached4s) > 0 {
		cachedips = cached4s
	} else if aaaa && len(cached6s) > 0 {
		cachedips = cached6s
	}

	log.VV("alg: response for %s (v4? %t / v6? %t) realip; in cache? %v (or stale? %v)",
		domain, a, aaaa, cachedips, stale)

	if len(cachedips) <= 0 {
		return nil, errNilCacheResponse
	}
	return xdns.AQuadAForQuery(q, cachedips...)
}

func (t *dnsgateway) qp(t1 Transport, uid, network string, q *dns.Msg, innersummary *x.DNSSummary) (ans *dns.Msg, err error) {
	// For A/AAAA queries, check if xips has an answer for the qname.
	if ans, err := t.fromInternalCache(idstr(t1), uid, q, typreal); err == nil {
		innersummary.Cached = true
		return ans, nil
	}
	return Req(t1, network, q, innersummary)
}

func (t *dnsgateway) qs(t2 Transport, uid, network string, msg *dns.Msg, t1res <-chan *dns.Msg) <-chan secans {
	t2res := make(chan secans, 1)

	go func() {
		defer close(t2res)

		qname := xdns.QName(msg)

		r, ok := core.Grx("alg.qs."+qname, func(_ context.Context) (secans, error) {
			return t.querySecondary(t2, uid, network, msg, t1res), nil
		}, timeout)

		if !ok {
			log.W("alg: skip; qs timeout; tr2: %s, qname: %s", idstr(t2), qname)
		}

		r.initIfNeeded() // r may be nil on Grx:timeout

		t2res <- r // may be zero secans
	}()
	return t2res
}

func (t *dnsgateway) querySecondary(t2 Transport, uid, network string, msg *dns.Msg, t1res <-chan *dns.Msg) (result secans) {
	var r *dns.Msg
	var err error

	result.initIfNeeded() // result must not be reassigned

	// check if the question is blocked
	if msg == nil || !xdns.HasAnyQuestion(msg) {
		result.smm.Msg = errNoQuestion.Error()
		return // not a valid dns message
	} else if ok := xdns.HasAQuadAQuestion(msg) || xdns.HasHTTPQuestion(msg) || xdns.HasSVCBQuestion(msg); !ok {
		result.smm.Msg = errNotEnoughAnswers.Error()
		return // not a dns question we care about
	} else if ans1, blocklists, err2 := t.rdns.blockQ( /*maybe nil*/ t2, nil, msg); err2 == nil {
		// if err !is nil, then the question is blocked
		if ans1 != nil && len(ans1.Answer) > 0 {
			result.ips = append(result.ips, xdns.AAnswer(ans1)...)
			result.ips = append(result.ips, xdns.AAAAAnswer(ans1)...)
		} // noop: for HTTP/SVCB, the answer is always empty
		result.smm.Blocklists = blocklists
		result.smm.Status = Complete
		return
	}

	// no secondary transport; check if there's already an answer to work with
	if t2 == nil || core.IsNil(t2) {
		r = <-t1res       // from primary transport, t1; r may be nil
		result.pri = true // secans not from secondary
	} else {
		// check if there's already a cached answer to work with
		// note: secondary ips are not cached per-transport (see xips.sec())
		if r, err = t.fromInternalCache(idstr(t2), uid, msg, typsecondary); err != nil {
			// else: query secondary to get answer for q
			r, err = Req(t2, network, msg, result.smm)
		}
	}

	// check if answer r is blocked; r is either from t2 or from <-in
	if err != nil || r == nil || !xdns.HasAnyAnswer(r) { // not a valid dns answer
		log.D("alg: skip; sec transport %s; nores? %t, err? %v", idstr(t2), r == nil, err)
		result.smm.Msg = errNotEnoughAnswers.Error()
		return
	} else if a, blocklistnames := t.rdns.blockA( /*may be nil*/ t2, nil, msg, r, result.smm.Blocklists); a != nil {
		// if "a" is not nil, then the r is blocked
		if len(blocklistnames) > 0 {
			result.smm.Blocklists = blocklistnames
		}
		// when rdns.blockA blocks, A/AAAA must be 0.0.0.0/::
		// and HTTPS/SVCB is an empty answer section
		// see: xdns.RefusedResponseFromMessage
		// if len(a.Answer) > 0 {
		//	result.ips = append(result.ips, xdns.AAnswer(a)...)
		//	result.ips = append(result.ips, xdns.AAAAAnswer(a)...)
		// }
		result.ips = append(result.ips, anyaddr4, anyaddr6)
		return
	} else {
		if len(blocklistnames) > 0 {
			result.smm.Blocklists = blocklistnames
		}
		if xdns.AQuadAUnspecified(r) {
			// A/AAAA must be 0.0.0.0/::, set UpstreamBlocks to true
			result.smm.UpstreamBlocks = true
			// discard all other answers
			result.ips = append(result.ips, anyaddr4, anyaddr6)
		} else if xdns.HasAnyAnswer(r) {
			ip4hints := xdns.IPHints(r, dns.SVCB_IPV4HINT)
			ip6hints := xdns.IPHints(r, dns.SVCB_IPV6HINT)
			result.ips = append(result.ips, xdns.AAnswer(r)...)
			result.ips = append(result.ips, xdns.AAAAAnswer(r)...)
			result.ips = append(result.ips, ip4hints...)
			result.ips = append(result.ips, ip6hints...)
			// TODO: result.targets?
		}
		return
	}
}

// Implements Gateway
// preset may be nil
func (t *dnsgateway) q(t1, t2 Transport, preset []netip.Addr, network, uid string, q *dns.Msg, smm *x.DNSSummary) (outmsg *dns.Msg, outerr error) {
	var ansin *dns.Msg // answer got from transports
	var err error

	usepreset := len(preset) > 0                    // preset may be nil
	mod := t.mod.Load()                             // allow alg?
	discarduid := !t.split.Load()                   // do not split tunnel?
	usefixed := !usepreset && isAnyFixed(idstr(t1)) // fixed realips?
	skipcache := skipInternalCache(idstr(t1), idstr(t2))
	// do not perform alg or use its "xip" caches by the way of ptr, nat, alg
	// maps for synthesized response and block-all transport. That's because
	// BlockAll and synth responses are "ephemeral" in that, they may be based
	// on a UID and not just a tid + qname + qtype (cf: DNSListener.OnQuery)
	// but ptr, nat, alg maps are only tied to (tid, qname, qtype) tuple. Also,
	// it isn't necessary that if a qname is blocked right now will be blocked
	// by the next OnQuery() as the rules are dynamic (for instance, a uid+qname
	// may be blocked because device is in keyguard/locked state but allowed
	// when the user is present (device is unlocked).
	dontalg := usepreset || skipcache
	synthAns := usepreset || usefixed

	if discarduid {
		uid = core.UNKNOWN_UID_STR
	}
	// fixed ip responses must always be alg'd unlike preset / blockall
	if usefixed {
		preset = fixedRealIPs
		mod = true // assert mod == true?
		t1 = t2    // assert t2 != nil?
	}
	if t1 == nil || core.IsNil(t1) {
		log.W("alg: no primary transport; t1 %s, t2 %s, uid %s, preset? %t fixed? %t synth? %t nouid? %t",
			idstr(t1), idstr(t2), uid, usepreset, usefixed, synthAns, discarduid)
		return nil, errAlgNoTransport
	}

	// when synthesizing answers, override both t1 and t2:
	// discard t2 as with preset we don't care about additional ips and blocklists;
	// t1 is not discarded entirely as it is needed to subst ips in https/svcb responses
	if synthAns {
		t2 = nil // assert t2 == nil?
	}
	t1res := make(chan *dns.Msg, 1)
	innersummary := new(x.DNSSummary)
	// todo: use context?
	secch := t.qs(t2, uid, network, q, t1res) // t2 may be nil

	if synthAns {
		ansin, err = synthesizeOrQuery(preset, t1, q, network, innersummary, usefixed)
	} else {
		ansin, err = t.qp(t1, uid, network, q, innersummary)
	}
	t1res <- ansin // ansin may be nil; but that's ok

	// override relevant values in smm
	fillSummary(innersummary, smm)

	if err != nil {
		if ansin == nil {
			log.I("alg: abort no ans on %s+%s[%s]; qerr %v", idstr(t1), idstr(t2), uid, err)
			return nil, err
		}
		if !xdns.HasRcodeSuccess(ansin) {
			return ansin, err
		}
		log.D("alg: err but ans ok: %d; qerr %v", xdns.Len(ansin), err)
	}

	if ansin == nil { // may be nil on errors
		return nil, errNoAnswer // err is nil
	}

	qname := qname(ansin)
	qtyp := qtype(ansin)
	smm.QName = qname
	smm.QType = qtyp

	// if usefixed is true, then d64 is no-op, as preset fixed ip does have ipv6
	ans64 := t.dns64.D64(network, ansin, t1) // ans64 may be nil if no D64 or error
	if ans64 != nil {
		log.D("alg: %s:%d dns64; s/ans(%d)/ans64(%d)", qname, qtyp, xdns.Len(ansin), xdns.Len(ans64))
		withDNS64Summary(ans64, smm)
		ansin = ans64
	} // else: no dns64, or error; continue with ansin

	hasq := xdns.HasAAAAQuestion(ansin) || xdns.HasAQuestion(ansin) ||
		xdns.HasSVCBQuestion(ansin) || xdns.HasHTTPQuestion(ansin)
	hasans := xdns.HasAnyAnswer(ansin)
	rgood := xdns.HasRcodeSuccess(ansin)
	// for t1, ansin's already evaluated for ans0000 in querySecondary
	// (secans.pri is set to true). ansin may be from t2 (if t2 != nil),
	// ans64, which is a modified ansin, is the only ans checked for
	// unspecified ips (0.0.0.0 / ::) as it covers ans from both t1 / t2.
	ans640000 := xdns.AQuadAUnspecified(ans64) // ans64 may be nil

	if ans640000 {
		smm.UpstreamBlocks = true
	}

	if !hasq || !hasans || !rgood || ans640000 || dontalg {
		log.D("alg: skip; query %s:%d / a:%d, dontalg(%t) hasq(%t) hasans(%t) rgood(%t), ans0000(%t)",
			qname, qtyp, xdns.Len(ansin), dontalg, hasq, hasans, rgood, ans640000)
		return ansin, nil
	}

	a6 := xdns.AAAAAnswer(ansin)
	a4 := xdns.AAnswer(ansin)
	ip4hints := xdns.IPHints(ansin, dns.SVCB_IPV4HINT)
	ip6hints := xdns.IPHints(ansin, dns.SVCB_IPV6HINT)
	// TODO: generate one alg ip per target, synth one rec per target
	targets := xdns.Targets(ansin)
	realip := make([]netip.Addr, 0)
	var algip4, algip6 netip.Addr

	// fetch secondary ips before locks
	// these may be from primary when secans.pri is true
	secres := <-secch

	// inform kt of secondary blocklists, if any
	smm.Blocklists = secres.smm.Blocklists
	smm.UpstreamBlocks = secres.smm.UpstreamBlocks || smm.UpstreamBlocks

	if smm.UpstreamBlocks || len(secres.smm.Msg) > 0 {
		smsg := secres.smm.Msg
		spri := secres.pri
		log.V("alg: %s:%d upstream blocks: primary? %t / sec? %t; secres: pri? %t, msg: %s",
			qname, qtyp, secres.smm.UpstreamBlocks, smm.UpstreamBlocks, spri, smsg)
	}

	defer func() {
		// answers in outmsg may not have been cached at all by xips
		// since register may not have happened at all
		xdns.BustAndroidCacheIfNeeded(outmsg)

		if isAlgErr(err) && !mod {
			log.D("alg: %s:%d no mod; suppress err %v", qname, qtyp, err)
			err = nil // ignore alg errors if no modification is desired
		}
	}()

	t.Lock()
	defer t.Unlock()

	var algip4hints, algip6hints, algip4s, algip6s netip.Addr
	if len(a6) > 0 {
		realip = append(realip, a6...)
		// choose the first alg ip6; may've been generated by a6
		algip, ipok := t.take6Locked(qname, 0)
		if !ipok {
			return ansin, errAlgNotAvail
		}
		algip6s = algip
	}
	if len(a4) > 0 {
		realip = append(realip, a4...)
		algip, ipok := t.take4Locked(qname, 0)
		if !ipok {
			return ansin, errAlgNotAvail
		}
		algip4s = algip
	}
	if len(ip4hints) > 0 {
		realip = append(realip, ip4hints...)
		// choose the first alg ip4; may've been generated by a4
		if !algip4s.IsValid() {
			// 0th algip is reserved for A records
			algip, ipok := t.take4Locked(qname, 0)
			if !ipok {
				return ansin, errAlgNotAvail
			}
			algip4hints = algip
		} else {
			algip4hints = algip4s
		}
	}
	if len(ip6hints) > 0 {
		realip = append(realip, ip6hints...)
		if !algip6s.IsValid() {
			// 0th algip is reserved for AAAA records
			algip, ipok := t.take6Locked(qname, 0)
			if !ipok {
				return ansin, errAlgNotAvail
			}
			algip6hints = algip
		} else {
			algip6hints = algip6s
		}
	}

	algXlatTtl := xdns.ZeroTTL
	substok4 := false
	substok6 := false
	// substituions needn't happen when no alg ips to begin with
	// but must happen if (real) ips are fixed
	mustsubst := false || usefixed
	ansout := ansin.Copy()
	// TODO: substitute ips in additional section
	if algip4hints.IsValid() {
		substok4 = xdns.SubstSVCBRecordIPs( /*out*/ ansout, dns.SVCB_IPV4HINT, algip4hints, algXlatTtl) || substok4
		mustsubst = true
	}
	if algip6hints.IsValid() {
		substok6 = xdns.SubstSVCBRecordIPs( /*out*/ ansout, dns.SVCB_IPV6HINT, algip6hints, algXlatTtl) || substok6
		mustsubst = true
	}
	if algip4s.IsValid() {
		substok4 = xdns.SubstARecords( /*out*/ ansout, algip4s, algXlatTtl) || substok4
		mustsubst = true
	}
	if algip6s.IsValid() {
		substok6 = xdns.SubstAAAARecords( /*out*/ ansout, algip6s, algXlatTtl) || substok6
		mustsubst = true
	}

	log.D("alg: %s; %s:%d a6(a %d / h %d / s %t) : a4(a %d / h %d / s %t)",
		uid, qname, qtyp, len(a6), len(ip6hints), substok6, len(a4), len(ip4hints), substok4)
	if !substok4 && !substok6 {
		if mustsubst {
			err = errAlgCannotSubst
		} else { // no algips
			err = nil
		}
		log.D("alg: %s skip; err(%v); ips subst %s:%d; fixed? %t",
			uid, err, qname, qtyp, usefixed)
		return ansin, err // ansin is nil if no alg ips
	}

	var fixedips []netip.Addr
	if usefixed {
		// if usefixed, then realips are in fact fixedips
		fixedips = realip
		// empty out realip and secres.ips got from answers
		// secres.ips is fixedips anyway since t2 is nil
		realip = nil
		secres.ips = nil
	}

	ansttl := time.Duration(xdns.RTtl(ansin)) * time.Second
	if algip4s.IsValid() {
		algip4 = algip4s
	} else {
		algip4 = algip4hints
	}
	if algip6s.IsValid() {
		algip6 = algip6s
	} else {
		algip6 = algip6hints
	}

	tid1 := idstr(t1)
	log.D("alg: ok; for %s[%s]:%s:%d, domains %s real: %s / fix: %s => subst %s | %s; (mod? %t / fix? %t / synth? %t); sec %s",
		tid1, uid, qname, qtyp, targets, realip, fixedips, algip4, algip6, mod, usefixed, synthAns, secres.ips)

	if t.registerLocked(qname, tid1, uid, algip4, algip6, realip, ansttl, targets, secres) {
		// if mod is set, send modified answer
		if mod {
			withAlgSummaryIfNeeded(smm, algip4, algip6)
			return ansout, nil
		} else {
			return ansin, nil
		}
	} else {
		return ansin, errAlgCannotRegister
	}
}

func Netip2Csv(ips []netip.Addr) (csv string) {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip.IsValid() {
			out = append(out, ip.String())
		}
	}
	return strings.Join(out, ",")
}

func Csv2Netip(csv string) (ips []netip.Addr) {
	out := make([]netip.Addr, 0, len(ips))
	for ip := range strings.SplitSeq(csv, ",") {
		if ipaddr, err := netip.ParseAddr(ip); ipaddr.IsValid() && err == nil {
			out = append(out, ipaddr)
		}
	}
	return out
}

func withDNS64Summary(ans64 *dns.Msg, s *x.DNSSummary) {
	s.RCode = xdns.Rcode(ans64)
	s.RData = xdns.GetInterestingRData(ans64)
	s.RTtl = xdns.RTtl(ans64)
	if settings.Debug {
		prefix := PrefixFor(AlgDNS64)
		s.Server = prefix + s.Server
	}
}

func withAlgSummaryIfNeeded(s *x.DNSSummary, algips ...netip.Addr) {
	if settings.Debug {
		// convert algips to ipcsv; any algips may be invalid
		ipcsv := Netip2Csv(algips)

		if len(s.RData) > 0 {
			s.RData = s.RData + "," + ipcsv
		} else {
			s.RData = ipcsv
		}
		prefix := PrefixFor(Alg)
		if len(s.Server) > 0 {
			s.Server = prefix + s.Server
		} else {
			s.Server = prefix + notransport
		}
	}
}

func (t *dnsgateway) registerLocked(q, tid, uid string, algip4, algip6 netip.Addr, realips []netip.Addr, ttl time.Duration, targets []string, secres secans) bool {
	if tid == notransport || tid == NoDNS || len(tid) <= 0 {
		log.E("alg: no tid for %s@%s[%s]; real? %d, sec? %d",
			q, tid, uid, len(realips), len(secres.ips))
		return false
	}
	if !algip4.IsValid() && !algip6.IsValid() { // defensive; should not happen
		log.E("alg: no algips for %s@%s[%s]; real? %d, sec? %d",
			q, tid, uid, len(realips), len(secres.ips))
		return false
	}

	now := time.Now()
	// ttl is used for algans and xips, but the alg'fied dns answer
	// has a lower ttl as defined by const algttl (currently, 15s).
	ansttl := now.Add(max(ttl2m, ttl))
	xipsttl := now.Add(ttl)
	// secres.ips may be empty on timeout errors, or
	// or same as realips if t2 is nil; realips can be nil
	// if fixedips is being used.
	am4 := &baseans{
		ips:        NewXips(tid, uid, v4only(realips), v4only(secres.ips), xipsttl),
		domains:    targets, // may be nil
		blocklists: secres.smm.Blocklists,
		ttl:        ansttl, // extended by 2m on every use
	}
	am6 := &baseans{
		ips:        NewXips(tid, uid, v6only(realips), v6only(secres.ips), xipsttl),
		domains:    targets, // may be nil
		blocklists: secres.smm.Blocklists,
		ttl:        ansttl, // extended by 2m on every use
	}

	didRegister := false
	// register mapping from qname -> algip+realip (alg) and algip -> qname+realip (nat)
	for _, ip := range []netip.Addr{algip4, algip6} { // algips may be nil?
		var k string
		var x *algans
		if ip.IsValid() && ip.Is4() {
			k = q + key4 + strconv.Itoa(0)
			x = &algans{
				algip:   ip,
				baseans: am4,
			}
		} else if ip.IsValid() && ip.Is6() {
			k = q + key6 + strconv.Itoa(0)
			x = &algans{
				algip:   ip,
				baseans: am6,
			}
		} // else: ip invalid
		if x == nil { // no valid algans
			continue
		}
		if prevans := t.alg[k]; prevans != nil {
			// merge x into prevam
			prevans.merge(x)
		} else {
			t.alg[k] = x
			t.nat[ip] = x.baseans
		}
		didRegister = true
	}
	if !didRegister {
		log.W("alg: no algips 2 for %s@%s[%s]; real? %d, sec? %d",
			q, tid, uid, len(realips), len(secres.ips))
		return false
	}
	// am.ips.realips() may return nil; ex: when preset fixed ips are used
	for _, ip := range realips {
		if ip.IsUnspecified() || !ip.IsValid() { // should never happen
			continue
		}
		// register mapping from realip -> algip+qname (ptr)
		if prevam := t.ptr[ip]; prevam == nil {
			if ip.Is4() {
				t.ptr[ip] = am4
			} else if ip.Is6() {
				t.ptr[ip] = am6
			}
		} // else prevam is merged into am4/am6 by t.alg above
	}
	return true
}

func (t *dnsgateway) take4Locked(q string, idx int) (netip.Addr, bool) {
	k := q + key4 + strconv.Itoa(idx)
	if ans, ok := t.alg[k]; ok {
		ip := ans.algip
		if ip.Is4() {
			ans.extend(ttl2m)
			return ip, true
		} else {
			// shouldn't happen; if it does, rm erroneous entry
			delete(t.alg, k)
			delete(t.nat, ip)
			ans.ips.each(func(ip netip.Addr) {
				if pans := t.ptr[ip]; pans == ans.baseans {
					delete(t.ptr, ip)
				}
			})
		}
	}

	if t.chash {
		for i := range maxiter {
			genip := gen4Locked(k, i)
			if !genip.IsGlobalUnicast() {
				continue
			}
			if _, taken := t.nat[genip]; !taken {
				return genip, genip.IsValid()
			}
		}
		log.W("alg: gen: no more IP4s (%v)", q)
		return zeroaddr, false
	}

	gen := true
	// 100.x.y.z: 4m+ ip4s
	if z := t.octets[3]; z < 254 {
		t.octets[3] += 1 // z
	} else if y := t.octets[2]; y < 254 {
		t.octets[2] += 1 // y
		t.octets[3] = 1  // z
	} else if x := t.octets[1]; x < 128 {
		t.octets[1] += 1 // x
		t.octets[2] = 0  // y
		t.octets[3] = 1  // z
	} else {
		i := 0
		for kx, ent := range t.alg {
			if i > maxiter {
				break
			}
			if d := time.Since(ent.ttl); d > 0 {
				log.I("alg: reuse stale alg %s for %s", kx, k)
				delete(t.alg, kx)
				delete(t.nat, ent.algip)
				ent.ips.each(func(ip netip.Addr) {
					if pans := t.ptr[ip]; pans == ent.baseans {
						delete(t.ptr, ip)
					}
				})
				return ent.algip, true
			}
			i += 1
		}
		gen = false
	}
	if gen {
		// 100.x.y.z: big endian is network-order, which netip expects
		b4 := [4]byte{t.octets[0], t.octets[1], t.octets[2], t.octets[3]}
		genip := netip.AddrFrom4(b4).Unmap()
		return genip, genip.IsValid()
	} else {
		log.W("alg: no more IP4s (%v)", t.octets)
	}
	return zeroaddr, false
}

func gen4Locked(k string, hop int) netip.Addr {
	s := strconv.Itoa(hop) + k
	v22 := hash22(s)
	// 100.64.y.z/15 2m+ ip4s
	b4 := [4]byte{
		rfc6598[0],                  // 100
		rfc6598[1] + uint8(v22>>16), // 64 + int(6bits)
		uint8((v22 >> 8) & 0xff),    // extract next 8 bits
		uint8(v22 & 0xff),           // extract last 8 bits
	}

	// why unmap? github.com/golang/go/issues/53607
	return netip.AddrFrom4(b4).Unmap()
}

func (t *dnsgateway) take6Locked(q string, idx int) (netip.Addr, bool) {
	k := q + key6 + strconv.Itoa(idx)
	if ans, ok := t.alg[k]; ok {
		ip := ans.algip
		if ip.Is6() {
			ans.extend(ttl2m)
			return ip, true
		} else {
			// shouldn't happen; if it does, rm erroneous entry
			delete(t.alg, k)
			delete(t.nat, ip)
			ans.ips.each(func(ip netip.Addr) {
				if pans := t.ptr[ip]; pans == ans.baseans {
					delete(t.ptr, ip)
				}
			})
		}
	}

	if t.chash {
		for i := range maxiter {
			genip := gen6Locked(k, i)
			if _, taken := t.nat[genip]; !taken {
				return genip, genip.IsValid()
			}
		}
		log.W("alg: gen: no more IP6s (%v)", q)
		return zeroaddr, false
	}

	gen := true
	// 64:ff9b:1:da19:0100.x.y.z: 281 trillion ip6s
	if z := t.hexes[7]; z < 65534 {
		t.hexes[7] += 1 // z
	} else if y := t.hexes[6]; y < 65534 {
		t.hexes[6] += 1 // y
		t.hexes[7] = 1  // z
	} else if x := t.hexes[5]; x < 65534 {
		t.hexes[5] += 1 // x
		t.hexes[6] = 0  // y
		t.hexes[7] = 1  // z
	} else {
		// possible that we run out of 200 trillion ips...?
		gen = false
	}
	if gen {
		// 64:ff9b:1:da19:0100.x.y.z: big endian is network-order, which netip expects
		b16 := [16]byte{}
		for i, hx := range t.hexes {
			i = i * 2
			binary.BigEndian.PutUint16(b16[i:i+2], hx)
		}
		genip := netip.AddrFrom16(b16)
		return genip, genip.IsValid()
	} else {
		log.W("alg: no more IP6s (%x)", t.hexes)
	}
	return zeroaddr, false
}

func gen6Locked(k string, hop int) netip.Addr {
	s := strconv.Itoa(hop) + k
	v48 := hash48(s)
	// 64:ff9b:1:da19:0100.x.y.z: 281 trillion ip6s
	a16 := [8]uint16{
		rfc8215a[0],                  // 64
		rfc8215a[1],                  // ff9b
		rfc8215a[2],                  // 1
		rfc8215a[3],                  // da19
		rfc8215a[4],                  // 0100
		uint16((v48 >> 32) & 0xffff), // extract the top 16 bits
		uint16((v48 >> 16) & 0xffff), // extract the mid 16 bits
		uint16(v48 & 0xffff),         // extract the last 16 bits
	}
	b16 := [16]byte{}
	for i, hx := range a16 {
		i = i * 2
		binary.BigEndian.PutUint16(b16[i:i+2], hx)
	}
	return netip.AddrFrom16(b16)
}

func (t *dnsgateway) X(maybeAlg netip.Addr, uid string, tids ...string) (ips []netip.Addr, undidAlg bool) {
	t.RLock()
	defer t.RUnlock()

	if !t.split.Load() {
		uid = core.UNKNOWN_UID_STR
	}
	// stale IPs are okay iff !mod; as then maybeAlg itself is a realip
	usestale := !t.mod.Load()
	return t.xLocked(maybeAlg, usestale, uid, tids...) // ips may be 0 len
}

func (t *dnsgateway) PTR(maybeAlg netip.Addr, force bool) (domains string, didForce bool) {
	t.RLock()
	defer t.RUnlock()

	// do not use t.ptr (realip -> ans) in mod (alg) mode, unless forced;
	// as t.nat (algip -> ans) is a more accurate translation.
	useptr := !t.mod.Load() || force
	d := t.ptrLocked(maybeAlg, useptr)
	if len(d) > 0 {
		domains = strings.Join(d, ",")
	} // else: algip isn't really an alg ip, nothing to do
	return domains, useptr
}

func (t *dnsgateway) RESOLV(domain, uid string) []netip.Addr {
	t.RLock()
	defer t.RUnlock()

	typ := typalg
	if !t.mod.Load() {
		typ = typreal
	}
	if !t.split.Load() {
		uid = core.UNKNOWN_UID_STR
	}
	ip4s, ip6s, _, _ := t.resolvLocked(domain, typ, notransport, uid)
	return append(ip4s, ip6s...)
}

func (t *dnsgateway) RDNSBL(algip netip.Addr) (blocklists string) {
	t.RLock()
	defer t.RUnlock()

	return t.rdnsblLocked(algip, !t.mod.Load())
}

func (t *dnsgateway) xLocked(maybeAlg netip.Addr, usestale bool, uid string, tids ...string) ([]netip.Addr, bool) {
	var realips []netip.Addr
	var undidAlg, fresh bool
	xst := makeXipStatus(!usestale)
	// alg ips are always unmappped; see take4Locked
	unmapped := maybeAlg.Unmap() // aligip may also be origip / realip
	if ans, ok := t.nat[unmapped]; ok {
		if len(tids) <= 0 {
			realips = ans.ips.realips(uid, xst)
		} else {
			for _, tid := range tids {
				realips = append(realips, ans.ips.realipsFor(tid, uid, xst)...)
			}
		}
		fresh = ans.fresh()
		// undidAlg is really "hasAnyAlgEntry"; set it to true
		// regardless of len(realips) or freshness of ans.ips
		undidAlg = true
	} else if ans, ok := t.ptr[unmapped]; ok {
		// for IPs (unlike domains), it is okay to fallback on ptr as the
		// maybeAlg may be an algip OR realip (latter in the case where an
		// app is connecting to a cached IP addr from before t.mod was set)
		// nb: both realips & secondaryips may be nil, but that's okay:
		// go.dev/play/p/fSjRjMSAS2m
		if len(tids) <= 0 {
			realips = ans.ips.realips(uid, xst)
		} else {
			for _, tid := range tids {
				realips = append(realips, ans.ips.realipsFor(tid, uid, xst)...)
			}
		}
		fresh = ans.fresh()
		undidAlg = false
	}

	// todo: ignore & return the fake dns address as-is (ex: 10.111.222.3:53)
	hasrealips := len(realips) > 0
	var unnated []netip.Addr
	if !hasrealips { // algip is probably origip / realip
		// unnat origip as it itself may have been synthesized from
		// our DNS responses by apps doing funky things; like FreeFire
		unnated = t.maybeUndoNat64(unmapped)
	} else {
		unnated = t.maybeUndoNat64(realips...)
	} // else: send realips as is
	logeif(!hasrealips)("alg: dns64: for %v[%s] (fresh? %t / undidAlg? %t / staleok? %t) algip(%v) => realips(%v) => unnated(%v)",
		tids, uid, fresh, undidAlg, usestale, unmapped, realips, unnated)
	if len(unnated) > 0 { // unnated is already de-duplicated
		return unnated, undidAlg
	}
	return copyUniq(realips), undidAlg
}

func (t *dnsgateway) maybeUndoNat64(realips ...netip.Addr) (unnateds []netip.Addr) {
	for _, nip := range realips {
		unmapped := nip.Unmap()
		if !unmapped.Is6() {
			continue
		}
		// the actual ID of the DNS64 for this whoever responded with "realips" for some unknown
		// DNS query is not available. But, we needn't worry about UN-NAT64'ing other resolvers
		// except the one we "force" onto the clients (aka dnsx.Local464Resolver).
		// whether the active network has ipv4 connectivity is checked by dialers.filter()
		ipx4 := t.dns64.X64(Local464Resolver, unmapped) // ipx4 may be zero addr
		if !ipok(ipx4) {                                // no nat?
			log.V("alg: dns64: maybeUndoNat64: no local nat64 to ip4(%v) for ip6(%v); ip4 not ok", ipx4, nip)
			continue
		}
		log.D("alg: dns64: maybeUndoNat64: nat64 to ip4(%v) from ip6(%v)", ipx4, nip)
		unmapped4 := ipx4.Unmap()
		unnateds = append(unnateds, unmapped4)
	}
	return copyUniq(unnateds)
}

func (t *dnsgateway) ptrLocked(maybeAlg netip.Addr, useptr bool) (domains []string) {
	// alg ips are always unmappped; see take4Locked
	unmapped := maybeAlg.Unmap()
	if ans, ok := t.nat[unmapped]; ok {
		domains = ans.domains
	} else if ans, ok := t.ptr[unmapped]; useptr && ok {
		// translate from realip only if not in mod mode
		domains = ans.domains
	}
	return copyUniq(domains)
}

// resolvLocked returns IPs and related targets for domain
// depending on typ.
// If typ is typalg, returns all algips for domain.
// If typ is typreal, returns all realips for domain resolved by tid.
// If typ is typsecondary, returns all secondaryips for domain (disregarding tid).
// ip4s and ip6s may overlap, and are segregated by the source algip
// family (and not by the family of the resolved IPs themselves).
func (t *dnsgateway) resolvLocked(domain string, typ iptype, tid, uid string) (ip4s, ip6s, staleips []netip.Addr, targets []string) {
	partkey4 := domain + key4
	partkey6 := domain + key6

	ip4s = make([]netip.Addr, 0)
	ip6s = make([]netip.Addr, 0)
	targets = make([]string, 0)
	staleips = make([]netip.Addr, 0)
	switch typ {
	case typalg:
		for i := range 2 {
			k4 := partkey4 + strconv.Itoa(i)
			if ans, ok := t.alg[k4]; ok {
				if ans.fresh() { // not stale
					ip4s = append(ip4s, ans.algip)
					targets = append(targets, ans.domains...)
				} else {
					staleips = append(staleips, ans.algip)
				}
			} else {
				break
			}
		}
		for i := range 2 {
			k6 := partkey6 + strconv.Itoa(i)
			if ans, ok := t.alg[k6]; ok {
				if ans.fresh() { // not stale
					ip6s = append(ip6s, ans.algip)
					targets = append(targets, ans.domains...)
				} else {
					staleips = append(staleips, ans.algip)
				}
			} else {
				break
			}
		}
		log.V("alg: resolv: %s:%s[%s] => alg ip4 %d, ip6 %d; stale %v",
			domain, tid, uid, len(ip4s), len(ip6s), staleips)
	case typreal:
		for i := range 2 { // a = 0, https/svcb = 1+
			k4 := partkey4 + strconv.Itoa(i)
			if ans, ok := t.alg[k4]; ok {
				if ans.fresh() { // not stale
					ip4s = append(ip4s, v4only(ans.ips.realipsFor(tid, uid, xalive))...)
					targets = append(targets, ans.domains...)
				} else {
					staleips = append(staleips, ans.ips.realipsFor(tid, uid, xall)...)
				}
				// all ans{} have all realips; pick the first one
				break
			} // continue
		}
		for i := range 2 { // aaaa = 0, https/svcb = 1+
			k6 := partkey6 + strconv.Itoa(i)
			if ans, ok := t.alg[k6]; ok {
				if ans.fresh() { // not stale
					ip6s = append(ip6s, v6only(ans.ips.realipsFor(tid, uid, xalive))...)
					targets = append(targets, ans.domains...)
				} else {
					staleips = append(staleips, ans.ips.realipsFor(tid, uid, xall)...)
				}
				// all ans{} have all realips; pick the first one
				break
			} // continue
		}
		log.V("alg: resolv: %s:%s[%s] => real(%s) ip4 %d, ip6 %d; stale %v",
			domain, tid, uid, len(ip4s), len(ip6s), staleips)
	case typsecondary:
		for i := range 2 { // a = 0, https/svcb = 1+
			k4 := partkey4 + strconv.Itoa(i)
			if ans, ok := t.alg[k4]; ok {
				if ans.fresh() { // not stale
					ip4s = append(ip4s, v4only(ans.ips.secof(tid, uid))...)
					targets = append(targets, ans.domains...)
				} else {
					staleips = append(staleips, ans.ips.sec(xall)...)
				}
				// all ans{} have all secondaryips; pick the first one
				break
			} // continue
		}
		for i := range 2 { // aaaa = 0, https/svcb = 1+
			k6 := partkey6 + strconv.Itoa(i)
			if ans, ok := t.alg[k6]; ok {
				if ans.fresh() { // not stale
					ip6s = append(ip6s, v6only(ans.ips.secof(tid, uid))...)
					targets = append(targets, ans.domains...)
				} else {
					staleips = append(staleips, ans.ips.sec(xall)...)
				}
				// all ans{} have all secondaryips; pick the first one
				break
			} // continue
		}
		log.V("alg: resolv: %s:%s[%s] => secondary ip4 %d, ip6 %d; stale %v",
			domain, tid, uid, len(ip4s), len(ip6s), staleips)
	}

	return
}

func (t *dnsgateway) rdnsblLocked(algip netip.Addr, useptr bool) (bcsv string) {
	// alg ips are always unmappped; see take4Locked
	unmapped := algip.Unmap()
	if ans, ok := t.nat[unmapped]; ok {
		bcsv = ans.blocklists
	} else if ans, ok := t.ptr[unmapped]; useptr && ok {
		// translate from realip only if not in mod mode
		bcsv = ans.blocklists
	}
	return
}

// xor fold fnv to 18 bits: www.isthe.com/chongo/tech/comp/fnv
func hash22(s string) uint32 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	v64 := h.Sum64()
	return (uint32(v64>>22) ^ uint32(v64)) & 0x3FFFFF // 22 bits
}

// xor fold fnv to 48 bits: www.isthe.com/chongo/tech/comp/fnv
func hash48(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	v64 := h.Sum64()
	return (uint64(v64>>48) ^ uint64(v64)) & 0xFFFFFFFFFFFF // 48 bits
}

func synthesizeOrQuery(preset []netip.Addr, tr Transport, msg *dns.Msg, network string, smm *x.DNSSummary, fixed bool) (*dns.Msg, error) {
	// synthesize a response with the given ips
	if len(preset) == 0 {
		return Req(tr, network, msg, smm)
	}
	if msg == nil || !xdns.HasAnyQuestion(msg) {
		return nil, errNoQuestion
	}
	algXlatTtl := xdns.ZeroTTL
	qname := qname(msg)
	qtyp := uint16(qtype(msg))
	is4 := xdns.IsAQType(qtyp)
	is6 := !is4 && xdns.IsAAAAQType(qtyp)
	isHTTPS := (!is4 && !is6) && xdns.IsHTTPSQType(qtyp)
	isSVCB := (!is4 && !is6) && xdns.IsSVCBQType(qtyp)
	if is4 || is6 {
		// if no ips are of the same family as the question xdns.AQuadAForQuery returns error
		ans, err := xdns.AQuadAForQuery(msg, preset...)
		if err != nil { // errors on invalid msg, question, or mismatched ips
			log.W("alg: synthesize: %s with %v; err(%v); using tr %s",
				qname, preset, err, idstr(tr))
			return Req(tr, network, msg, smm)
		}
		withPresetSummary(smm, false /*req sent?*/, fixed)
		smm.RCode = xdns.Rcode(ans)
		smm.RData = xdns.GetInterestingRData(ans)
		smm.RTtl = xdns.RTtl(ans) // usually 1 per xdns.AnsTTL

		log.V("alg: synthesize: %s q(4? %t / 6? %t), fixed? %t, rdata(%s)",
			qname, is4, is6, fixed, smm.RData)

		return ans, nil // no error
	} else if isHTTPS || isSVCB {
		ans, err := Req(tr, network, msg, smm)
		if err != nil {
			return ans, err
		} else if ans == nil { // empty answer is ok
			return nil, errNoAnswer
		}
		var ok4, ok6 bool
		ip4s, ip6s := splitIPFamilies(preset)
		if len(ip4s) > 0 {
			ok4 = xdns.SubstSVCBRecordIPs( /*out*/ ans, dns.SVCB_IPV4HINT, ip4s[0], algXlatTtl)
		}
		if len(ip6s) > 0 {
			ok6 = xdns.SubstSVCBRecordIPs( /*out*/ ans, dns.SVCB_IPV6HINT, ip6s[0], algXlatTtl)
		}

		withPresetSummary(smm, true /*req sent?*/, fixed)
		smm.RCode = xdns.Rcode(ans)
		smm.RData = xdns.GetInterestingRData(ans)
		smm.RTtl = xdns.RTtl(ans)

		log.D("alg: synthesize: q: %s; (HTTPS? %t / fixed? %t); subst4(%t), subst6(%t); rdata(%s); tr: %s",
			qname, isHTTPS, fixed, ok4, ok6, smm.RData, idstr(tr))

		return ans, nil // no error
	} else {
		note := log.VV
		if fixed {
			note = log.W
		}
		note("alg: synthesize: %s skip; fixed? %t, qtype %d; using tr %s",
			qname, fixed, qtyp, idstr(tr))
		return Req(tr, network, msg, smm)
	}
}

// Req sends q to transport t and returns the answer, if any;
// errors are unset if answer is not servfail or empty;
// smm, the in/out parameter, is dns summary as got from t.
func Req(t Transport, network string, q *dns.Msg, smm *x.DNSSummary) (*dns.Msg, error) {
	if t == nil || core.IsNil(t) {
		return nil, errNoSuchTransport
	}
	if !xdns.HasAnyQuestion(q) {
		return nil, errNoQuestion
	}
	qname := qname(q)

	if smm == nil { // discard smm
		discarded := new(x.DNSSummary)
		smm = discarded
	}
	if len(smm.QName) <= 0 {
		smm.QName = qname
	}
	if smm.QType <= 0 {
		qtyp := qtype(q)
		smm.QType = qtyp
	}

	r, err := t.Query(network, q, smm)

	if r == nil {
		log.D("alg: Req: %s no answer; but err? %v", qname, err)
		return nil, err // err may be nil
	}
	if !xdns.IsServFailOrInvalid(r) {
		return r, nil
	}

	log.V("alg: Req: %s servfail; rcode %d", qname, xdns.Rcode(r))
	return r, err
}

func splitIPFamilies(ips []netip.Addr) (ip4s, ip6s []netip.Addr) {
	for _, ip := range ips {
		if !ip.IsValid() {
			continue
		}
		ip = ip.Unmap()
		if ip.Is4() {
			ip4s = append(ip4s, ip)
		} else if ip.Is6() {
			ip6s = append(ip6s, ip)
		}
	}
	return
}

func v4only(ips []netip.Addr) []netip.Addr {
	return filterLeft(ips, func(ip netip.Addr) bool {
		return ip.Is4()
	})
}

func v6only(ips []netip.Addr) []netip.Addr {
	return filterLeft(ips, func(ip netip.Addr) bool {
		return ip.Is6()
	})
}

type TestFn[T any] func(T) bool

func filterLeft[T any](arr []T, yes TestFn[T]) []T {
	out := make([]T, 0)
	for _, x := range arr {
		if yes(x) {
			out = append(out, x)
		}
	}
	return out
}

func withPresetSummary(smm *x.DNSSummary, reqSent, fixed bool) {
	id := Preset
	if fixed {
		id = Fixed
	}
	// override id and type from whatever was set before
	smm.ID = id
	smm.Type = id
	if !reqSent { // other unset fields if req not sent upstream
		smm.Latency = 0
		smm.Status = Complete
		smm.Server = "127.5.3.9"
	}
	smm.Server = PrefixFor(id) + smm.Server
	smm.Blocklists = ""  // blocklists are not honoured
	smm.RelayServer = "" // no relay is used
}

func idstr(t Transport) string {
	if t == nil {
		return notransport
	}
	return t.ID()
}

func ipok(ip netip.Addr) bool {
	return !ip.IsUnspecified() && ip.IsValid()
}

// flattens and returns a copy with dups removed, if any.
// go.dev/play/p/WJXpAa-nmep
func copyUniq[T comparable](a ...[]T) (out []T) {
	out = make([]T, 0)
	if len(a) <= 0 {
		return
	}
	if len(a) == 1 {
		out = append(out, a[0]...)
		return
	}
	acc := make(map[T]struct{}, 0)
	for _, x := range a {
		for _, xx := range x {
			if _, ok := acc[xx]; ok {
				continue
			}
			// maintain incoming order
			out = append(out, xx)
			acc[xx] = struct{}{}
		}
	}
	return
}

func logeif(cond bool) log.LogFn {
	if cond {
		return log.E
	}
	return log.D
}
