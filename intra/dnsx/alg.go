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
	"hash/fnv"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

const (
	timeout = 15 * time.Second
	// 2m max ttl for alg/nat ip
	ttl2m = 2 * time.Minute
	// 8s min ttl for alg/nat ip; chosen to be closer to transport timeouts
	ttl8s = 8 * time.Second
	// 3s timeout to undo dns64/nat64
	ttl3s = 3 * time.Second

	key4 = ":a"
	key6 = ":aaaa"

	notransport = "NoTransport"

	maxiter = 100 // max number alg/nat evict iterations
	// minimum interval between two consecutive vaccums
	vaccumInterval = 2 * time.Minute
	// max number of past entries to vaccum in one go
	maxVaccumIterCount = maxiter

	// stale threshold for retaining expired ips from merge
	staleXipsThres = 24 * time.Hour
	// stale threshold for retaining expired domains from merge
	staleDomainThres = 24 * time.Hour
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
	PTR(maybeAlg netip.Addr, uid, tid string, force bool) (domaincsv string, didForce bool)
	// given domain, retrieve assoc alg ips or real ips as csv, if any
	RESOLV(domain, uid, tid string) []netip.Addr
	// given an alg or real ip, retrieve assoc blocklists as csv, if any
	RDNSBL(maybeAlg netip.Addr) (blocklistcsv string)
	// translate overwrites ip answers to alg ip & fixed ip answers
	translate(tr, fix bool)
	// splitTunnel sets per-app split tunneling on
	splitTunnel()
	// fixedTransport returns true if split tunneling is enforced via dnsx.Fixed
	fixedTransport() bool
	// Query using t1 as primary transport and t2 as secondary and preset as pre-determined ip answers
	// network is the primary transport's proxy routing; snetwork is for the secondary transport.
	q(t1, t2 Transport, preset []netip.Addr, origin, network, snetwork, uid string, q *dns.Msg, s *x.DNSSummary) (og *dns.Msg, algd *dns.Msg, err error)
	// onStopped is called when a transport tid is stopped. Gateway invalidates its local caches, if any.
	onStopped(tid string)
	// S reveals internal state for debugging
	S() string
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
	dob time.Time
}

func (a expaddr) String() string {
	return fmt.Sprintf("addrs(%v / ttl: %s / dob: %s)", a.ips, core.FmtTimeAsPeriod(a.ttl), core.FmtTimeAsPeriod(a.dob))
}

func (a expaddr) sizes() (alive, tot int) {
	if a.ips == nil {
		return
	}
	return len(a.alive()), len(a.ips)
}

func (a expaddr) all() []netip.Addr {
	return a.get(xall)
}

func (a expaddr) alive() []netip.Addr {
	return a.get(xalive)
}

// fresh returns false if a has expired or if a is zero-value.
func (a expaddr) fresh() (rem time.Duration, y bool) {
	if a.ttl.IsZero() {
		return
	}
	rem = time.Until(a.ttl)
	y = rem > 0
	return
}

func (a expaddr) after(b expaddr) bool {
	if a.dob.IsZero() {
		return b.dob.IsZero()
	}
	return a.dob.After(b.dob)
}

func (a expaddr) fresherThan(b expaddr) bool {
	if a.ttl.IsZero() {
		return b.ttl.IsZero()
	}
	return a.ttl.After(b.ttl)
}

// withinStaleThres returns true if a is within the stale threshold for retaining expired ips.
func (a expaddr) withinStaleThres() bool {
	return !a.dob.IsZero() && time.Since(a.dob) <= staleXipsThres
}

func (a expaddr) get(s xaddrstatus) (out []netip.Addr) {
	if a.ips == nil {
		return
	}
	if s == xall {
		return a.ips
	} else if s == xalive {
		if _, y := a.fresh(); y {
			return a.ips
		}
	}
	return
}

// go.dev/play/p/t24GYIQERsp
func expaddrDobSorter(a, b expaddr) int {
	if a.after(b) {
		return -1
	} else if b.after(a) {
		return 1
	}
	return 0
}

type xips struct {
	// protects pri, aux, past
	pmu sync.RWMutex
	// resolved expaddr(v6 or v4) by tid; may be nil
	pri map[string]expaddr
	// resolved expaddr(v6 or v4) by secondary tid for a uid; may be nil
	aux map[string]expaddr
	// recently expired ips within staleXipsThres captured from merge; tid+uid -> expaddr
	past map[string]expaddr
	// last time past was vaccumed (unix millis)
	lastVaccum time.Time
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
		log.W("alg: xips: tid cannot be empty")
		return nil
	}

	x := &xips{
		pri:  make(map[string]expaddr),
		aux:  make(map[string]expaddr), // sec may be nil
		past: make(map[string]expaddr),
	}
	now := time.Now()
	// id == "" for dnsx.NoDNS, in which case pri should be empty
	if len(pri) > 0 { // pri may be nil
		x.pri[tid] = expaddr{pri, ttl, now}
	}
	if len(uid) <= 0 {
		uid = core.UNKNOWN_UID_STR
	}
	if len(sec) > 0 { // sec may be same as pri
		x.aux[tid+uid] = expaddr{sec, ttl, now}
	}
	return x
}

func vals[K comparable, V any](m map[K]V, upto uint) []V {
	outv := make([]V, 0, upto)
	for _, v := range m {
		if upto != 0 && uint(len(outv)) >= upto {
			break
		}
		outv = append(outv, v)
	}
	return outv
}

func (p *xips) String() string {
	if p == nil {
		return "<nil>"
	}
	p.pmu.RLock()
	defer p.pmu.RUnlock()
	return fmt.Sprintf("xips: pri(%v) sec(%v) past(%v)", p.pri, p.aux, p.past)
}

// secondary ips for all tids+uids
func (p *xips) secips(s xaddrstatus) (out []netip.Addr) {
	// as far as secondary is concerned, only live ips matter;
	// expired ips should not be used for allow/deny decisions.
	// that is, s should almost always be set to xalive.
	return p.allips(xsec, s)
}

// secondary ip by a given tid+uid pair
func (p *xips) secipsFor(tid, uid string) (out []netip.Addr) {
	// as far as secondary is concerned, only live ips matter;
	// expired ips should not be used for allow/deny decisions.
	return p.ipsFor(tid, uid, xsec, xalive)
}

func (p *xips) allips(t xaddrtyp, s xaddrstatus) (out []netip.Addr) {
	p.pmu.RLock()
	defer p.pmu.RUnlock()

	g := p.pri
	if t == xsec {
		g = p.aux
	}
	const all = 0
	addrs := append([]expaddr{}, vals(g, all)...)
	for _, v := range core.Sort(addrs, expaddrDobSorter) {
		out = append(out, v.get(s)...)
	}
	// staleXipsThres only applies to pastips, not pri/aux entries
	if s == xall && t == xpri {
		for _, v := range core.Sort(vals(p.past, all), expaddrDobSorter) {
			if v.withinStaleThres() {
				out = copyUniq(out, v.ips)
			}
		}
	}
	return
}

// realips returns all live primary ips for a given uid.
// returns all tracked live primary ips.
// and returns unspecified ips, if uid had a "block" response.
func (p *xips) realips(uid string, s xaddrstatus) (pri []netip.Addr) {
	if p == nil {
		return nil
	}

	pri = p.allips(xpri, s)

	zz := p.zz(uid) // check for "block" responses for just this uid
	if zz {
		// if aux had unspecified ips, then append those to
		// primary ips. if aux has proper ips or no ips,
		// those are made redundant by primary.
		// append unspecified ips (zz) to pri regardless of xaddrstatus, s,
		// which is set to xall by xLocked if alg is disabled (mod == false),
		// but that does not mean the values from aux (secondary) are not
		// needed; ie, the "domain block" decision (indicated by aux) must
		// be commmunicated to the client at all costs. However, aux itself
		// must be xalive (not expired).
		pri = append(pri, anyaddr4, anyaddr6)
	}
	loged(len(pri) == 0)("alg: xips: x(%s): zz(%s)? %t; %v", s, uid, zz, pri)
	return pri // may be nil / empty
}

func (p *xips) zz(uid string) bool {
	if p == nil {
		return false
	}
	return anyUnspecified(p.secipsFor(notransport, uid))
}

// realipsFor returns all live primary ips for a given tid+uid pair
func (p *xips) realipsFor(tid, uid string, s xaddrstatus) (pri []netip.Addr) {
	return p.ipsFor(tid, uid, xpri, s)
}

func (p *xips) ipsFor(tid, uid string, t xaddrtyp, s xaddrstatus) (out []netip.Addr) {
	if p == nil {
		return nil
	}

	if len(uid) <= 0 {
		uid = core.UNKNOWN_UID_STR
	}

	if t == xpri && (tid == notransport || tid == NoDNS || len(tid) <= 0) {
		out = p.allips(xpri, s)
		if log.Verbose {
			log.VV("alg: xips: xof(%s,%s): no tid? %s[%s]; returning all %v", t, s, tid, uid, out)
		}
		return
	}

	p.pmu.RLock()
	defer p.pmu.RUnlock()

	if t == xsec { // ignore alive for secondary
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

	if log.Verbose {
		log.VV("alg: xips: xof(%s,%s): tid %s + uid %s; %v", t, s, tid, uid, out)
	}
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
	xaddr := p.pri[tid]
	if _, y := xaddr.fresh(); y {
		i++
		xaddr.ttl = time.Now() // mark as expired
		p.pri[tid] = xaddr
		p.relegateLocked(tid, xaddr)
	}
	for k, v := range p.aux {
		if _, y := v.fresh(); !y {
			continue
		}
		if strings.HasPrefix(k, tid) {
			j++
			v.ttl = time.Now() // mark as expired
			p.aux[k] = v
		}
	}
	done = (i + j) > 0
	if done {
		p.vaccumLocked()
	}
	if done && log.Debug {
		log.D("alg: xips: rmv(%s): pri(%d), sec(%d); ok? %t", tid, i, j, done)
	}
	return
}

// relegateLocked moves v (expaddr) into past under key k, merging with an existing entry if still within stale threshold.
func (p *xips) relegateLocked(k string, v expaddr) {
	if cur, ok := p.past[k]; ok && cur.withinStaleThres() {
		cur.ips = copyUniq(cur.ips, v.ips)
		// extend lifetime: keep it younger
		if cur.dob.Before(v.dob) {
			cur.dob = v.dob
		}
		p.past[k] = cur
	} else {
		p.past[k] = expaddr{ips: copyUniq(nil, v.ips), ttl: v.ttl, dob: v.dob}
	}
}

// vaccumLocked removes stale entries from past, limiting to maxVaccumIterCount.
func (p *xips) vaccumLocked() {
	last := p.lastVaccum
	if !last.IsZero() && time.Since(last) < vaccumInterval {
		return
	}
	n := 0
	for k, v := range p.past {
		n++
		if !v.withinStaleThres() {
			delete(p.past, k)
		}
		if n >= maxVaccumIterCount {
			break
		}
	}
	p.lastVaccum = time.Now()
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

func anyAddrEqual(ipps []netip.AddrPort, ip netip.Addr) bool {
	for _, ipp := range ipps {
		if ipp.Addr().Compare(ip) == 0 {
			return true
		}
	}
	return false
}

// each iterates over each primary ip
func (p *xips) each(f func(ip netip.Addr)) {
	for _, ip := range p.allips(xpri, xall) {
		f(ip)
	}
	for _, ip := range p.allips(xsec, xall) {
		f(ip)
	}
}

func (p *xips) merge(q *xips) (szprialiv, szpri, szsecaliv, szsec int) {
	szprialiv, szpri, szsecaliv, szsec = -1, -1, -1, -1 // -1 means no change

	if p == nil || q == nil {
		return
	}

	p.pmu.Lock() // write lock on p
	defer p.pmu.Unlock()
	q.pmu.RLock() // read lock on q
	defer q.pmu.RUnlock()

	if len(q.pri) > 0 {
		szprialiv, szpri = 0, 0
	}
	if len(q.aux) > 0 {
		szsecaliv, szsec = 0, 0
	}

	for qk, qv := range q.pri {
		pv := p.pri[qk]
		if _, y := pv.fresh(); !y {
			// pv is not fresh; capture its stale ips before replacement
			if len(pv.ips) > 0 && pv.withinStaleThres() {
				p.relegateLocked(qk, pv)
			}

			p.pri[qk] = qv // copy v from q into p
			szqaliv, szqpri := qv.sizes()
			szprialiv += szqaliv
			szpri += szqpri
		} else {
			var ips []netip.Addr
			ttl := pv.ttl
			dob := pv.dob
			if !pv.after(qv) {
				// qv is younger, so qv's ips should come first (youngest first ordering)
				ips = copyUniq(qv.alive(), pv.alive())
				dob = qv.dob
			} else {
				// pv is younger, so pv's ips should come first (youngest first ordering)
				ips = copyUniq(pv.alive(), qv.alive())
			}
			// capture stale (expired) ips from qv that would otherwise be lost
			if len(qv.ips) > 0 && qv.withinStaleThres() {
				p.relegateLocked(qk, qv)
			}

			if !pv.fresherThan(qv) {
				// ips from aa & v both get assigned the latest ttl
				// which is strictly incorrect, but for accounting
				// purposes (that is, algip->realip translations),
				// it is preferable to keep as many realips around
				// as possible (even at the slight cost of correctness).
				ttl = qv.ttl
			}
			v := expaddr{ips, ttl, dob}
			p.pri[qk] = v
			szqaliv, szqpri := v.sizes()
			szprialiv += szqaliv
			szpri += szqpri
		}
	}

	for qk, qv := range q.aux {
		pv := p.aux[qk]
		if _, y := pv.fresh(); !y {
			p.aux[qk] = qv // copy v from q into p
			szqaliv, szqsec := qv.sizes()
			szsecaliv += szqaliv
			szsec += szqsec
		} else {
			var ips []netip.Addr
			ttl := pv.ttl
			dob := pv.dob
			if !pv.after(qv) {
				// qv is younger, so qv's ips should come first (youngest first ordering)
				ips = copyUniq(qv.alive(), pv.alive())
				dob = qv.dob
			} else {
				// pv is younger, so pv's ips should come first (youngest first ordering)
				ips = copyUniq(pv.alive(), qv.alive())
			}
			if !pv.fresherThan(qv) {
				ttl = qv.ttl
			}
			v := expaddr{ips: ips, ttl: ttl, dob: dob}
			p.aux[qk] = v
			szqaliv, szqsec := v.sizes()
			szsecaliv += szqaliv
			szsec += szqsec
		}
	}

	p.vaccumLocked()

	return
}

// expdomains tracks domains with ttl and birth for ordering; unlike expaddr,
// there is no secondary domains map.
type expdomains struct {
	domains []string
	ttl     time.Time
	dob     time.Time
}

func (a expdomains) String() string {
	return fmt.Sprintf("domains(%v / ttl: %s / dob: %s)", a.domains, core.FmtTimeAsPeriod(a.ttl), core.FmtTimeAsPeriod(a.dob))
}

func (a expdomains) sizes() (alive, tot int) {
	if a.domains == nil {
		return
	}
	return len(a.get(xalive)), len(a.domains) // == len(a.get(xall))
}

func (a expdomains) get(s xaddrstatus) (out []string) {
	if a.domains == nil {
		return
	}
	if s == xall {
		return a.domains
	}
	if s == xalive {
		if _, y := a.fresh(); y {
			return a.domains
		}
	}
	return
}

func (a expdomains) fresh() (rem time.Duration, y bool) {
	if a.ttl.IsZero() {
		return
	}
	rem = time.Until(a.ttl)
	y = rem > 0
	return
}

func (a expdomains) after(b expdomains) bool {
	if a.dob.IsZero() {
		return b.dob.IsZero()
	}
	return a.dob.After(b.dob)
}

func (a expdomains) fresherThan(b expdomains) bool {
	if a.ttl.IsZero() {
		return b.ttl.IsZero()
	}
	return a.ttl.After(b.ttl)
}

// withinStaleThres returns true if a is within the stale threshold for retaining expired domains.
func (a expdomains) withinStaleThres() bool {
	return !a.dob.IsZero() && time.Since(a.dob) <= staleDomainThres
}

func expdomainsDobSorter(a, b expdomains) int {
	if a.after(b) { // a is born after b (ie, a is younger)
		return -1
	} else if b.after(a) { // b is younger
		return 1
	}
	return 0
}

// xdomains tracks domains per tid+uid; there is no secondary (aux) store.
type xdomains struct {
	pmu  *sync.RWMutex
	pri  map[string]expdomains // tid+uid -> domains
	past map[string]expdomains // recently expired domains within staleDomainThres captured from merge; tid+uid -> expdomains
	// last time past was vaccumed
	lastVaccum time.Time
}

// NewXdomains returns a new xdomains object keyed by tid+uid.
func NewXdomains(tid, uid string, pri []string, ttl time.Time) *xdomains {
	if len(tid) <= 0 {
		log.W("alg: xdomains: tid cannot be empty")
		return nil
	}
	if len(uid) <= 0 {
		uid = core.UNKNOWN_UID_STR
	}

	x := &xdomains{
		pmu:  new(sync.RWMutex),
		pri:  make(map[string]expdomains),
		past: make(map[string]expdomains),
	}

	if len(pri) > 0 { // pri may be nil
		x.pri[tid+uid] = expdomains{domains: pri, ttl: ttl, dob: time.Now()}
	}
	return x
}

func (p *xdomains) String() string {
	if p == nil {
		return "<nil>"
	}
	p.pmu.RLock()
	defer p.pmu.RUnlock()
	return fmt.Sprintf("xdomains: pri(%v) past(%v)", p.pri, p.past)
}

func (p *xdomains) domainsFor(tid, uid string, forIP netip.Addr, s xaddrstatus) (out []string) {
	if p == nil {
		return nil
	}
	if len(uid) <= 0 {
		uid = core.UNKNOWN_UID_STR
	}

	doms := make([]expdomains, 0)
	ttls := []time.Time{}
	key := tid + uid

	p.pmu.RLock()
	defer p.pmu.RUnlock()

	if tid == notransport || tid == NoDNS || len(tid) <= 0 {
		for k, v := range p.pri {
			if !strings.HasSuffix(k, uid) {
				continue
			}
			doms = append(doms, v)
		}
		for _, v := range core.Sort(doms, expdomainsDobSorter) {
			if settings.Debug {
				// for debugging: may have expired ttls
				ttls = append(ttls, v.ttl)
			}
			out = append(out, v.get(s)...)
		}
		// staleDomainThres only applies to pastdomains, not pri entries
		if s == xall {
			past := make([]expdomains, 0)
			for k, v := range p.past {
				if !strings.HasSuffix(k, uid) {
					continue
				}
				past = append(past, v)
			}
			for _, v := range core.Sort(past, expdomainsDobSorter) {
				if v.withinStaleThres() {
					out = copyUniq(out, v.domains)
				}
			}
		}
	} else {
		if v, ok := p.pri[key]; ok {
			if settings.Debug {
				ttls = append(ttls, v.ttl)
			}
			out = v.get(s)
		}
		// staleDomainThres only applies to pastdomains, not pri entries
		if s == xall {
			if v, ok := p.past[key]; ok {
				if v.withinStaleThres() {
					out = copyUniq(out, v.domains)
				}
			}
		}
	}

	if log.Verbose {
		log.VV("alg: xdomains: [%s%s] xof(%s/%s): %s => %v [%v]", tid, uid, s, forIP, key, out, core.Map(ttls, core.FmtTimeAsPeriod))
	}
	return
}

func (p *xdomains) rmv(tid string) (done bool) {
	if p == nil {
		return
	}
	if len(tid) <= 0 || tid == NoDNS || tid == notransport {
		return
	}

	keyPrefix := tid
	i := 0
	p.pmu.Lock()
	defer p.pmu.Unlock()
	for k, v := range p.pri {
		if !strings.HasPrefix(k, keyPrefix) {
			continue
		}
		if _, y := v.fresh(); y {
			i++
			v.ttl = time.Now() // mark as expired
			p.pri[k] = v
			p.relegateLocked(k, v)
		}
	}
	if done = i > 0; done {
		p.vaccumLocked()
	}
	return
}

// relegateLocked moves v (expdomains) into past under key k, merging with an existing entry if still within stale threshold.
func (p *xdomains) relegateLocked(k string, v expdomains) {
	if existing, ok := p.past[k]; ok && existing.withinStaleThres() {
		existing.domains = copyUniq(existing.domains, v.domains)
		if v.dob.Before(existing.dob) {
			existing.dob = v.dob
		}
		p.past[k] = existing
	} else {
		p.past[k] = expdomains{domains: copyUniq(nil, v.domains), ttl: v.ttl, dob: v.dob}
	}
}

// vaccumLocked removes stale entries from past, limiting to maxVaccumIterCount.
func (p *xdomains) vaccumLocked() {
	last := p.lastVaccum
	if !last.IsZero() && time.Since(last) < vaccumInterval {
		return
	}
	n := 0
	for k, v := range p.past {
		n++
		if !v.withinStaleThres() {
			delete(p.past, k)
		}
		if n >= maxVaccumIterCount {
			break
		}
	}
	p.lastVaccum = time.Now()
}

func (p *xdomains) merge(q *xdomains) (szprialiv, szpri int) {
	szprialiv, szpri = -1, -1 // -1 means no change

	if p == nil || q == nil {
		return
	}

	p.pmu.Lock()
	defer p.pmu.Unlock()
	q.pmu.RLock()
	defer q.pmu.RUnlock()

	if len(q.pri) > 0 {
		szprialiv, szpri = 0, 0
	}

	for qk, qv := range q.pri {
		pv := p.pri[qk]
		if _, y := pv.fresh(); !y {
			// pv is not fresh; capture its stale domains before replacement
			if len(pv.domains) > 0 && pv.withinStaleThres() {
				p.relegateLocked(qk, pv)
			}

			p.pri[qk] = qv // copy v from q into p
			szqaliv, szqpri := qv.sizes()
			szprialiv += szqaliv
			szpri += szqpri
		} else {
			var doms []string
			ttl := pv.ttl
			dob := pv.dob
			if !pv.after(qv) {
				// qv is younger, so qv's domains should come first (youngest first ordering)
				doms = copyUniq(qv.get(xalive), pv.get(xalive))
				dob = qv.dob
			} else {
				// pv is younger, so pv's domains should come first (youngest first ordering)
				doms = copyUniq(pv.get(xalive), qv.get(xalive))
			}
			// capture stale (expired) domains from qv that would otherwise be lost
			if len(qv.domains) > 0 && qv.withinStaleThres() {
				p.relegateLocked(qk, qv)
			}

			if !pv.fresherThan(qv) {
				ttl = qv.ttl
			}
			v := expdomains{domains: doms, ttl: ttl, dob: dob}
			p.pri[qk] = v
			szqaliv, szqpri := v.sizes()
			szprialiv += szqaliv
			szpri += szqpri
		}
	}

	p.vaccumLocked()

	return
}

type baseans struct {
	ips        *xips     // all ip answers, v6+v4; may be nil
	domains    *xdomains // all domain names in an answer (incl qname); per tid+uid
	blocklists string    // csv blocklists containing qname per active config at the time
	ttl        time.Time // ttl for this alg translation
}

func (a *baseans) String() string {
	if a == nil {
		return "<nil>"
	}
	return fmt.Sprintf("xips(%v) domains(%v) blocklists(%s) ttl(%s)",
		a.ips, a.domains, a.blocklists, core.FmtTimeAsPeriod(a.ttl))
}

// fresh returns false if a has expired or if a is nil
func (a *baseans) fresh() (rem time.Duration, y bool) {
	if a == nil || a.ttl.IsZero() {
		return
	}
	rem = time.Until(a.ttl)
	y = rem > 0
	return
}

type algans struct {
	algip netip.Addr // generated answer, v6 or v4
	*baseans
}

func (a *algans) String() string {
	if a == nil {
		return "<nil>"
	}
	return fmt.Sprintf("algans: algip(%s) base(%s)", a.algip, a.baseans)
}

func (a *algans) extend(by time.Duration) {
	if a == nil || a.ttl.IsZero() || time.Since(a.ttl) > 0 {
		a.ttl = time.Now().Add(by)
	} else {
		a.ttl = a.ttl.Add(by)
	}
}

func (a *algans) after(b *algans) bool {
	if a.ttl.IsZero() {
		return b.ttl.IsZero()
	}
	return a.ttl.After(b.ttl)
}

// merge merges b into a.
func (a *algans) merge(b *algans) {
	if a == nil || b == nil {
		log.W("alg: merge: nil algans; a? %s; b? %s", a, b)
		return
	}

	log.VV("alg: merge: b(%s) into a(%s)", b, a)

	if a.ips == nil {
		a.ips = b.ips
	} else {
		prialiv, totpri, secaliv, totsec := a.ips.merge(b.ips)
		logeif(totpri < 0 && totsec < 0)("alg: merge: ips; pri(%d/%d) sec(%d/%d), out(%s)",
			prialiv, totpri, secaliv, totsec, a)
	}
	if a.domains == nil {
		a.domains = b.domains
	} else {
		prialiv, totpri := a.domains.merge(b.domains)
		logeif(totpri < 0)("alg: merge: domains; pri(%d/%d), out(%s)",
			prialiv, totpri, a)
	}
	a.blocklists = b.blocklists // TODO: merge?
	if b.after(a) {
		a.ttl = b.ttl
	}
}

func domainsFor(base *baseans, tid, uid string, forIP netip.Addr, s xaddrstatus) []string {
	if base == nil || base.domains == nil {
		return nil
	}
	return base.domains.domainsFor(tid, uid, forIP, s)
}

type dnsgateway struct {
	sync.RWMutex                         // protects alg, nat, octets, hexes
	alg          map[string]*algans      // domain+type => ans
	nat          map[netip.Addr]*baseans // algip => baseans
	ptr          map[netip.Addr]*baseans // primaryip => baseans
	octets       []uint8                 // ip4 octets, 100.x.y.z
	hexes        []uint16                // ip6 hex, 64:ff9b:1:da19:0100.x.y.z

	// fields below are never reassigned

	fake  []netip.AddrPort // fake DNS addrs to ignore for "undoAlg"
	rdns  RdnsResolver     // local and remote rdns blocks
	dns64 NatPt            // dns64/nat64
	chash bool             // use consistent hashing to generate alg ips

	// fields below are mutable

	mod   atomic.Bool // modify realip to algip
	fix   atomic.Bool // enforce split tunneling via dnsx.Fixed
	split atomic.Bool // per-app split tunneling
}

var _ Gateway = (*dnsgateway)(nil)

// NewDNSGateway returns a DNS ALG, ready for use.
func NewDNSGateway(pctx context.Context, fakeaddrs []netip.AddrPort, outer RdnsResolver, dns64 NatPt) (t *dnsgateway) {
	alg := make(map[string]*algans)
	nat := make(map[netip.Addr]*baseans)
	ptr := make(map[netip.Addr]*baseans)

	t = &dnsgateway{
		alg:    alg,
		nat:    nat,
		ptr:    ptr,
		fake:   fakeaddrs,
		rdns:   outer,
		dns64:  dns64,
		octets: make([]uint8, len(rfc6598)),
		hexes:  make([]uint16, len(rfc8215a)),
		chash:  true,
	}
	copy(t.octets, rfc6598)
	copy(t.hexes, rfc8215a)

	context.AfterFunc(pctx, t.stop)
	log.I("alg: setup done")
	return
}

func (t *dnsgateway) translate(tr, fix bool) {
	prevtr := t.mod.Swap(tr)
	prevfix := t.fix.Swap(fix)
	log.I("alg: translate? prevtr(%t) > nowtr(%t); prevfix(%t) > nowfix(%t)", prevtr, tr, prevfix, fix)
}

func (t *dnsgateway) splitTunnel() {
	if t.split.Load() {
		return
	}
	t.split.Store(true)
	log.I("alg: splitTunnel turned on")
}

func (t *dnsgateway) fixedTransport() bool {
	// fixed transport can only be used if translation "mod" is on.
	return t.mod.Load() && t.split.Load() && t.fix.Load()
}

func (t *dnsgateway) onStopped(tid string) {
	if len(tid) <= 0 {
		return
	}

	t.RLock()
	algEntries := make([]*xips, 0, len(t.alg))
	domEntries := make([]*xdomains, 0, len(t.alg))
	for _, algans := range t.alg {
		if algans != nil {
			if algans.ips != nil {
				algEntries = append(algEntries, algans.ips)
			}
			if algans.domains != nil {
				domEntries = append(domEntries, algans.domains)
			}
		}
	}
	t.RUnlock()

	// Process outside the lock to avoid holding it too long
	n := 0
	for _, xip := range algEntries {
		if xip.rmv(tid) {
			n++
		}
	}
	m := 0
	for _, xdom := range domEntries {
		if xdom.rmv(tid) {
			m++
		}
	}
	log.I("alg: onStopped(%s): removed %d alg<>realip translations; %d domains", tid, n, m)
}

// clears alg states
func (t *dnsgateway) stop() {
	t.Lock()
	defer t.Unlock()

	clear(t.alg)
	clear(t.nat)
	clear(t.ptr)
	// Copy values to avoid mutating global state
	copy(t.octets, rfc6598)
	copy(t.hexes, rfc8215a)
}

func (t *dnsgateway) fromInternalCache(tid, uid, fid string, q *dns.Msg, typ iptype) (ans *dns.Msg, err error) {
	if skipInternalCache(tid) {
		return nil, errSkipInternalCache
	}
	// Skip answering from internal cache when DNSSEC is requested
	if typ == typreal && xdns.IsDNSSECRequested(q) {
		return nil, errSkipInternalCache
	}
	a, aaaa := xdns.HasAQuestion(q), xdns.HasAAAAQuestion(q)
	if !a && !aaaa {
		return nil, errNilCacheResponse
	}

	domain := qname(q)

	t.RLock()
	cached4s, cached6s, stale, until, _ := t.resolvLocked(domain, typ, tid, uid)
	t.RUnlock()

	var cachedips []netip.Addr
	if a && len(cached4s) > 0 {
		cachedips = cached4s
	} else if aaaa && len(cached6s) > 0 {
		cachedips = cached6s
	}
	cachehit := len(cachedips) > 0
	ttlnegative := false
	ttl := int64(until / time.Second)
	if ttl < 0 {
		ttl = int64(ttl8s / time.Second)
		ttlnegative = true
	}

	logeif(ttlnegative && cachehit)("alg: c: response for %s by %s[%s] %s (q4? %t / q6? %t) realip; in cache? %v [ttl: %s / -ve? %t / hit? %t / until: %s] (or stale? %v)",
		domain, tid, uid, fid, a, aaaa, cachedips, core.FmtSecs(ttl), ttlnegative, cachehit, core.FmtPeriod(until), stale)

	if !cachehit {
		return nil, errNilCacheResponse
	}
	return xdns.AQuadAForQueryTTL(q, uint32(ttl), cachedips...)
}

func (t *dnsgateway) qp(t1 Transport, uid, network string, q *dns.Msg, inner *x.DNSSummary) (ans *dns.Msg, err error) {
	// For A/AAAA queries, check if xips has an answer for the qname.
	if ans, err := t.fromInternalCache(idstr(t1), uid, inner.FID, q, typreal); err == nil {
		inner.ID = idstr(t1)
		inner.Server = getaddrstr(t1)
		inner.RData = xdns.GetInterestingRData(ans)
		inner.RCode = xdns.Rcode(ans)
		inner.RTtl = xdns.RTtl(ans)
		inner.Status = Complete
		inner.Cached = true
		return ans, nil
	}
	return Req(t1, network, q, inner)
}

func (t *dnsgateway) qs(t2 Transport, uid, fid, network string, msg *dns.Msg, t1res <-chan *dns.Msg) <-chan secans {
	t2res := make(chan secans, 1)
	msg = msg.Copy() // to avoid racing against changes made by caller

	core.Gx("alg.qs."+xdns.QName(msg), func() {
		defer close(t2res)

		qname := xdns.QName(msg)

		r, completed := core.Grx("alg.qs."+qname, func(_ context.Context) (secans, error) {
			return t.querySecondary(t2, uid, fid, network, msg, t1res), nil
		}, timeout)

		if !completed {
			log.W("alg: skip; %s qs timeout; tr2: %s, qname: %s", fid, idstr(t2), qname)
		}

		r.initIfNeeded() // r may be nil value on Grx:timeout

		t2res <- r // may be zero secans
	})
	return t2res
}

func (t *dnsgateway) querySecondary(t2 Transport, uid, fid, network string, msg *dns.Msg, t1res <-chan *dns.Msg) (result secans) {
	var r *dns.Msg
	var err error

	result.initIfNeeded() // result must not be reassigned

	result.smm.FID = fid

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
		if r, err = t.fromInternalCache(idstr(t2), uid, fid, msg, typsecondary); err != nil {
			// else: query secondary to get answer for q
			r, err = Req(t2, network, msg, result.smm)
		} else {
			result.smm.ID = idstr(t2)
			result.smm.Server = getaddrstr(t2)
			result.smm.RData = xdns.GetInterestingRData(r)
			result.smm.RCode = xdns.Rcode(r)
			result.smm.RTtl = xdns.RTtl(r)
			result.smm.Status = Complete
			result.smm.Cached = true
		}
	}

	// check if answer r is blocked; r is either from t2 or from <-in
	if err != nil || r == nil || !xdns.HasAnyAnswer(r) { // not a valid dns answer
		log.V("alg: querySecondary: skip; %s sec transport %s; nores? %t, err? %v", fid, idstr(t2), r == nil, err)
		result.smm.Msg = errNotEnoughAnswers.Error()
		return
	} else if a, blockedtarget, blocklistnames := t.rdns.blockA( /*may be nil*/ t2, nil, msg, r, result.smm.Blocklists); a != nil {
		// if "a" is not nil, then the r is blocked
		if len(blocklistnames) > 0 {
			result.smm.Blocklists = blocklistnames
			result.smm.BlockedTarget = blockedtarget
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
			result.smm.BlockedTarget = blockedtarget
		}
		if xdns.AQuadAUnspecified(r) {
			// A/AAAA must be 0.0.0.0/::, set UpstreamBlocks to true
			result.smm.UpstreamBlocks = true
			// discard all other answers
			result.ips = append(result.ips, anyaddr4, anyaddr6)
		} else if xdns.HasAnyAnswer(r) {
			ip4hints := xdns.IPHints(r, dns.SVCB_IPV4HINT)
			ip6hints := xdns.IPHints(r, dns.SVCB_IPV6HINT)
			result.ips = append(result.ips, xdns.IPs(r)...)
			result.ips = append(result.ips, ip4hints...)
			result.ips = append(result.ips, ip6hints...)
			// TODO: result.targets?
		}
		return
	}
}

// Implements Gateway
// preset may be nil; network for t1, snetwork for t2.
func (t *dnsgateway) q(t1, t2 Transport, preset []netip.Addr, origin, network, snetwork, uid string, q *dns.Msg, smm *x.DNSSummary) (ogmsg *dns.Msg, outmsg *dns.Msg, outerr error) {
	var ansin *dns.Msg // answer got from transports
	var err error

	fromtun := origin == x.OriginTunnel        // from tun? not an internal query
	uidself := uid == protect.MyUid            // us?
	usepreset := len(preset) > 0               // preset may be nil
	mod := !uidself && fromtun && t.mod.Load() // allow alg?
	discarduid := !t.split.Load()              // do not split tunnel?
	hasblock := isAnyBlockAll(idstr(t1), idstr(t2))
	hasfixed := isAnyFixed(idstr(t1))         // fixed transport?
	usefixed := !usepreset && mod && hasfixed // use preset fixed realips?
	skipcache := skipInternalCache(idstr(t1), idstr(t2))
	// do not perform alg or use its "xip" caches by the way of ptr, nat, alg
	// maps for synthesized response and block-all transport. That's because
	// BlockAll and synth responses are "ephemeral" in that, they may be based
	// on a UID and not just a tid + qname + qtype (cf: DNSListener.OnQuery)
	// but ptr, nat, alg maps are only tied to (tid, qname, qtype) tuple. Also,
	// it isn't necessary that if a qname is blocked right now, it will be blocked
	// by subsequent OnQuery()s as the rules are dynamic (for instance, a uid+qname
	// may be blocked because device is in keyguard/locked state but allowed
	// when the user is present (device is unlocked).
	//
	// In the cases where the uid is protect.MyUid (that is, requests sent by dns64.go
	// or ipmapper.go) should not be alg'd as the alg'd ips will end up as "realips"
	// in xips caches. nb: setting mod = false will achieve the same effect but it goes
	// through the effort of setting up alg/ptr/nat caches which is wasteful but usefult:
	// Since in Loopback scenario for uidself (which probably should be alg'd to make
	// sure the ptr/nat mapping (ips=>doms) are up-to-date for firewall decisions
	// like "block when dns is bypassed")
	dontalg := usepreset || skipcache || hasblock /*|| uidself */
	// usefixed generates fake but static answers for A/AAAA queries and no
	// actual resolution request is sent (not even to the cache). It is expected
	// that during PreFlow, the proxy layer will again attempt to resolve when
	// it sees that an algip has been mapped to this fake (fixed) ip.
	synthAns := usepreset || usefixed
	hasdnssec := xdns.IsDNSSECRequested(q)

	smm.DO = hasdnssec

	oguid := uid
	if discarduid {
		// forces use of a common (not per-app) ptr, nat, alg "key"
		uid = core.UNKNOWN_UID_STR
	}
	if hasfixed && !usefixed {
		log.W("alg: q: %s dnsx.Fixed must be used with mod & without preset, instead using... %s", smm.FID, idstr(t2))
		t1 = t2 // assert t2 != nil?
	} else if usefixed {
		// fixed ip responses must always be alg'd unlike preset / blockall
		// even when uid == protect.MyUid as dnsx.Fixed overrides all other
		// settings & must respond with modded (alg'd) ips. It is another thing
		// that protect.MyUid requests should never need dnsx.Fixed.
		dontalg = false
		preset = fixedRealIPs
		mod = true // assert mod == true?
		t1 = t2    // assert t2 != nil?
	}
	if t1 == nil || core.IsNil(t1) {
		log.W("alg: q: no primary transport %s; t1 %s, t2 %s, uid %s, self? %t preset? %t fixed? %t synth? %t nouid? %t",
			smm.FID, idstr(t1), idstr(t2), uid, uidself, usepreset, usefixed, synthAns, discarduid)
		return nil, nil, errAlgNoTransport
	}

	// when synthesizing answers, override both t1 and t2:
	// discard t2 as with preset we don't care about additional ips and blocklists;
	// t1 is not discarded entirely as it is needed to subst ips in https/svcb responses
	if synthAns {
		t2 = nil // assert t2 == nil?
	}
	t1res := make(chan *dns.Msg, 1)
	innersummary := copySummary(smm)
	// todo: use context?
	secch := t.qs(t2, uid, innersummary.FID, snetwork, q, t1res) // t2 may be nil

	if synthAns {
		ansin, err = synthesizeOrQuery(preset, t1, q, network, innersummary, usefixed)
	} else {
		ansin, err = t.qp(t1, uid, network, q, innersummary)
	}
	t1res <- ansin // ansin may be nil; but that's ok

	// override relevant values in smm
	fillSummary(innersummary, smm)

	if err != nil || ansin == nil {
		if ansin == nil {
			log.I("alg: q: abort no ans on %s+%s[%s] (fid: %s); self? %t synth? %t; qerr %v",
				idstr(t1), idstr(t2), uid, smm.FID, uidself, synthAns, err)
			return nil, nil, core.JoinErr(err, errNoAnswer)
		}
		if !xdns.HasRcodeSuccess(ansin) {
			return ansin, nil, err
		}
		if log.Debug {
			log.D("alg: q: for %s:%s (fid: %s) err but ans ok: %d; do? %t, self? %t synth? %t; qerr %v",
				qname(ansin), qtype(ansin), smm.FID, xdns.Len(ansin), hasdnssec, uidself, synthAns, err)
		}
	}

	hasauth64 := false
	hasauth := xdns.IsDNSSECAnswerAuthenticated(ansin)

	qname := qname(ansin)
	qtyp := qtype(ansin)
	smm.QName = qname
	smm.QType = qtyp

	// if usefixed is true, then d64 is no-op, as preset fixed ip does have ipv6
	ans64 := t.dns64.D64(network, t1.ID(), oguid, ansin) // ans64 may be nil if no D64 or error
	if ans64 != nil {
		if log.Debug {
			log.D("alg: %s<>%s:%s[%s] %d dns64; dnssec? %t; s/ans(%d)/ans64(%d)",
				qname, smm.ID, idstr(t1), oguid, qtyp, hasdnssec, xdns.Len(ansin), xdns.Len(ans64))
		}
		withDNS64Summary(ans64, smm)
		// todo: for uidself, skip dns64? see: ipmapper.go:undoAlgAndOrNat64
		// todo: skip for for undelegated domains like ipv4only.arpa?
		ansin = ans64
		// false if ans64 is synthesized or nil
		// or its value matches hasauth
		hasauth64 = xdns.IsDNSSECAnswerAuthenticated(ans64)
	} // else: no dns64, or error; continue with ansin

	smm.AD = hasauth && hasauth64 // true if both ansin and ans64 are authenticated

	hasq := xdns.HasAAAAQuestion(ansin) || xdns.HasAQuestion(ansin) ||
		xdns.HasSVCBQuestion(ansin) || xdns.HasHTTPQuestion(ansin)
	hasans := xdns.HasAnyAnswer(ansin)
	rgood := xdns.HasRcodeSuccess(ansin)
	// for t1, ansin's already evaluated for ans0000 in querySecondary
	// (secans.pri is set to true). ansin may be from t2 (if t2 != nil),
	// ans64, which is a modified ansin, depending on settings.PtMode
	ans0000 := xdns.AQuadAUnspecified(ansin) // ansin is not nil; ans64 may be nil

	if ans0000 {
		smm.UpstreamBlocks = true
	}

	defer func() {
		// answers in outmsg may not have been cached at all by xips
		// since register may not have happened at all
		xdns.BustAndroidCacheIfNeeded(outmsg)

		if isAlgErr(outerr) && !mod {
			if log.Debug {
				log.D("alg: q: %s<>%s[%s]:%s:%d %s no mod; suppress err %v",
					smm.ID, idstr(t1), uid, qname, qtyp, smm.FID, outerr)
			}
			outerr = nil // ignore alg errors if no modification is desired
		}
	}()

	// todo: skip alg for undelegated domains like ipv4only.arpa?
	if !hasq || !hasans || !rgood || ans0000 || dontalg {
		if log.Debug {
			log.D("alg: q: skip; query %s<>%s[%s]:%s:%d %s / a:%d + rdata: %s + status: %d, dnssec(do? %t /ad? %t) self(%t) dontalg(%t) hasq(%t) hasans(%t) rgood(%t), ans0000(%t)",
				smm.ID, idstr(t1), uid, qname, qtyp, smm.FID, xdns.Len(ansin), smm.RData, smm.Status, smm.DO, smm.AD, uidself, dontalg, hasq, hasans, rgood, ans0000)
		}
		return ansin, nil, nil
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
	smm.BlockedTarget = secres.smm.BlockedTarget
	smm.UpstreamBlocks = secres.smm.UpstreamBlocks || smm.UpstreamBlocks

	if smm.UpstreamBlocks || len(secres.smm.Msg) > 0 {
		smsg := secres.smm.Msg
		spri := secres.pri
		log.V("alg: q: %s<>%s[%s]:%s:%d %s upstream blocks: primary? %t / sec? %t / per-app? %t; secres: pri? %t, msg: %s",
			smm.ID, idstr(t1), oguid, qname, qtyp, smm.FID, secres.smm.UpstreamBlocks, smm.UpstreamBlocks, !discarduid, spri, smsg)
	}

	ansttl := time.Duration(xdns.RTtl(ansin)) * time.Second

	t.Lock()
	defer t.Unlock()

	var algip4hints, algip6hints, algip4s, algip6s netip.Addr
	if len(a6) > 0 {
		realip = append(realip, a6...)
		// choose the first alg ip6; may've been generated by a6
		algip, ipok := t.take6Locked(qname, 0)
		if !ipok {
			return ansin, nil, errAlgNotAvail
		}
		algip6s = algip
	}
	if len(a4) > 0 {
		realip = append(realip, a4...)
		algip, ipok := t.take4Locked(qname, 0)
		if !ipok {
			return ansin, nil, errAlgNotAvail
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
				return ansin, nil, errAlgNotAvail
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
				return ansin, nil, errAlgNotAvail
			}
			algip6hints = algip
		} else {
			algip6hints = algip6s
		}
	}

	algXlatTtl := xdns.ZeroTTL
	substok4 := false
	substok6 := false
	// substitutions needn't happen when no alg ips to begin with
	// but must happen if (real) ips are fixed
	mustsubst := false || usefixed
	ansmod := xdns.CopyAns(ansin)
	// TODO: substitute ips in additional section
	if algip4hints.IsValid() {
		substok4 = xdns.SubstSVCBRecordIPs( /*out*/ ansmod, dns.SVCB_IPV4HINT, algip4hints, algXlatTtl) || substok4
		mustsubst = true
	}
	if algip6hints.IsValid() {
		substok6 = xdns.SubstSVCBRecordIPs( /*out*/ ansmod, dns.SVCB_IPV6HINT, algip6hints, algXlatTtl) || substok6
		mustsubst = true
	}
	if algip4s.IsValid() {
		substok4 = xdns.SubstARecords( /*out*/ ansmod, algip4s, algXlatTtl) || substok4
		mustsubst = true
	}
	if algip6s.IsValid() {
		substok6 = xdns.SubstAAAARecords( /*out*/ ansmod, algip6s, algXlatTtl) || substok6
		mustsubst = true
	}

	if log.Debug {
		log.D("alg: q: %s<>%s[%s]; %s:%d %s (split? %t, do? %t / ad? %t) a6(a %d / h %d / s %t) : a4(a %d / h %d / s %t); ttl: %s",
			smm.ID, idstr(t1), oguid, qname, qtyp, smm.FID, !discarduid, smm.DO, smm.AD, len(a6), len(ip6hints), substok6, len(a4), len(ip4hints), substok4, ansttl)
	}
	if !substok4 && !substok6 {
		if mustsubst { // always true when usefixed is true
			err = errAlgCannotSubst
		} else { // no algips
			err = nil
		}
		logeif(err != nil)("alg: q: %s<>%s[%s] %s:%d %s: skip; err(%v); ips subst %s:%d; fixed? %t, split? %t",
			smm.ID, idstr(t1), oguid, qname, qtyp, smm.FID, err, usefixed, !discarduid)
		return ansin, nil, err // ansin is nil if no alg ips
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

	// always use the ID as set in the summary; which may or may not match
	// the primary t1.ID(). For instance, a caching dnsx.Transport (cacher)
	// may set DNSSummary.ID of the underlying dnsx.Transport that fetched
	// the answer, whose ID != to t1 (cacher) itself. OTOH, dnsx.Resolver
	// uses DNSSummary.ID when returning ans to the caller (ex: ipmapper)
	tidToReg := smm.ID
	if log.Debug {
		log.D("alg: q: ok; for %s<>%s[%s]:%s:%d %s (do? %t / ad? %t), domains %s real: %s / fix: %s => subst %s | %s; (mod? %t / fix? %t / synth? %t / split? %t); sec %s; ttl %s",
			tidToReg, idstr(t1), oguid, qname, qtyp, smm.FID, smm.DO, smm.AD, targets, realip, fixedips, algip4, algip6, mod, usefixed, synthAns, !discarduid, secres.ips, ansttl)
	}

	// always register algips, even if mod is false, to maintain a hot cache.
	// if client enables mod later, algips will be instantly available.
	algok := t.registerLocked(qname, tidToReg, uid /* not oguid */, smm.FID, algip4, algip6, realip, ansttl, targets, secres)

	if mod { // if mod is set, send modified answer and summary
		withAlgSummary(smm, algip4, algip6)
		if algok {
			return ansin, ansmod, nil
		} // else: err out if alg is requested but algips could not be registered
		return ansin, nil, errAlgCannotRegister
	}
	return ansin, nil, nil
}

func Netip2Csv(ips []netip.Addr) (csv string) {
	if len(ips) <= 0 {
		return ""
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip.IsValid() {
			out = append(out, ip.String())
		}
	}
	return strings.Join(out, ",")
}

func Csv2Netip(csv string) (ips []netip.Addr) {
	out := make([]netip.Addr, 0)
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
		prefix := TransportPrefix(AlgDNS64)
		s.Server = prefix + s.Server
	}
}

func withAlgSummary(s *x.DNSSummary, algips ...netip.Addr) {
	// convert algips to ipcsv; any algips may be invalid
	ipcsv := Netip2Csv(algips)

	if settings.Debug {
		if len(s.RData) > 0 {
			s.RData = s.RData + "," + ipcsv
		} else {
			s.RData = ipcsv
		}
		prefix := TransportPrefix(Alg)
		if len(s.Server) > 0 {
			s.Server = prefix + s.Server
		} else {
			s.Server = prefix + notransport
		}
	}
}

func (t *dnsgateway) registerLocked(q, tid, uid, fid string, algip4, algip6 netip.Addr, realips []netip.Addr, ttl time.Duration, targets []string, secres secans) bool {
	if tid == notransport || tid == NoDNS || len(tid) <= 0 {
		log.E("alg: reg: no tid for %s@%s[%s] %s; real? %d [%v], sec? %d [%v]",
			q, tid, uid, fid, len(realips), realips, len(secres.ips), secres.ips)
		return false
	}
	if !algip4.IsValid() && !algip6.IsValid() { // defensive; should not happen
		log.E("alg: reg: no algips for %s@%s[%s] %s; real? %d [%v], sec? %d [%v]",
			q, tid, uid, fid, len(realips), realips, len(secres.ips), secres.ips)
		return false
	}

	// uid may be UNKNOWN_UID_STR if discarduid is true (ie, split is false)

	// some domain set very low ttl (ex: 1s for news.ycombinator.com) which
	// is too short for translations; use a minimum of 8s to account
	// for just-in-time re-resolution of the same domain by common.go via
	// dialers.ResolverFor(uid) which may be called on new tcp / udp conn.
	ttl = min(ttl8s, ttl)
	algttl := min(ttl2m, ttl)

	now := time.Now()
	// ttl is used for algans and xips, but the alg'fied dns answer
	// has a lower ttl as defined by const algttl (currently, 8s).
	ansttl := now.Add(algttl)
	xipsttl := now.Add(ttl)
	// secres.ips may be empty on timeout errors, or
	// or same as realips if t2 is nil; realips can be nil
	// if fixedips is being used.
	am4 := &baseans{
		ips:        NewXips(tid, uid, v4only(realips), v4only(secres.ips), xipsttl),
		domains:    NewXdomains(tid, uid, targets, xipsttl), // targets may be nil
		blocklists: secres.smm.Blocklists,
		ttl:        ansttl, // extended by 2m on every use
	}
	am6 := &baseans{
		ips:        NewXips(tid, uid, v6only(realips), v6only(secres.ips), xipsttl),
		domains:    NewXdomains(tid, uid, targets, xipsttl), // targets may be nil
		blocklists: secres.smm.Blocklists,
		ttl:        ansttl, // extended by 2m on every use
	}

	// Check if NewXips failed to create valid xips objects
	if am4.ips == nil || am6.ips == nil || am4.domains == nil || am6.domains == nil {
		log.E("alg: reg: failed to create xips/xdomains for %s@%s[%s] %s; am4.ips: %v, am6.ips: %v",
			q, tid, uid, fid, am4.ips, am6.ips)
		return false
	}

	newEntry := false
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
			// merge x into prevans
			prevans.merge(x)
			x = prevans
		} else {
			t.alg[k] = x
			t.nat[ip] = x.baseans
			newEntry = true
		}
		// am.ips.realips() may return nil; ex: when preset fixed ips are used
		x.ips.each(func(ip netip.Addr) {
			// existing am is merged into am4/am6 by t.alg above
			// register mapping from realip -> algip+qname (ptr)
			t.ptr[ip] = x.baseans
		})
		didRegister = true
	}
	logeif(!didRegister)("alg: reg: algips (reg? %t / new? %t) (alg: %s+%s => real: %s) for %s@%s[%s] %s; real? %d, sec? %d; until (ans: %s / xips: %s)",
		didRegister, newEntry, algip4, algip6, realips, q, tid, uid, fid, len(realips), len(secres.ips), time.Until(ansttl), time.Until(xipsttl))

	return didRegister
}

func (t *dnsgateway) take4Locked(q string, idx int) (netip.Addr, bool) {
	k := q + key4 + strconv.Itoa(idx)
	if ans, ok := t.alg[k]; ok {
		ip := ans.algip
		if ip.Is4() {
			ans.extend(ttl2m)
			return ip, true
		} else {
			// shouldn't happen; if it does, rm erroneous entry and fall through to generate new
			delete(t.alg, k)
			delete(t.nat, ip)
			ans.ips.each(func(ip netip.Addr) {
				if pans := t.ptr[ip]; pans == ans.baseans {
					delete(t.ptr, ip)
				}
			})
			log.E("alg: gen: take4: found %s but not ip4 %s; removed: %s", k, ip, ans)
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
		log.E("alg: gen: no more IP4s (%v)", q)
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
			if d := time.Since(ent.ttl); d > 0 && ent.algip.Is4() {
				log.I("alg: gen: take4: reuse stale alg %s for %s", kx, k)
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
		log.E("alg: gen: take4: no more IP4s (%v)", t.octets)
	}
	return zeroaddr, false
}

func gen4Locked(k string, salt int) netip.Addr {
	s := strconv.Itoa(salt) + k
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
			log.E("alg: gen: take6: found %s but not ip6 %s; removed: %s", k, ip, ans)
		}
	}

	if t.chash {
		for i := range maxiter {
			genip := gen6Locked(k, i)
			if _, taken := t.nat[genip]; !taken {
				return genip, genip.IsValid()
			}
		}
		log.E("alg: gen: take6: no more IP6s (%v)", q)
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
		// try recycling stale entries before giving up
		i := 0
		for kx, ent := range t.alg {
			if i > maxiter {
				break
			}
			if d := time.Since(ent.ttl); d > 0 && ent.algip.Is6() {
				log.I("alg: gen: take6: reuse stale alg %s for %s", kx, k)
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
		// 64:ff9b:1:da19:0100.x.y.z: big endian is network-order, which netip expects
		b16 := [16]byte{}
		for i, hx := range t.hexes {
			i = i * 2
			binary.BigEndian.PutUint16(b16[i:i+2], hx)
		}
		genip := netip.AddrFrom16(b16)
		return genip, genip.IsValid()
	} else {
		log.E("alg: gen: take6: no more IP6s (%x)", t.hexes)
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

func (t *dnsgateway) S() string {
	t.RLock()
	defer t.RUnlock()

	var (
		priips, auxips, pastips uint64
		pridoms, pastdoms       uint64
	)

	for _, a := range t.alg {
		if a == nil || a.baseans == nil {
			continue
		}
		if a.ips != nil {
			a.ips.pmu.RLock()
			priips += uint64(len(a.ips.pri))
			auxips += uint64(len(a.ips.aux))
			pastips += uint64(len(a.ips.past))
			a.ips.pmu.RUnlock()
		}
		if a.domains != nil {
			a.domains.pmu.RLock()
			pridoms += uint64(len(a.domains.pri))
			pastdoms += uint64(len(a.domains.past))
			a.domains.pmu.RUnlock()
		}
	}

	var sb strings.Builder
	sb.WriteString("dnsgateway state:\n")
	sb.WriteString(" mod: ")
	sb.WriteString(strconv.FormatBool(t.mod.Load()))
	sb.WriteString(" / cansplit: ")
	sb.WriteString(strconv.FormatBool(t.split.Load()))
	sb.WriteString(" / forcesplit: ")
	sb.WriteString(strconv.FormatBool(t.fix.Load()))
	sb.WriteString(" / usefixed: ")
	sb.WriteString(strconv.FormatBool(t.fixedTransport()))
	sb.WriteString(" / chash: ")
	sb.WriteString(strconv.FormatBool(t.chash))
	sb.WriteString("\n alg: ")
	sb.WriteString(strconv.Itoa(len(t.alg)))
	sb.WriteString(" / nat: ")
	sb.WriteString(strconv.Itoa(len(t.nat)))
	sb.WriteString(" / ptr: ")
	sb.WriteString(strconv.Itoa(len(t.ptr)))
	sb.WriteString("\n    xips(pri=")
	sb.WriteString(strconv.FormatUint(priips, 10))
	sb.WriteString(" aux=")
	sb.WriteString(strconv.FormatUint(auxips, 10))
	sb.WriteString(" past=")
	sb.WriteString(strconv.FormatUint(pastips, 10))
	sb.WriteString(")\n    xdoms(pri=")
	sb.WriteString(strconv.FormatUint(pridoms, 10))
	sb.WriteString(" past=")
	sb.WriteString(strconv.FormatUint(pastdoms, 10))
	sb.WriteString(")")
	return sb.String()
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

func (t *dnsgateway) PTR(maybeAlg netip.Addr, uid, tid string, force bool) (domains string, didForce bool) {
	t.RLock()
	defer t.RUnlock()

	if !t.split.Load() {
		uid = core.UNKNOWN_UID_STR
	}

	// do not use t.ptr (realip -> ans) in mod (alg) mode, unless forced;
	// as t.nat (algip -> ans) is a more accurate translation.
	useptr := !t.mod.Load() || force
	d := t.ptrLocked(maybeAlg, uid, tid, useptr)
	if len(d) > 0 {
		domains = strings.Join(d, ",")
	} // else: algip isn't really an alg ip, nothing to do
	return domains, useptr
}

func (t *dnsgateway) RESOLV(domain, uid, tid string) []netip.Addr {
	t.RLock()
	defer t.RUnlock()

	typ := typalg
	if !t.mod.Load() {
		typ = typreal
	}
	if !t.split.Load() {
		uid = core.UNKNOWN_UID_STR
	}
	// TODO: handle Preset IPs which aren't alg'd
	// TODO: for some skipInternalCache(tid) and uid == protect.MyUid
	// alg caches (nat/ptr) won't have any entries
	// See: dontalg var in dnsgateway.q() and dnsgateway.xLocked()
	if uid == protect.MyUid {
		uid = core.UNKNOWN_UID_STR // wildcard, so xips searches across all UIDs
		tid = notransport          // wildcard, so xips searches across all TIDs
	}
	if len(tid) <= 0 {
		tid = notransport
	}
	ip4s, ip6s, _, _, _ := t.resolvLocked(domain, typ, tid, uid)
	return append(ip4s, ip6s...)
}

func (t *dnsgateway) RDNSBL(algip netip.Addr) (blocklists string) {
	t.RLock()
	defer t.RUnlock()

	return t.rdnsblLocked(algip, !t.mod.Load())
}

func (t *dnsgateway) xLocked(maybeAlg netip.Addr, usestale bool, uid string, tids ...string) (realips []netip.Addr, _ bool) {
	var until time.Duration
	var undidAlg, undidPtr, fresh bool

	xst := makeXipStatus(!usestale)
	// alg ips are always unmappped; see take4Locked
	unmapped := maybeAlg.Unmap() // aligip may also be origip / realip

	// ignore & return the fake dns address as-is (ex: 10.111.222.3:53)
	if anyAddrEqual(t.fake, unmapped) {
		return []netip.Addr{maybeAlg}, false
	}

	// see: dontalg var in dnsgateway.q()
	// TODO: handle preset IPs that won't be in the ptr/nat caches
	uidself := uid == protect.MyUid
	skippedcache := skipInternalCache(tids...)
	didnotAlg := skippedcache || uidself

	if !didnotAlg {
		var ans *baseans
		// undidAlg is really "hasAnyAlgEntry"; set it to true
		// regardless of len(realips) or freshness of ans.ips
		if ans, undidAlg = t.nat[unmapped]; undidAlg {
			if len(tids) <= 0 {
				realips = ans.ips.realips(uid, xst)
			} else {
				for _, tid := range tids {
					realips = append(realips, ans.ips.realipsFor(tid, uid, xst)...)
				}
			}
			until, fresh = ans.fresh()
		} else if ans, undidPtr = t.ptr[unmapped]; undidPtr {
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
			until, fresh = ans.fresh()
		}
	}

	hasrealips := len(realips) > 0
	var unnated []netip.Addr
	if !hasrealips { // algip is probably origip / realip
		// unnat origip as it itself may have been synthesized from
		// our DNS responses by apps doing funky things; like FreeFire
		unnated = t.maybeUndoNat64Locked(unmapped)
	} else {
		unnated = t.maybeUndoNat64Locked(realips...)
	} // else: send realips as is

	logeif(!hasrealips && (!usestale && (!undidAlg || !undidPtr)))("alg: dns64: for %v[%s] (didnotAlg? %t / fresh? %t / undidAlg? %t / undidPtr? %t / staleok? %t) maybealgip(%v) => realips(%v) => unnated(%v); until: %s",
		tids, uid, didnotAlg, fresh, undidAlg, undidPtr, usestale, unmapped, realips, unnated, until)

	if len(unnated) > 0 { // unnated is already de-duplicated
		return unnated, undidAlg
	}

	if !hasrealips {
		// when realips is empty but one of undidAlg / undidPtr is not false,
		// it means the client code may retry re-resolving the corresponding
		// domain to freshen up alg mapping; which is to say, sending empty
		// realips instead of unmapped as-is is a way to signal that
		// the alg mapping is stale.
		if undidAlg || undidPtr {
			return realips, undidAlg // realips is empty here
		}
		// no algip, no realips, no unnated;
		// ptr + nat alg mapping do not exist / apply;
		// return unmapped as-is to the client code.
		return []netip.Addr{unmapped}, undidAlg
	}

	return copyUniq(realips), undidAlg
}

func (t *dnsgateway) maybeUndoNat64Locked(realips ...netip.Addr) (unnateds []netip.Addr) {
	for _, nip := range realips {
		unmapped := nip.Unmap()
		if !unmapped.Is6() {
			continue
		}
		// the actual ID of the DNS64 for this whoever responded with "realips" for some unknown
		// DNS query is not available. But, we needn't worry about UN-NAT64'ing other resolvers
		// except the one we "force" onto the clients (aka dnsx.Local464Resolver).
		// whether the active network has ipv4 connectivity is checked by dialers.filter()
		ipx4, completed := core.Grx("undoNat64."+unmapped.String(), func(ctx context.Context) (netip.Addr, error) {
			// with async+timeout to avoid blocking on mutex
			return t.dns64.X64(Local464Resolver, unmapped), nil // ipx4 may be zero addr
		}, ttl3s)

		logeif(!completed)("alg: dns64: maybeUndoNat64: nat64 to ip4(%v) for ip6(%v); timedout? %t",
			ipx4, nip, !completed)
		if !completed || !ipok(ipx4) { // no nat?
			continue
		}
		unmapped4 := ipx4.Unmap()
		unnateds = append(unnateds, unmapped4)
	}
	return copyUniq(unnateds)
}

func (t *dnsgateway) ptrLocked(maybeAlg netip.Addr, uid, tid string, useptr bool) (domains []string) {
	alivedoms := true
	hasnatdoms := false
	hasdoms := false

	// alg ips are always unmapped; see take4Locked
	unmapped := maybeAlg.Unmap()
	if len(uid) <= 0 {
		uid = core.UNKNOWN_UID_STR
	}
	if len(tid) <= 0 {
		tid = notransport
	}
	if ans, ok := t.nat[unmapped]; ok {
		domains = domainsFor(ans, tid, uid, unmapped, xalive)
		hasnatdoms = len(domains) > 0
		hasdoms = hasnatdoms
	}
	if useptr && !hasnatdoms {
		if ans, ok := t.ptr[unmapped]; ok {
			// translate from realip only if not in mod mode
			// for useptr, s/xalive/xall/
			domains = domainsFor(ans, tid, uid, unmapped, xalive /*prefer fresh mapping */)
			hasdoms = len(domains) > 0
			if !hasdoms {
				domains = domainsFor(ans, tid, uid, unmapped, xall /*useptr == true */)
				alivedoms = false
			}
		}
		hasdoms = len(domains) > 0
	}
	if log.Debug || !hasdoms {
		loged(!hasdoms)("alg: ptr: in nat? (natdoms? %t / doms? %t) for %v[%s@%s] => in ptr? (useptr? %t / gotalive? %t)? (%v)",
			hasnatdoms, hasdoms, unmapped, tid, uid, useptr, hasdoms && alivedoms, domains)
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
func (t *dnsgateway) resolvLocked(domain string, typ iptype, tid, uid string) (ip4s, ip6s, staleips []netip.Addr, until time.Duration, targets []string) {
	partkey4 := domain + key4
	partkey6 := domain + key6
	until = time.Duration(math.MaxInt64)

	ip4s = make([]netip.Addr, 0)
	ip6s = make([]netip.Addr, 0)
	targets = make([]string, 0)
	staleips = make([]netip.Addr, 0)
	switch typ {
	case typalg:
		for i := range 2 {
			k4 := partkey4 + strconv.Itoa(i)
			if ans, ok := t.alg[k4]; ok {
				if life, fresh := ans.fresh(); fresh { // not stale
					ip4s = append(ip4s, ans.algip)
					targets = append(targets, domainsFor(ans.baseans, tid, uid, ans.algip, xalive)...)
					until = min(until, life)
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
				if life, fresh := ans.fresh(); fresh { // not stale
					ip6s = append(ip6s, ans.algip)
					targets = append(targets, domainsFor(ans.baseans, tid, uid, ans.algip, xalive)...)
					until = min(until, life)
				} else {
					staleips = append(staleips, ans.algip)
				}
			} else {
				break
			}
		}
		if log.Verbose {
			log.V("alg: resolv: %s:%s[%s] => alg ip4 %d, ip6 %d (until: %s); stale %v",
				domain, tid, uid, len(ip4s), len(ip6s), until, staleips)
		}
	case typreal:
		for i := range 2 { // a = 0, https/svcb = 1+
			k4 := partkey4 + strconv.Itoa(i)
			if ans, ok := t.alg[k4]; ok {
				if life, fresh := ans.fresh(); fresh { // not stale
					all4s := v4only(ans.ips.realipsFor(tid, uid, xalive))
					ip4s = append(ip4s, all4s...)
					targets = append(targets, domainsFor(ans.baseans, tid, uid, core.FirstOf(all4s), xalive)...)
					until = min(until, life)
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
				if life, fresh := ans.fresh(); fresh { // not stale
					all6s := v6only(ans.ips.realipsFor(tid, uid, xalive))
					ip6s = append(ip6s, all6s...)
					targets = append(targets, domainsFor(ans.baseans, tid, uid, core.FirstOf(all6s), xalive)...)
					until = min(until, life)
				} else {
					staleips = append(staleips, ans.ips.realipsFor(tid, uid, xall)...)
				}
				// all ans{} have all realips; pick the first one
				break
			} // continue
		}
		if log.Verbose {
			log.V("alg: resolv: %s:%s[%s] => real(ip4 %d, ip6 %d) until: %s; stale %v",
				domain, tid, uid, len(ip4s), len(ip6s), until, staleips)
		}
	case typsecondary:
		for i := range 2 { // a = 0, https/svcb = 1+
			k4 := partkey4 + strconv.Itoa(i)
			if ans, ok := t.alg[k4]; ok {
				if life, fresh := ans.fresh(); fresh { // not stale
					all4s := v4only(ans.ips.secipsFor(tid, uid))
					ip4s = append(ip4s, all4s...)
					targets = append(targets, domainsFor(ans.baseans, tid, uid, core.FirstOf(all4s), xalive)...)
					until = min(until, life)
				} else {
					staleips = append(staleips, ans.ips.secips(xall)...)
				}
				// all ans{} have all secondaryips; pick the first one
				break
			} // continue
		}
		for i := range 2 { // aaaa = 0, https/svcb = 1+
			k6 := partkey6 + strconv.Itoa(i)
			if ans, ok := t.alg[k6]; ok {
				if life, fresh := ans.fresh(); fresh { // not stale
					all6s := v6only(ans.ips.secipsFor(tid, uid))
					ip6s = append(ip6s, all6s...)
					targets = append(targets, domainsFor(ans.baseans, tid, uid, core.FirstOf(all6s), xalive)...)
					until = min(until, life)
				} else {
					// TODO: stale targets?
					staleips = append(staleips, ans.ips.secips(xall)...)
				}
				// all ans{} have all secondaryips; pick the first one
				break
			} // continue
		}
		if log.Verbose {
			log.V("alg: resolv: %s:%s[%s] => secondary ip4 %d, ip6 %d (until: %s); stale %v",
				domain, tid, uid, len(ip4s), len(ip6s), until, staleips)
		}
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

// xor fold fnv to 22 bits: www.isthe.com/chongo/tech/comp/fnv
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
			log.W("alg: synthesize: %s with %v; err(%v); using tr %s %s",
				qname, preset, err, idstr(tr), smm.FID)
			return Req(tr, network, msg, smm)
		}
		withPresetSummary(smm, false /*req sent?*/, fixed)
		smm.ID = Preset
		smm.RCode = xdns.Rcode(ans)
		smm.RData = xdns.GetInterestingRData(ans)
		smm.RTtl = xdns.RTtl(ans) // usually 1 per xdns.AnsTTL

		log.V("alg: synthesize: %s q(4? %t / 6? %t), fixed? %t, rdata(%s) tr: %s fid: %s",
			qname, is4, is6, fixed, smm.RData, idstr(tr), smm.FID)

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

		log.D("alg: synthesize: q: %s; (HTTPS? %t / fixed? %t); subst4(%t), subst6(%t); rdata(%s); tr: %s fid: %s",
			qname, isHTTPS, fixed, ok4, ok6, smm.RData, idstr(tr), smm.FID)

		return ans, nil // no error
	} else {
		note := log.VV
		if fixed {
			note = log.W
		}
		note("alg: synthesize: %s skip; fixed? %t, qtype %d; using tr %s fid: %s",
			qname, fixed, qtyp, idstr(tr), smm.FID)
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
	qtyp := qtype(q)

	if smm == nil { // discard smm
		discarded := new(x.DNSSummary)
		smm = discarded
	}
	smm.ID = idstr(t)
	if len(smm.QName) <= 0 {
		smm.QName = qname
	}
	if smm.QType <= 0 {
		smm.QType = qtyp
	}

	r, err := t.Query(network, q, smm)

	if r == nil {
		if log.Verbose {
			log.V("alg: Req: %s:%d no answer; by: %s, fid: %s, rdata: %s, status: %d; err? %v",
				qname, qtyp, smm.ID, smm.FID, smm.RData, smm.Status, err)
		}
		return nil, err // err may be nil
	}
	if !xdns.IsServFailOrInvalid(r) {
		return r, nil
	}

	if log.Verbose {
		log.V("alg: Req: %s:%d servfail; by: %s, fid: %s, rdata: %s, status: %d, rcode %d",
			qname, qtyp, smm.ID, smm.FID, smm.RData, smm.Status, xdns.Rcode(r))
	}
	return r, err
}

func ChooseHealthyProxy(who, proto string, ipps []netip.AddrPort, pids []string, px ipn.ProxyProvider) (pid string) {
	var errs []error
	pid = NetNoProxy
	if len(pids) > 0 {
		pid = pids[0]
	}
	foundProxy := false
	cipp := netip.AddrPort{}
	for _, ipp := range ipps {
		if !ipp.IsValid() {
			continue
		}
		if p, err := px.ProxyTo(ipp, proto, protect.MyUid, pids); err == nil {
			pid = proxyID(p)
			foundProxy = pid != NetNoProxy
			cipp = ipp
			break
		} else {
			errs = append(errs, err)
		}
	}
	logeif(!foundProxy)("%s: proxy for %s [among %v]; choosing %s among %v; errs? %v",
		who, cipp, ipps, pid, pids, core.JoinErr(errs...))
	return
}

func ChooseHealthyProxyHostPort(who, proto string, host string, port uint16, pids []string, px ipn.ProxyProvider) (pid string) {
	var ipps []netip.AddrPort

	splithost, _, _ := net.SplitHostPort(host)
	if len(splithost) > 0 {
		host = splithost
	}

	if c := dialers.Confirmed(host); c.IsValid() {
		ipps = append(ipps, netip.AddrPortFrom(c, port))
	}

	for _, ip := range dialers.For(host) {
		if ip.IsValid() {
			ipps = append(ipps, netip.AddrPortFrom(ip, port))
		}
	}

	return ChooseHealthyProxy(who+" : "+host, proto, ipps, pids, px)
}

func OverrideStatusFrom(p x.Proxy) (bool, int32) {
	if p == nil {
		return false, Unknown
	}
	if s := p.Status(); s == ipn.TPU {
		// relay paused => transport paused
		return true, Paused
	} else if s == ipn.TKO {
		return true, TransportError
	} else if s == ipn.TUP {
		return true, Start
	}
	return false, Unknown
}

func proxyID(p ipn.Proxy) string {
	if p == nil {
		return NetNoProxy
	}
	return p.ID()
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
	return core.FilterLeft(ips, func(ip netip.Addr) bool {
		return ip.Is4()
	})
}

func v6only(ips []netip.Addr) []netip.Addr {
	return core.FilterLeft(ips, func(ip netip.Addr) bool {
		return ip.Is6()
	})
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
	smm.Server = TransportPrefix(id) + smm.Server
	smm.Blocklists = ""    // blocklists are not honoured
	smm.BlockedTarget = "" // no targets are blocked
	smm.PID = ""           // no relay is used
	smm.RPID = ""          // no hops either
}

func idstr(t Transport) string {
	if t == nil {
		return notransport
	}
	return t.ID()
}

func infcsv(ts ...Transport) string {
	var s []string
	for _, t := range ts {
		s = append(s, idstr(t)+":"+getaddrstr(t))
	}
	return strings.Join(s, ",")
}

func getaddrstr(t Transport) string {
	if t == nil {
		return notransport
	}
	return t.GetAddr()
}

func ipok(ip netip.Addr) bool {
	return !ip.IsUnspecified() && ip.IsValid()
}

// flattens and returns a copy with dups removed, if any.
func copyUniq[T comparable](a ...[]T) (out []T) {
	return core.CopyUniq(a...)
}

func logeif(cond bool) log.LogFn {
	if cond {
		return log.E
	}
	return log.D
}

func logwif(cond bool) log.LogFn {
	if cond {
		return log.W
	}
	return log.D
}
