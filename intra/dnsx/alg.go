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
	timeout     = 15 * time.Second
	ttl2m       = 2 * time.Minute // 2m ttl for alg/nat ip
	algttl      = 15              // 15s ttl for alg dns
	key4        = ":a"
	key6        = ":aaaa"
	notransport = "NoTransport"
	maxiter     = 100 // max number alg/nat evict iterations
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
	fixedRealIPs = []*netip.Addr{&rfc3068ip4, &rfc3068ip6}

	errNoTransportAlg    = errors.New("no alg transport")
	errNotAvailableAlg   = errors.New("no valid alg ips")
	errCannotRegisterAlg = errors.New("cannot register alg ip")
	errCannotSubstAlg    = errors.New("cannot substitute alg ip")
)

func isAlgErr(err error) bool {
	return (err == errCannotRegisterAlg || err == errNotAvailableAlg || err == errCannotSubstAlg)
}

type Gateway interface {
	// given an alg or real ip, retrieves assoc real ips as csv, if any
	X(maybeAlg netip.Addr) (realipcsv string, undidAlg bool)
	// given an alg or real ip, retrieves assoc dns names as csv, if any
	PTR(maybeAlg netip.Addr, force bool) (domaincsv string, didForce bool)
	// given domain, retrieve assoc alg ips or real ips as csv, if any
	RESOLV(domain string) (ipcsv string)
	// given an alg or real ip, retrieve assoc blocklists as csv, if any
	RDNSBL(maybeAlg netip.Addr) (blocklistcsv string)
	// translate overwrites ip answers to alg ip & fixed ip answers
	translate(yes bool)
	// Query using t1 as primary transport and t2 as secondary and preset as pre-determined ip answers
	q(t1 Transport, t2 Transport, preset []*netip.Addr, network string, q *dns.Msg, s *x.DNSSummary) (*dns.Msg, error)
	// clear obj state
	stop()
}

type secans struct {
	ips []*netip.Addr
	smm *x.DNSSummary
	pri bool
}

func (sec *secans) initIfNeeded() {
	// ptr reciever updates all secans in-place:
	// go.dev/play/p/wjBd1TC59zN
	if sec.ips == nil {
		sec.ips = []*netip.Addr{}
	}
	if sec.smm == nil {
		sec.smm = new(x.DNSSummary)
	}
}

type ans struct {
	algip        *netip.Addr   // generated answer, v6 or v4
	realips      []*netip.Addr // all ip answers, v6+v4; may be nil
	secondaryips []*netip.Addr // all ip answers from secondary, v6+v4; may be nil
	domain       []string      // all domain names in an answer (incl qname)
	qname        string        // the query domain name
	blocklists   string        // csv blocklists containing qname per active config at the time
	ttl          time.Time
}

type ansMulti struct {
	algips       []*netip.Addr // generated answers, v6 or v4
	realips      []*netip.Addr // all ip answers, v6+v4; may be nil
	secondaryips []*netip.Addr // all ip answers from secondary, v6+v4; may be nil
	domain       []string      // all domain names in an answer (incl qname)
	qname        string        // the query domain name
	blocklists   string        // csv blocklists containing qname per active config at the time
	ttl          time.Time
}

// TODO: Keep a context here so that queries can be canceled.
type dnsgateway struct {
	sync.RWMutex                          // locks alg, nat, octets, hexes
	alg          map[string]*ans          // domain+type -> ans
	nat          map[netip.Addr]*ans      // algip -> ans
	ptr          map[netip.Addr]*ansMulti // realip -> ansMulti
	octets       []uint8                  // ip4 octets, 100.x.y.z
	hexes        []uint16                 // ip6 hex, 64:ff9b:1:da19:0100.x.y.z

	// fields below are never reassigned

	rdns  RdnsResolver // local and remote rdns blocks
	dns64 NatPt        // dns64/nat64
	chash bool         // use consistent hashing to generate alg ips

	// fields below are mutable

	mod atomic.Bool // modify realip to algip
}

var _ Gateway = (*dnsgateway)(nil)

// NewDNSGateway returns a DNS ALG, ready for use.
func NewDNSGateway(pctx context.Context, outer RdnsResolver, dns64 NatPt) (t *dnsgateway) {
	alg := make(map[string]*ans)
	nat := make(map[netip.Addr]*ans)
	ptr := make(map[netip.Addr]*ansMulti)

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

// Implements Gateway
func (t *dnsgateway) stop() {
	t.Lock()
	defer t.Unlock()

	clear(t.alg)
	clear(t.nat)
	t.octets = rfc6598
	t.hexes = rfc8215a
}

func (t *dnsgateway) qs(t2 Transport, network string, msg *dns.Msg, t1res <-chan *dns.Msg) <-chan secans {
	t2res := make(chan secans, 1)
	go func() {
		defer close(t2res)

		qname := xdns.QName(msg)

		r, ok := core.Grx("alg.qs."+qname, func() secans {
			return t.querySecondary(t2, network, msg, t1res)
		}, timeout)

		if !ok {
			log.W("alg: skip; qs timeout; tr2: %s, qname: %s", idstr(t2), qname)
		}

		r.initIfNeeded() // r may be nil on Grx:timeout

		t2res <- r // may be zero secans
	}()
	return t2res
}

func (t *dnsgateway) querySecondary(t2 Transport, network string, msg *dns.Msg, t1res <-chan *dns.Msg) (result secans) {
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
		// query secondary to get answer for q
		r, err = Req(t2, network, msg, result.smm)
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
		if len(a.Answer) > 0 {
			result.ips = append(result.ips, xdns.AAnswer(a)...)
			result.ips = append(result.ips, xdns.AAAAAnswer(a)...)
		} // noop: for HTTPS/SVCB, the answer section is empty
		return
	} else {
		if len(blocklistnames) > 0 {
			result.smm.Blocklists = blocklistnames
		}
		if xdns.AQuadAUnspecified(r) {
			// A/AAAA must be 0.0.0.0/::, when UpstreamBlocks is true
			result.smm.UpstreamBlocks = true
		}
		if xdns.HasAnyAnswer(r) {
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
func (t *dnsgateway) q(t1, t2 Transport, preset []*netip.Addr, network string, q *dns.Msg, smm *x.DNSSummary) (*dns.Msg, error) {
	var ansin *dns.Msg // answer got from transports
	var err error

	usepreset := len(preset) > 0                    // preset may be nil
	mod := t.mod.Load()                             // allow alg?
	usefixed := !usepreset && isAnyFixed(idstr(t1)) // fixed realips?
	if usefixed {
		preset = fixedRealIPs
		mod = true // assert mod == true?
		usepreset = true
		t1 = t2 // assert t2 != nil?
	}
	if t1 == nil || core.IsNil(t1) {
		log.W("alg: no primary transport; t1 %s, t2 %s, preset? %t fixed? %t",
			idstr(t1), idstr(t2), usepreset, usefixed)
		return nil, errNoTransportAlg
	}

	// presets override both t1 and t2:
	// discard t2 as with preset we don't care about additional ips and blocklists;
	// t1 is not discarded entirely as it is needed to subst ips in https/svcb responses
	if usepreset {
		t2 = nil // assert t2 == nil?
	}
	t1res := make(chan *dns.Msg, 1)
	innersummary := new(x.DNSSummary)
	// todo: use context?
	secch := t.qs(t2, network, q, t1res) // t2 may be nil

	if usepreset {
		ansin, err = synthesizeOrQuery(preset, t1, q, network, innersummary, usefixed)
	} else {
		ansin, err = Req(t1, network, q, innersummary)
	}
	t1res <- ansin // ansin may be nil; but that's ok

	// override relevant values in summary
	fillSummary(innersummary, smm)

	if err != nil {
		if ansin == nil {
			log.I("alg: abort; r: 0, qerr %v", err)
			return nil, err
		}
		if !xdns.HasRcodeSuccess(ansin) {
			return ansin, err
		}
		log.D("alg: err but r ok; ans: %d, qerr %v", xdns.Len(ansin), err)
	}

	if ansin == nil { // may be nil on errors
		return nil, errNoAnswer // err is nil
	}

	qname, _ := xdns.NormalizeQName(xdns.QName(ansin))

	smm.QName = qname
	smm.QType = qtype(ansin)

	// if usefixed is true, then d64 is no-op, as preset fixed ip does have ipv6
	ans64 := t.dns64.D64(network, ansin, t1) // ans64 may be nil if no D64 or error
	if ans64 != nil {
		log.D("alg: %s:%d dns64; s/ans(%d)/ans64(%d)", qname, smm.QType, xdns.Len(ansin), xdns.Len(ans64))
		withDNS64Summary(ans64, smm)
		ansin = ans64
	} // else: no dns64, or error; continue with ansin

	hasq := xdns.HasAAAAQuestion(ansin) || xdns.HasAQuestion(ansin) ||
		xdns.HasSVCBQuestion(ansin) || xdns.HasHTTPQuestion(ansin)
	hasans := xdns.HasAnyAnswer(ansin)
	rgood := xdns.HasRcodeSuccess(ansin)
	// for t1, ansin's already evaluated for ans0000 in querySecondary,
	// when secans.pri is true (may be superceded by answer from t2,
	// if t2 != nil), & so only ans64 is checked for 0.0.0.0 / :: here.
	ans640000 := xdns.AQuadAUnspecified(ans64) // ans64 may be nil

	if ans640000 {
		smm.UpstreamBlocks = true
	}

	if !hasq || !hasans || !rgood || ans640000 {
		log.D("alg: skip; query %s:%d / a:%d, hasq(%t) hasans(%t) rgood(%t), ans0000(%t)",
			qname, smm.QType, xdns.Len(ansin), hasq, hasans, rgood, ans640000)
		return ansin, nil
	}

	a6 := xdns.AAAAAnswer(ansin)
	a4 := xdns.AAnswer(ansin)
	ip4hints := xdns.IPHints(ansin, dns.SVCB_IPV4HINT)
	ip6hints := xdns.IPHints(ansin, dns.SVCB_IPV6HINT)
	// TODO: generate one alg ip per target, synth one rec per target
	targets := xdns.Targets(ansin)
	realip := make([]*netip.Addr, 0)
	algips := make([]*netip.Addr, 0)

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
			qname, smm.QType, secres.smm.UpstreamBlocks, smm.UpstreamBlocks, spri, smsg)
	}

	defer func() {
		if isAlgErr(err) && !mod {
			log.D("alg: %s:%d no mod; suppress err %v", qname, smm.QType, err)
			err = nil // ignore alg errors if no modification is desired
		}
	}()

	t.Lock()
	defer t.Unlock()

	algip4hints := make([]*netip.Addr, 0, len(ip4hints))
	algip6hints := make([]*netip.Addr, 0, len(ip6hints))
	algip4s := make([]*netip.Addr, 0, len(a4))
	algip6s := make([]*netip.Addr, 0, len(a6))
	for i, ip4 := range ip4hints {
		realip = append(realip, ip4)
		// 0th algip is reserved for A records
		algip, ipok := t.take4Locked(qname, i+1)
		if !ipok {
			return ansin, errNotAvailableAlg
		}
		algip4hints = append(algip4hints, algip)
	}
	for i, ip6 := range ip6hints {
		realip = append(realip, ip6)
		// 0th algip is reserved for AAAA records
		algip, ipok := t.take6Locked(qname, i+1)
		if !ipok {
			return ansin, errNotAvailableAlg
		}
		algip6hints = append(algip6hints, algip)
	}
	if len(a6) > 0 {
		realip = append(realip, a6...)
		// choose the first alg ip6; may've been generated by ip6hints
		algip, ipok := t.take6Locked(qname, 0)
		if !ipok {
			return ansin, errNotAvailableAlg
		}
		algip6s = append(algip6s, algip)
	}
	if len(a4) > 0 {
		realip = append(realip, a4...)
		// choose the first alg ip4; may've been generated by ip4hints
		algip, ipok := t.take4Locked(qname, 0)
		if !ipok {
			return ansin, errNotAvailableAlg
		}
		algip4s = append(algip4s, algip)
	}

	substok4 := false
	substok6 := false
	// substituions needn't happen when no alg ips to begin with
	// but must happen if (real) ips are fixed
	mustsubst := false || usefixed
	ansout := ansin.Copy()
	// TODO: substitute ips in additional section
	if len(algip4hints) > 0 {
		substok4 = xdns.SubstSVCBRecordIPs( /*out*/ ansout, dns.SVCB_IPV4HINT, algip4hints, algttl) || substok4
		mustsubst = true
	}
	if len(algip6hints) > 0 {
		substok6 = xdns.SubstSVCBRecordIPs( /*out*/ ansout, dns.SVCB_IPV6HINT, algip6hints, algttl) || substok6
		mustsubst = true
	}
	if len(algip4s) > 0 {
		substok4 = xdns.SubstARecords( /*out*/ ansout, algip4s, algttl) || substok4
		mustsubst = true
	}
	if len(algip6s) > 0 {
		substok6 = xdns.SubstAAAARecords( /*out*/ ansout, algip6s, algttl) || substok6
		mustsubst = true
	}

	log.D("alg: %s:%d a6(a %d / h %d / s %t) : a4(a %d / h %d / s %t)",
		qname, smm.QType, len(a6), len(ip6hints), substok6, len(a4), len(ip4hints), substok4)
	if !substok4 && !substok6 {
		if mustsubst {
			err = errCannotSubstAlg
		} else { // no algips
			err = nil
		}
		log.D("alg: skip; err(%v); ips subst %s:%d; fixed? %t",
			err, qname, smm.QType, usefixed)
		return ansin, err // ansin is nil if no alg ips
	}

	// get existing real ips for qname, from previous alg/nat
	previp4s, previp6s, prevtargets := t.resolvLocked(qname, typreal)
	targets = removeDups(targets, prevtargets)

	var fixedips []*netip.Addr
	if usefixed {
		// if usefixed, then realips are in fact fixedips
		fixedips = realip
		// empty out realip and secres.ips got from answers
		// secres.ips is fixedips anyway since t2 is nil
		realip = nil
		secres.ips = nil
	}

	realip = removeDups2(realip, previp4s, previp6s)
	// get existing secondary ips for qname, from previous alg/nat
	prevsec4s, prevsec6s, _ := t.resolvLocked(qname, typsecondary)
	secres.ips = removeDups2(secres.ips, prevsec4s, prevsec6s)

	log.D("alg: subst; for %s:%d / prev targets %s; prev ips (alg? %t / fix? %t); v4: %s, v6: %s; sec4: %s, sec6: %s",
		qname, smm.QType, prevtargets, mod, usefixed, previp4s, previp6s, prevsec4s, prevsec6s)
	// TODO: just like w/ previps/prevtargets, get blocklists for qname and merge w/ new ones?

	ansttl := time.Duration(xdns.RTtl(ansin)) * time.Second
	algips = append(algips, algip4s...)
	algips = append(algips, algip6s...)
	algips = append(algips, algip4hints...)
	algips = append(algips, algip6hints...)
	x := &ansMulti{
		algips:  algips,
		realips: realip,
		// may be empty on timeout errors, or
		// or same as realips if t2 is nil
		secondaryips: secres.ips,
		domain:       targets, // may be nil
		qname:        qname,
		blocklists:   secres.smm.Blocklists,
		// qname->realip valid for next ttl seconds
		// but algips are valid for algttl seconds
		ttl: time.Now().Add(max(ttl2m, ansttl)),
	}

	log.D("alg: ok; domains %s real: %s / fix: %s => subst %s; mod? %t; sec %s",
		targets, realip, fixedips, algips, mod, secres.ips)

	if t.registerMultiLocked(qname, x) {
		// if mod is set, send modified answer
		if mod {
			withAlgSummaryIfNeeded(algips, smm)
			return ansout, nil
		} else {
			return ansin, nil
		}
	} else {
		return ansin, errCannotRegisterAlg
	}
}

func netip2csv(ips []*netip.Addr) (csv string) {
	for i, ip := range ips {
		if i > 0 {
			csv += ","
		}
		csv += ip.String()
	}
	return strings.TrimSuffix(csv, ",")
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

func withAlgSummaryIfNeeded(algips []*netip.Addr, s *x.DNSSummary) {
	if settings.Debug {
		// convert algips to ipcsv
		ipcsv := netip2csv(algips)

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

func (am *ansMulti) ansViewLocked(i int) *ans {
	return &ans{
		algip:        am.algips[i],
		realips:      am.realips,
		secondaryips: am.secondaryips,
		domain:       am.domain,
		qname:        am.qname,
		blocklists:   am.blocklists,
		ttl:          am.ttl,
	}
}

func (t *dnsgateway) registerMultiLocked(q string, am *ansMulti) bool {
	if len(am.algips) <= 0 { // defensive; should not happen
		log.E("alg: no algips for %s; real? %d, sec? %d", q, len(am.realips), len(am.secondaryips))
		return false
	}

	// register mapping from qname -> algip+realip (alg) and algip -> qname+realip (nat)
	for i := range am.algips { // am.algip may be nil?
		x := am.ansViewLocked(i)
		ip := x.algip
		var k string
		if ip.Is4() {
			k = q + key4 + strconv.Itoa(i)
		} else if ip.Is6() {
			k = q + key6 + strconv.Itoa(i)
		} else {
			return false
		}
		t.alg[k] = x
		t.nat[*ip] = x
	}
	// register mapping from realip -> algip+qname (ptr)
	for i := range am.realips { // am.realip may be nil.
		ip := am.realips[i] // todo: clone(am)?
		t.ptr[*ip] = am     // am contains qname and the algips
	}
	return true
}

func (t *dnsgateway) take4Locked(q string, idx int) (*netip.Addr, bool) {
	k := q + key4 + strconv.Itoa(idx)
	if ans, ok := t.alg[k]; ok {
		ip := ans.algip
		if ip.Is4() {
			ans.ttl = time.Now().Add(ttl2m)
			return ip, true
		} else {
			// shouldn't happen; if it does, rm erroneous entry
			delete(t.alg, k)
			delete(t.nat, *ip)
		}
	}

	if t.chash {
		for i := 0; i < maxiter; i++ {
			genip := gen4Locked(k, i)
			if !genip.IsGlobalUnicast() {
				continue
			}
			if _, taken := t.nat[genip]; !taken {
				return &genip, genip.IsValid()
			}
		}
		log.W("alg: gen: no more IP4s (%v)", q)
		return nil, false
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
				delete(t.nat, *ent.algip)
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
		return &genip, genip.IsValid()
	} else {
		log.W("alg: no more IP4s (%v)", t.octets)
	}
	return nil, false
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

func (t *dnsgateway) take6Locked(q string, idx int) (*netip.Addr, bool) {
	k := q + key6 + strconv.Itoa(idx)
	if ans, ok := t.alg[k]; ok {
		ip := ans.algip
		if ip.Is6() {
			ans.ttl = time.Now().Add(ttl2m)
			return ip, true
		} else {
			// shouldn't happen; if it does, rm erroneous entry
			delete(t.alg, k)
			delete(t.nat, *ip)
		}
	}

	if t.chash {
		for i := 0; i < maxiter; i++ {
			genip := gen6Locked(k, i)
			if _, taken := t.nat[genip]; !taken {
				return &genip, genip.IsValid()
			}
		}
		log.W("alg: gen: no more IP6s (%v)", q)
		return nil, false
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
		return &genip, genip.IsValid()
	} else {
		log.W("alg: no more IP6s (%x)", t.hexes)
	}
	return nil, false
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

func (t *dnsgateway) X(maybeAlg netip.Addr) (ips string, undidAlg bool) {
	t.RLock()
	defer t.RUnlock()

	// stale IPs are okay iff !mod; as then maybeAlg itself is a realip
	usestale := !t.mod.Load()
	rip, undidAlg := t.xLocked(maybeAlg, usestale)
	if len(rip) > 0 {
		var s []string
		for _, r := range rip {
			if r != nil && r.IsValid() {
				s = append(s, r.String())
			}
		}
		ips = strings.Join(s, ",")
	} // else: algip isn't really an alg ip, nothing to do

	return ips, undidAlg
}

func (t *dnsgateway) PTR(maybeAlg netip.Addr, force bool) (domains string, didForce bool) {
	t.RLock()
	defer t.RUnlock()

	// do not use t.ptr (realip -> ans) in mod mode, unless forced
	useptr := !t.mod.Load() || force
	d := t.ptrLocked(maybeAlg, useptr)
	if len(d) > 0 {
		domains = strings.Join(d, ",")
	} // else: algip isn't really an alg ip, nothing to do
	return domains, useptr
}

func (t *dnsgateway) RESOLV(domain string) (ipcsv string) {
	t.RLock()
	defer t.RUnlock()

	typ := typalg
	if !t.mod.Load() {
		typ = typreal
	}
	ip4s, ip6s, _ := t.resolvLocked(domain, typ)
	ips := append(ip4s, ip6s...)
	if len(ips) > 0 {
		var s []string
		for _, ip := range ips {
			if ip != nil && ip.IsValid() {
				s = append(s, ip.String())
			}
		}
		ipcsv = strings.Join(s, ",")
	}
	return
}

func (t *dnsgateway) RDNSBL(algip netip.Addr) (blocklists string) {
	t.RLock()
	defer t.RUnlock()

	return t.rdnsblLocked(algip, !t.mod.Load())
}

func (t *dnsgateway) xLocked(maybeAlg netip.Addr, usestale bool) ([]*netip.Addr, bool) {
	var realips []*netip.Addr
	var undidAlg, fresh bool
	// alg ips are always unmappped; see take4Locked
	unmapped := maybeAlg.Unmap() // aligip may also be origip / realip
	if ans, ok := t.nat[unmapped]; ok {
		if fresh = time.Until(ans.ttl) > 0; fresh || usestale {
			realips = append(ans.realips, ans.secondaryips...)
		}
		undidAlg = true
	} else if ans, ok := t.ptr[unmapped]; ok {
		// for IPs (unlike domains), it is okay to fallback on ptr as the
		// maybeAlg may be an algip OR realip (latter in the case where an
		// app is connecting to a cached IP addr from before t.mod was set)
		// nb: both realips & secondaryips may be nil, but that's okay:
		// go.dev/play/p/fSjRjMSAS2m
		if fresh = time.Until(ans.ttl) > 0; fresh || usestale {
			realips = append(ans.realips, ans.secondaryips...)
		}
	}
	var unnated []*netip.Addr
	if len(realips) == 0 { // algip is probably origip / realip
		// unnat origip as it itself may have been synthesized from
		// our DNS responses by apps doing funky things; like FreeFire
		unnated = t.maybeUndoNat64(&unmapped)
	} else {
		unnated = t.maybeUndoNat64(realips...)
	}
	log.D("alg: dns64: (fresh? %t / staleok? %t) algip(%v) -> realips(%v) -> unnated(%v)",
		fresh, usestale, unmapped, realips, unnated)
	if len(unnated) > 0 { // unnated is already de-duplicated
		return unnated, undidAlg
	}
	return removeDups2(realips), undidAlg
}

func (t *dnsgateway) maybeUndoNat64(realips ...*netip.Addr) (unnat []*netip.Addr) {
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
			log.V("alg: dns64: maybeUndoNat64: No local nat64 to ip4(%v) for ip6(%v); ip not ok", ipx4, nip)
			continue
		}
		log.D("alg: dns64: maybeUndoNat64: nat64 to ip4(%v) from ip6(%v)", ipx4, nip)
		unmapped4 := ipx4.Unmap()
		unnat = append(unnat, &unmapped4)
	}
	return removeDups2(unnat)
}

func (t *dnsgateway) ptrLocked(maybeAlg netip.Addr, useptr bool) (domains []string) {
	// alg ips are always unmappped; see take4Locked
	unmapped := maybeAlg.Unmap()
	if ans, ok := t.nat[unmapped]; ok {
		domains = ans.domain
	} else if ans, ok := t.ptr[unmapped]; useptr && ok {
		// translate from realip only if not in mod mode
		domains = ans.domain
	}
	return removeDups(domains)
}

// resolvLocked returns IPs and related targets for domain
// depending on typ.
// If typ is typalg, it returns all algips for domain.
// If typ is typreal, it returns all realips for domain.
// If typ is typsecondary, it returns all secondaryips for domain.
// ip4s and ip6s may overlap, and are segregated by the source algip
// family (and not by the family of the resolved IPs themselves).
func (t *dnsgateway) resolvLocked(domain string, typ iptype) (ip4s, ip6s []*netip.Addr, targets []string) {
	partkey4 := domain + key4
	partkey6 := domain + key6

	ip4s = make([]*netip.Addr, 0)
	ip6s = make([]*netip.Addr, 0)
	targets = make([]string, 0)
	staleips := make([]*netip.Addr, 0)
	switch typ {
	case typalg:
		for i := 0; i < maxiter; i++ {
			k4 := partkey4 + strconv.Itoa(i)
			if ans, ok := t.alg[k4]; ok {
				if time.Until(ans.ttl) > 0 { // not stale
					ip4s = append(ip4s, ans.algip)
					targets = append(targets, ans.domain...)
				} else {
					staleips = append(staleips, ans.algip)
				}
			} else {
				break
			}
		}
		for i := 0; i < maxiter; i++ {
			k6 := partkey6 + strconv.Itoa(i)
			if ans, ok := t.alg[k6]; ok {
				if time.Until(ans.ttl) > 0 { // not stale
					ip6s = append(ip6s, ans.algip)
					targets = append(targets, ans.domain...)
				} else {
					staleips = append(staleips, ans.algip)
				}
			} else {
				break
			}
		}
		log.V("alg: resolv: %s -> alg ip4 %d, ip6 %d; stale %v", domain, len(ip4s), len(ip6s), staleips)
	case typreal:
		for i := 0; i < 2; i++ { // a = 0, https/svcb = 1+
			k4 := partkey4 + strconv.Itoa(i)
			if ans, ok := t.alg[k4]; ok {
				if time.Until(ans.ttl) > 0 { // not stale
					ip4s = append(ip4s, v4only(ans.realips)...)
					targets = append(targets, ans.domain...)
				} else {
					staleips = append(staleips, ans.realips...)
				}
				// all ans{} have all realips; pick the first one
				break
			} // continue
		}
		for i := 0; i < 2; i++ { // aaaa = 0, https/svcb = 1+
			k6 := partkey6 + strconv.Itoa(i)
			if ans, ok := t.alg[k6]; ok {
				if time.Until(ans.ttl) > 0 { // not stale
					ip6s = append(ip6s, v6only(ans.realips)...)
					targets = append(targets, ans.domain...)
				} else {
					staleips = append(staleips, ans.realips...)
				}
				// all ans{} have all realips; pick the first one
				break
			} // continue
		}
		log.V("alg: resolv: %s -> real ip4 %d, ip6 %d; stale %v", domain, len(ip4s), len(ip6s), staleips)
	case typsecondary:
		for i := 0; i < 2; i++ { // a = 0, https/svcb = 1+
			k4 := partkey4 + strconv.Itoa(i)
			if ans, ok := t.alg[k4]; ok {
				if time.Until(ans.ttl) > 0 { // not stale
					ip4s = append(ip4s, v4only(ans.secondaryips)...)
					targets = append(targets, ans.domain...)
				} else {
					staleips = append(staleips, ans.secondaryips...)
				}
				// all ans{} have all secondaryips; pick the first one
				break
			} // continue
		}
		for i := 0; i < 2; i++ { // aaaa = 0, https/svcb = 1+
			k6 := partkey6 + strconv.Itoa(i)
			if ans, ok := t.alg[k6]; ok {
				if time.Until(ans.ttl) > 0 { // not stale
					ip6s = append(ip6s, v6only(ans.secondaryips)...)
					targets = append(targets, ans.domain...)
				} else {
					staleips = append(staleips, ans.secondaryips...)
				}
				// all ans{} have all secondaryips; pick the first one
				break
			} // continue
		}
		log.V("alg: resolv: %s -> secondary ip4 %d, ip6 %d; stale %v", domain, len(ip4s), len(ip6s), staleips)
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

func synthesizeOrQuery(pre []*netip.Addr, tr Transport, msg *dns.Msg, network string, smm *x.DNSSummary, fixed bool) (*dns.Msg, error) {
	// synthesize a response with the given ips
	if len(pre) == 0 {
		return Req(tr, network, msg, smm)
	}
	if msg == nil || !xdns.HasAnyQuestion(msg) {
		return nil, errNoQuestion
	}
	qname := xdns.QName(msg)
	qtyp := uint16(qtype(msg))
	is4 := xdns.IsAQType(qtyp)
	is6 := !is4 && xdns.IsAAAAQType(qtyp)
	isHTTPS := (!is4 && !is6) && xdns.IsHTTPSQType(qtyp)
	isSVCB := (!is4 && !is6) && xdns.IsSVCBQType(qtyp)
	if is4 || is6 {
		preset := unptr(pre)
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

		log.D("alg: synthesize: q(4? %t / 6? %t), fixed? %t, rdata(%s)",
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
		ttl := int(xdns.AnsTTL)
		ip4s, ip6s := splitIPFamilies(pre)
		if len(ip4s) > 0 {
			ok4 = xdns.SubstSVCBRecordIPs( /*out*/ ans, dns.SVCB_IPV4HINT, ip4s, ttl)
		}
		if len(ip6s) > 0 {
			ok6 = xdns.SubstSVCBRecordIPs( /*out*/ ans, dns.SVCB_IPV6HINT, ip6s, ttl)
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

func splitIPFamilies(ips []*netip.Addr) (ip4s, ip6s []*netip.Addr) {
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		*ip = ip.Unmap()
		if ip.Is4() {
			ip4s = append(ip4s, ip)
		} else if ip.Is6() {
			ip6s = append(ip6s, ip)
		}
	}
	return
}

func v4only(ips []*netip.Addr) []*netip.Addr {
	return filterLeft(ips, func(ip *netip.Addr) (ok bool) {
		if ip != nil {
			ok = ip.Is4()
		}
		return
	})
}

func v6only(ips []*netip.Addr) []*netip.Addr {
	return filterLeft(ips, func(ip *netip.Addr) (ok bool) {
		if ip != nil {
			ok = ip.Is6()
		}
		return
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

// unptr removes pointer from a slice of pointers of type T
func unptr[t any](p []*t) (v []t) {
	for _, x := range p {
		v = append(v, *x)
	}
	return
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

// go.dev/play/p/WJXpAa-nmep
func removeDups[T comparable](a ...[]T) (out []T) {
	acc := make(map[T]struct{}, 0)
	out = make([]T, 0)
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

// go.dev/play/p/zI_9nYhEVJY
func removeDups2[T comparable](all ...[]*T) (out []*T) {
	acc := make(map[T]struct{}, 0)
	out = make([]*T, 0)
	for _, list := range all {
		for _, e := range list {
			if e == nil {
				continue
			}
			if _, ok := acc[*e]; ok {
				continue
			}
			out = append(out, e)
			acc[*e] = struct{}{}
		}
	}
	return
}
