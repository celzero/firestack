// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

import (
	"encoding/binary"
	"errors"
	"hash/fnv"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	x "github.com/celzero/firestack/intra/backend"
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

var (
	// 100.64.x.x
	rfc6598  = []uint8{100, 64, 0, 1}
	rfc8215a = []uint16{0x64, 0xff9b, 0x1, 0xda19, 0x100, 0x0, 0x0, 0x0}

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
	X(algip []byte) (realipcsv string)
	// given an alg or real ip, retrieves assoc dns names as csv, if any
	PTR(algip []byte, force bool) (domaincsv string)
	// given an alg or real ip, retrieve assoc blocklists as csv, if any
	RDNSBL(algip []byte) (blocklistcsv string)
	// translate overwrites ip answers to alg ip answers
	translate(yes bool)
	// Query using t1 as primary transport and t2 as secondary and preset as pre-determined ip answers
	q(t1 Transport, t2 Transport, preset []*netip.Addr, network string, q []byte, s *x.DNSSummary) (r []byte, err error)
	// clear obj state
	stop()
}

type secans struct {
	ips     []*netip.Addr
	summary *x.DNSSummary
}

type ans struct {
	algip        *netip.Addr   // generated answer
	realips      []*netip.Addr // all ip answers
	secondaryips []*netip.Addr // all ip answers from secondary
	domain       []string      // all domain names in an answer (incl qname)
	qname        string        // the query domain name
	blocklists   string        // csv blocklists containing qname per active config at the time
	ttl          time.Time
}

type ansMulti struct {
	algip        []*netip.Addr // generated answers
	realip       []*netip.Addr // all ip answers
	secondaryips []*netip.Addr // all ip answers from secondary
	domain       []string      // all domain names in an answer (incl qname)
	qname        string        // the query domain name
	blocklists   string        // csv blocklists containing qname per active config at the time
	ttl          time.Time
}

// TODO: Keep a context here so that queries can be canceled.
type dnsgateway struct {
	sync.RWMutex                     // locks alg, nat, octets, hexes
	mod          bool                // modify realip to algip
	alg          map[string]*ans     // domain+type -> ans
	nat          map[netip.Addr]*ans // algip -> ans
	ptr          map[netip.Addr]*ans // realip -> ans
	rdns         RdnsResolver        // local and remote rdns blocks
	dns64        NatPt               // dns64/nat64
	octets       []uint8             // ip4 octets, 100.x.y.z
	hexes        []uint16            // ip6 hex, 64:ff9b:1:da19:0100.x.y.z
	chash        bool                // use consistent hashing to generae alg ips
}

var _ Gateway = (*dnsgateway)(nil)

// NewDNSGateway returns a DNS ALG, ready for use.
func NewDNSGateway(outer RdnsResolver, dns64 NatPt) (t *dnsgateway) {
	alg := make(map[string]*ans)
	nat := make(map[netip.Addr]*ans)
	ptr := make(map[netip.Addr]*ans)

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
	log.I("alg: setup done")
	return
}

func (t *dnsgateway) translate(yes bool) {
	log.I("alg: translate? %t", yes)
	t.mod = yes
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

func (t *dnsgateway) querySecondary(t2 Transport, network string, q []byte, out chan<- secans, in <-chan []byte) {
	var r []byte
	var msg *dns.Msg
	var err error
	result := secans{
		ips:     []*netip.Addr{},
		summary: new(x.DNSSummary),
	}

	go func() {
		time.Sleep(timeout)
		out <- result
	}()
	defer func() {
		// race against the timeout
		out <- result
	}()

	// check if the question is blocked
	if msg = xdns.AsMsg(q); msg == nil {
		return // not a valid dns message
	} else if ok := xdns.HasAQuadAQuestion(msg) || xdns.HasHTTPQuestion(msg) || xdns.HasSVCBQuestion(msg); !ok {
		return // not a dns question we care about
	} else if ans1, blocklists, err2 := t.rdns.blockQ( /*maybe nil*/ t2, nil, msg); err2 == nil {
		// if err !is nil, then the question is blocked
		if ans1 != nil && len(ans1.Answer) > 0 {
			result.ips = append(result.ips, xdns.AAnswer(ans1)...)
			result.ips = append(result.ips, xdns.AAAAAnswer(ans1)...)
		} // noop: for HTTP/SVCB, the answer is always empty
		result.summary.Blocklists = blocklists
		result.summary.Status = Complete
		return
	}

	// no secondary transport; check if there's already an answer to work with
	if t2 == nil {
		ticker := time.NewTicker(timeout)
		select {
		case r = <-in:
			ticker.Stop()
			break
		case <-ticker.C:
			ticker.Stop()
			return
		}
	} else { // query secondary to get answer for q
		if r, err = t2.Query(network, q, result.summary); err != nil {
			log.D("alg: skip; sec transport %s err %v", t2.ID(), err)
			return
		}
	}

	if len(r) == 0 {
		log.W("alg: skip; no primary or sec ans")
		return
	}

	// check if answer r is blocked
	if ans2 := xdns.AsMsg(r); ans2 == nil {
		// not a valid dns answer
		return
	} else if ans3, blocklistnames := t.rdns.blockA( /*may be nil*/ t2, nil, msg, ans2, result.summary.Blocklists); ans3 != nil {
		// if ans3 is not nil, then the ans2/r is blocked
		if len(blocklistnames) > 0 {
			result.summary.Blocklists = blocklistnames
		}
		// a blocked answer (ans3) has A, AAAA, or HTTPS/SVCB records
		// see: xdns.RefusedResponseFromMessage
		if len(ans3.Answer) > 0 {
			result.ips = append(result.ips, xdns.AAnswer(ans3)...)
			result.ips = append(result.ips, xdns.AAAAAnswer(ans3)...)
		} // noop: for HTTPS/SVCB, the answer section is empty
		return
	} else {
		if len(blocklistnames) > 0 {
			result.summary.Blocklists = blocklistnames
		}
		a4 := xdns.AAAAAnswer(ans2)
		a6 := xdns.AAnswer(ans2)
		ip4hints := xdns.IPHints(ans2, dns.SVCB_IPV4HINT)
		ip6hints := xdns.IPHints(ans2, dns.SVCB_IPV6HINT)
		result.ips = append(result.ips, a4...)
		result.ips = append(result.ips, a6...)
		result.ips = append(result.ips, ip4hints...)
		result.ips = append(result.ips, ip6hints...)
		return
	}
}

// Implements Gateway
func (t *dnsgateway) q(t1, t2 Transport, preset []*netip.Addr, network string, q []byte, summary *x.DNSSummary) (r []byte, err error) {
	if t1 == nil {
		return nil, errNoTransportAlg
	}
	usepreset := len(preset) > 0
	// presets override both t1 and t2:
	// discard t2 as with preset we don't care about additional ips and blocklists;
	// t1 is not discarded entirely as it is needed to subst ips in https/svcb responses
	if usepreset {
		t2 = nil
	}
	mod := t.mod // allow alg?
	secch := make(chan secans, 1)
	resch := make(chan []byte, 1)
	innersummary := new(x.DNSSummary)
	// todo: use context?
	// t2 may be nil
	go t.querySecondary(t2, network, q, secch, resch)

	if usepreset {
		r, err = synthesizeOrQuery(preset, t1, q, network, innersummary)
	} else {
		r, err = query(t1, network, q, innersummary)
	}
	resch <- r

	// override relevant values in summary
	fillSummary(innersummary, summary)

	if err != nil {
		log.D("alg: abort; qerr %v", err)
		return
	}

	ansin := &dns.Msg{}
	err = ansin.Unpack(r)
	if err != nil {
		log.D("alg: abort; ans err %v", err)
		return nil, err
	}

	qname, _ := xdns.NormalizeQName(xdns.QName(ansin))

	summary.QName = qname
	summary.QType = qtype(ansin)

	hasaaaaq := xdns.HasAAAAQuestion(ansin)
	hasans := xdns.HasAnyAnswer(ansin)
	if !hasans && hasaaaaq {
		// override original resp with dns64 if needed
		d64 := t.dns64.D64(t1.ID(), r, t1) // d64 is disabled by default
		if len(d64) > xdns.MinDNSPacketSize {
			ans64 := new(dns.Msg)
			_ = ans64.Unpack(d64)

			withDNS64Summary(ans64, summary)
			ansin = ans64
			r = d64
		} // else: d64 is nil on no D64 or error
	} // else: no d64; not AAAA question or AAAA answer already exists

	hasq := hasaaaaq || xdns.HasAQuestion(ansin) || xdns.HasSVCBQuestion(ansin) || xdns.HasHTTPQuestion(ansin)
	hasans = xdns.HasAnyAnswer(ansin) // recheck after d64
	rgood := xdns.HasRcodeSuccess(ansin)
	ans0000 := xdns.AQuadAUnspecified(ansin)
	if !hasq || !hasans || !rgood || ans0000 {
		log.D("alg: skip; query(n:%s / a:%d) hasq(%t) hasans(%t) rgood(%t), ans0000(%t)", qname, len(ansin.Answer), hasq, hasans, rgood, ans0000)
		return // equivalent to return r, nil
	}

	a6 := xdns.AAAAAnswer(ansin)
	a4 := xdns.AAnswer(ansin)
	ip4hints := xdns.IPHints(ansin, dns.SVCB_IPV4HINT)
	ip6hints := xdns.IPHints(ansin, dns.SVCB_IPV6HINT)
	// TODO: generate one alg ip per target, synth one rec per target
	targets := xdns.Targets(ansin)
	realip := make([]*netip.Addr, 0)
	algips := make([]*netip.Addr, 0)
	// fetch secondary ips before lock
	secres := <-secch

	// inform kt of secondary blocklists, if any
	summary.Blocklists = secres.summary.Blocklists

	defer func() {
		if isAlgErr(err) && !mod {
			log.D("alg: no mod; supress err %v", err)
			// ignore alg errors if no modification is desired
			err = nil
		}
	}()

	t.Lock()
	defer t.Unlock()

	algip4hints := []*netip.Addr{}
	algip6hints := []*netip.Addr{}
	algip4s := []*netip.Addr{}
	algip6s := []*netip.Addr{}
	for i, ip4 := range ip4hints {
		realip = append(realip, ip4)
		// 0th algip is reserved for A records
		algip, ipok := t.take4Locked(qname, i+1)
		if !ipok {
			return r, errNotAvailableAlg
		}
		algip4hints = append(algip4hints, algip)
	}
	for i, ip6 := range ip6hints {
		realip = append(realip, ip6)
		// 0th algip is reserved for AAAA records
		algip, ipok := t.take6Locked(qname, i+1)
		if !ipok {
			return r, errNotAvailableAlg
		}
		algip6hints = append(algip6hints, algip)
	}
	if len(a6) > 0 {
		realip = append(realip, a6...)
		// choose the first alg ip6; may've been generated by ip6hints
		algip, ipok := t.take6Locked(qname, 0)
		if !ipok {
			return r, errNotAvailableAlg
		}
		algip6s = append(algip6s, algip)
	}
	if len(a4) > 0 {
		realip = append(realip, a4...)
		// choose the first alg ip4; may've been generated by ip4hints
		algip, ipok := t.take4Locked(qname, 0)
		if !ipok {
			return r, errNotAvailableAlg
		}
		algip4s = append(algip4s, algip)
	}

	substok4 := false
	substok6 := false
	// substituions needn't happen when no alg ips to begin with
	mustsubst := false
	ansout := ansin
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

	log.D("alg: %s a6(a %d / h %d / s %t) : a4(a %d / h %d / s %t)", qname, len(a6), len(ip6hints), substok6, len(a4), len(ip4hints), substok4)
	if !substok4 && !substok6 {
		if mustsubst {
			err = errCannotSubstAlg
		} else {
			err = nil
		}
		log.D("alg: skip; err(%v); ips subst %s", err, qname)
		return r, err // nil if no alg ips
	}

	algips = append(algips, algip4s...)
	algips = append(algips, algip6s...)
	algips = append(algips, algip4hints...)
	algips = append(algips, algip6hints...)
	x := &ansMulti{
		algip:  algips,
		realip: realip,
		// may be empty on timeout errors, or
		// or same as realips if t2 is nil
		secondaryips: secres.ips,
		domain:       targets, // may be nil
		qname:        qname,
		blocklists:   secres.summary.Blocklists,
		// qname->realip valid for next ttl seconds
		ttl: time.Now().Add(ttl2m),
	}

	log.D("alg: ok; domains %s ips %s => subst %s; mod? %t", targets, realip, algips, mod)

	if rout, err := ansout.Pack(); err == nil {
		if t.registerMultiLocked(qname, x) {
			// if mod is set, send modified answer
			if mod {
				withAlgSummaryIfNeeded(algips, summary)
				return rout, nil
			} else {
				return r, nil
			}
		} else {
			return r, errCannotRegisterAlg
		}
	} else {
		log.W("alg: unpacking err(%v)", err)
		return r, err
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
		algip:        am.algip[i],
		realips:      am.realip,
		secondaryips: am.secondaryips,
		domain:       am.domain,
		qname:        am.qname,
		blocklists:   am.blocklists,
		ttl:          am.ttl,
	}
}

func (t *dnsgateway) registerMultiLocked(q string, am *ansMulti) bool {
	for i := range am.algip {
		if ok := t.registerNatLocked(q, i, am.ansViewLocked(i)); !ok {
			return false
		}
	}
	for i := range am.realip {
		// index is always 0 since algip is inconsequential for ptr
		if ok := t.registerPtrLocked(i, am.ansViewLocked(0)); !ok {
			return false
		}
	}
	return true
}

// register mapping from qname -> algip+realip (alg) and algip -> qname+realip (nat)
func (t *dnsgateway) registerNatLocked(q string, idx int, x *ans) bool {
	ip := x.algip
	var k string
	if ip.Is4() {
		k = q + key4 + strconv.Itoa(idx)
	} else if ip.Is6() {
		k = q + key6 + strconv.Itoa(idx)
	} else {
		return false
	}
	t.alg[k] = x
	t.nat[*ip] = x
	return true
}

// register mapping from realip -> algip+qname (ptr)
func (t *dnsgateway) registerPtrLocked(idx int, x *ans) bool {
	ip := x.realips[idx]
	t.ptr[*ip] = x // x contains qname and the algip
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

func (t *dnsgateway) X(algip []byte) (ips string) {
	t.RLock()
	defer t.RUnlock()

	if fip, ok := netip.AddrFromSlice(algip); ok {
		rip := t.xLocked(fip, !t.mod)
		if len(rip) > 0 {
			var s []string
			for _, r := range rip {
				s = append(s, r.String())
			}
			ips = strings.Join(s, ",")
		} // else: algip isn't really an alg ip, nothing to do
	} else {
		log.W("alg: invalid algip(%s)", algip)
	}

	return ips
}

func (t *dnsgateway) PTR(algip []byte, force bool) (domains string) {
	t.RLock()
	defer t.RUnlock()

	if fip, ok := netip.AddrFromSlice(algip); ok {
		d := t.ptrLocked(fip, (!t.mod || force))
		if len(d) > 0 {
			domains = strings.Join(d, ",")
		} // else: algip isn't really an alg ip, nothing to do
	} else {
		log.W("alg: invalid algip(%s)", algip)
	}
	return domains
}

func (t *dnsgateway) RDNSBL(algip []byte) (blocklists string) {
	t.RLock()
	defer t.RUnlock()

	if fip, ok := netip.AddrFromSlice(algip); ok {
		blocklists = t.rdnsblLocked(fip, !t.mod)
	} else {
		log.W("alg: invalid algip(%s)", algip)
	}
	return blocklists
}

func (t *dnsgateway) xLocked(algip netip.Addr, useptr bool) []*netip.Addr {
	var realips []*netip.Addr
	// alg ips are always unmappped; see take4Locked
	unmapped := algip.Unmap()
	if ans, ok := t.nat[unmapped]; ok {
		realips = append(ans.realips, ans.secondaryips...)
	} else if ans, ok := t.ptr[unmapped]; useptr && ok {
		// translate from realip only if not in mod mode
		realips = append(ans.realips, ans.secondaryips...)
	}
	unnated := t.maybeUndoNat64(realips) // modifies / NATs realip in-place
	log.D("alg: dns64: algip(%v) -> realips(%v) -> unnated(%v)", unmapped, realips, unnated)
	if len(unnated) > 0 {
		return unnated
	}
	return realips
}

func (t *dnsgateway) maybeUndoNat64(realips []*netip.Addr) (unnat []*netip.Addr) {
	for _, nip := range realips {
		if !nip.Unmap().Is6() || nip.IsUnspecified() {
			continue
		}
		// TODO: use the actual ID of the transport that did nat64
		// TODO: check if the active network has ipv4 connectivity
		ipx4 := net.IP(t.dns64.X64(Local464Resolver, nip.Unmap().AsSlice())) // ipx4 may be nil
		if len(ipx4) < net.IPv4len {                                         // no nat?
			log.D("alg: dns64: maybeUndoNat64: No local nat64 to ip4(%v) for ip6(%v)", ipx4, nip)
			continue
		}
		log.D("alg: dns64: maybeUndoNat64: nat64 to ip4(%v) from ip6(%v)", ipx4, nip)
		if nipx4, ok := netip.AddrFromSlice(ipx4); ok {
			unmapped4 := nipx4.Unmap()
			unnat = append(unnat, &unmapped4)
		}
	}
	return
}

func (t *dnsgateway) ptrLocked(algip netip.Addr, useptr bool) (domains []string) {
	// alg ips are always unmappped; see take4Locked
	unmapped := algip.Unmap()
	if ans, ok := t.nat[unmapped]; ok {
		domains = ans.domain
	} else if ans, ok := t.ptr[unmapped]; useptr && ok {
		// translate from realip only if not in mod mode
		domains = ans.domain
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
	h.Write([]byte(s))
	v64 := h.Sum64()
	return (uint32(v64>>22) ^ uint32(v64)) & 0x3FFFFF // 22 bits
}

// xor fold fnv to 48 bits: www.isthe.com/chongo/tech/comp/fnv
func hash48(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	v64 := h.Sum64()
	return (uint64(v64>>48) ^ uint64(v64)) & 0xFFFFFFFFFFFF // 48 bits
}

func synthesizeOrQuery(pre []*netip.Addr, tr Transport, q []byte, network string, smm *x.DNSSummary) ([]byte, error) {
	// synthesize a response with the given ips
	if len(pre) == 0 {
		return query(tr, network, q, smm)
	}
	msg := xdns.AsMsg(q)
	if msg == nil {
		return nil, errNoQuestion
	}
	qname := xdns.QName(msg)
	qtyp := uint16(qtype(msg))
	is4 := xdns.IsAQType(qtyp)
	is6 := !is4 && xdns.IsAAAAQType(qtyp)
	isHTTPS := (!is4 && !is6) && xdns.IsHTTPSQType(qtyp)
	isSVCB := (!is4 && !is6) && xdns.IsSVCBQType(qtyp)
	if is4 || is6 {
		// if no ips are of the same family as the question xdns.AQuadAForQuery returns error
		ans, err := xdns.AQuadAForQuery(msg, unptr(pre)...)
		if err != nil { // errors on invalid msg, question, or mismatched ips
			return query(tr, network, q, smm)
		}
		withPresetSummary(smm)
		smm.RCode = xdns.Rcode(ans)
		smm.RData = xdns.GetInterestingRData(ans)
		smm.RTtl = xdns.RTtl(ans)

		log.D("alg: synthesize: q(4? %t / 6? %t) rdata(%s)", qname, is4, is6, smm.RData)
		return ans.Pack()
	} else if isHTTPS || isSVCB {
		r, err := tr.Query(network, q, smm)
		if err != nil {
			return r, err
		}
		ans := xdns.AsMsg(r)
		if ans == nil {
			return r, errNoAnswer
		}
		var ok4, ok6 bool
		ttl := int(xdns.AnsTTL)
		ip4s, ip6s := splitIPFamilies(pre)
		if len(ip4s) > 0 {
			ok4 = xdns.SubstSVCBRecordIPs( /*out*/ ans, dns.SVCB_IPV4HINT, ip4s, ttl)
		}
		if len(ip6s) > 0 {
			ok6 = xdns.SubstSVCBRecordIPs( /*out*/ ans, dns.SVCB_IPV6HINT, ip6s, algttl)
		}

		withPresetSummary(smm)
		smm.RCode = xdns.Rcode(ans)
		smm.RData = xdns.GetInterestingRData(ans)
		smm.RTtl = xdns.RTtl(ans)

		log.D("alg: synthesize: q(HTTPS? %t); subst4(%t), subst6(%t); rdata(%s)", q, isHTTPS, ok4, ok6, smm.RData)

		return ans.Pack()
	} else {
		return query(tr, network, q, smm)
	}
}

func query(t Transport, network string, q []byte, smm *x.DNSSummary) ([]byte, error) {
	return t.Query(network, q, smm)
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

// unptr removes pointer from a slice of pointers of type T
func unptr[t any](p []*t) (v []t) {
	for _, x := range p {
		v = append(v, *x)
	}
	return
}

func withPresetSummary(smm *x.DNSSummary) {
	// override id and type from whatever was set before
	smm.ID = Preset
	smm.Type = Preset
	// other unset fields
	smm.Latency = 0
	smm.Status = Complete
	smm.Server = Preset
	smm.Blocklists = ""  // blocklists are not honoured
	smm.RelayServer = "" // no relay is used
}
