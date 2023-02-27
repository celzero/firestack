// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

const (
	algprefix   = "alg."
	timeout     = 10 * time.Second
	ttl         = 120 // 2m ttl for alg/nat ip
	algttl      = 15  // 15s ttl for alg dns
	key4        = ":a"
	key6        = ":aaaa"
	NoTransport = "NoTransport"
	maxiter     = 1000 // max number alg/nat evict iterations
)

var (
	errNoTransportAlg    = errors.New("no alg transport")
	errNotAvailableAlg   = errors.New("no valid alg ips")
	errCannotRegisterAlg = errors.New("cannot register alg ip")
	errCannotSubstAlg    = errors.New("cannot substitute alg ip")
)

func isAlgErr(err error) bool {
	return (err == errCannotRegisterAlg || err == errNotAvailableAlg || err == errCannotSubstAlg)
}

type Gateway interface {
	// given an alg ip, retrieve its actual ips as csv, if any
	X(algip []byte) (realipcsv string)
	// given an alg ip, retrieve its dns names as csv, if any
	PTR(algip []byte) (domaincsv string)
	// given an alg ip, retrieve its blocklists as csv, if any
	RDNSBL(algip []byte) (blocklistcsv string)
	// set Transport as the underlying upstream DNS for alg queries
	WithTransport(Transport) bool
	// unset Transport as the underlying upstream DNS for alg queries
	WithoutTransport(Transport) bool
	// clear obj state
	Stop()
}

type secans struct {
	ips     []*netip.Addr
	summary *Summary
}

type ans struct {
	algip        *netip.Addr   // generated answer
	realip       []*netip.Addr // all ip answers
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
	sync.RWMutex // locks alg, nat, octets, hexes
	Transport
	Gateway
	secondary Transport
	alg       map[string]*ans     // domain+type -> ans
	nat       map[netip.Addr]*ans // algip -> ans
	rdns      RdnsResolver        // local and remote rdns blocks
	octets    []uint8             // ip4 octets, 100.x.y.z
	hexes     []uint16            // ip6 hex, 64:ff9b:1:da19:0100.x.y.z
}

// NewDNSGateway returns a DNS ALG, ready for use.
func NewDNSGateway(inner Transport, outer RdnsResolver) (t *dnsgateway) {
	alg := make(map[string]*ans)
	nat := make(map[netip.Addr]*ans)

	t = &dnsgateway{
		alg:    alg,
		nat:    nat,
		rdns:   outer,
		octets: []uint8{100, 64, 0, 1},
		hexes:  []uint16{0x64, 0xff9b, 0x1, 0xda19, 0x100, 0x0, 0x0, 0x0},
	}
	t.WithTransport(inner)
	log.Infof("alg(%s) setup: %s/%s", inner.ID(), inner.GetAddr(), inner.Type())
	return
}

func (t *dnsgateway) Stop() {
	t.Lock()
	defer t.Unlock()

	t.alg = make(map[string]*ans)
	t.nat = make(map[netip.Addr]*ans)
	t.octets = []uint8{100, 64, 0, 1}
	t.hexes = []uint16{0x64, 0xff9b, 0x1, 0xda19, 0x100, 0x0, 0x0, 0x0}
}

func (t *dnsgateway) querySecondary(network string, q []byte, out chan<- secans, in <-chan []byte, timeout time.Duration) {
	var r []byte
	var msg *dns.Msg
	var err error
	result := secans{
		ips:     []*netip.Addr{},
		summary: &Summary{},
	}
	go func() {
		time.Sleep(timeout)
		out <- result
	}()
	defer func() {
		out <- result
	}()

	if t.secondary == nil {
		// no secondary transport; check if there's already an answer to work with
		ticker := time.NewTicker(timeout)
		select {
		case r = <-in:
			ticker.Stop()
		case <-ticker.C:
			return
		}
	}

	// check if the question is blocked
	if msg = xdns.AsMsg(q); msg == nil {
		return // not a valid dns message
	} else if ok := xdns.HasAQuadAQuestion(msg) || xdns.HasSVCBQuestion(msg); !ok {
		return // not a dns question we care about
	} else if ans1, blocklists, err := t.rdns.blockQ(t.secondary, msg); err == nil {
		// if err !is nil, then the question is blocked
		result.ips = append(result.ips, xdns.AAnswer(ans1)...)
		result.ips = append(result.ips, xdns.AAAAAnswer(ans1)...)
		result.summary.Blocklists = blocklists
		result.summary.Status = Complete
		return
	}

	// check if the query must be upstreamed to get answer r
	if r == nil {
		if r, err = t.secondary.Query(network, q, result.summary); err != nil {
			log.Debugf("alg: skip; sec transport %s err %v", t.secondary.ID(), err)
			return
		}
	}

	// check if answer r is blocked
	if ans2 := xdns.AsMsg(r); ans2 == nil {
		// not a valid dns answer
		return
	} else if ans3, blocklistnames := t.rdns.blockA(t.secondary, msg, ans2, result.summary.Blocklists); ans3 != nil {
		// if ans3 is not nil, then the answer is blocked
		if len(blocklistnames) > 0 {
			result.summary.Blocklists = blocklistnames
		}
		result.ips = append(result.ips, xdns.AAnswer(ans3)...)
		result.ips = append(result.ips, xdns.AAAAAnswer(ans3)...)
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

func (t *dnsgateway) Query(network string, q []byte, summary *Summary) (r []byte, err error) {
	if t.Transport == nil {
		return nil, errNoTransportAlg
	}

	secch := make(chan secans, 1)
	resch := make(chan []byte, 1)
	// todo: use context?
	go t.querySecondary(network, q, secch, resch, timeout)

	r, err = t.Transport.Query(network, q, summary)
	resch <- r
	if err != nil {
		log.Debugf("alg: abort; qerr %v", err)
		return
	}

	// override relevant values in summary
	summary.ID = t.ID()
	summary.Type = t.Type()

	ansin := &dns.Msg{}
	err = ansin.Unpack(r)
	if err != nil {
		log.Debugf("alg: abort; ans err %v", err)
		return nil, err
	}

	qname, _ := xdns.NormalizeQName(xdns.QName(ansin))
	hasq := xdns.HasAQuadAQuestion(ansin) || xdns.HasSVCBQuestion(ansin)
	hasans := xdns.HasAnyAnswer(ansin)
	rgood := xdns.HasRcodeSuccess(ansin)
	ans0000 := xdns.AQuadAUnspecified(ansin)
	if !hasans || !hasq || !rgood || ans0000 {
		log.Debugf("alg: skip; query(n:%s / a:%d) hasq(%t) hasans(%t) rgood(%t), ans0000(%t)", qname, len(ansin.Answer), hasq, hasans, rgood, ans0000)
		return
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
	ansout := ansin
	// TODO: substitute ips in additional section
	if len(algip4hints) > 0 {
		substok4 = xdns.SubstSVCBRecordIPs( /*out*/ ansout, dns.SVCB_IPV4HINT, algip4hints, algttl) || substok4
	}
	if len(algip6hints) > 0 {
		substok6 = xdns.SubstSVCBRecordIPs( /*out*/ ansout, dns.SVCB_IPV6HINT, algip6hints, algttl) || substok6
	}
	if len(algip4s) > 0 {
		substok4 = xdns.SubstARecords( /*out*/ ansout, algip4s, algttl) || substok4
	}
	if len(algip6s) > 0 {
		substok6 = xdns.SubstAAAARecords( /*out*/ ansout, algip6s, algttl) || substok6
	}

	log.Debugf("alg: %s a6(a %d / h %d / s %t) : a4(a %d / h %d / s %t)", qname, len(a6), len(ip6hints), substok6, len(a4), len(ip4hints), substok4)
	if !substok4 && !substok6 {
		log.Debugf("alg: skip; err ips subst %s", qname)
		return r, errCannotSubstAlg
	}

	algips = append(algips, algip4s...)
	algips = append(algips, algip6s...)
	algips = append(algips, algip4hints...)
	algips = append(algips, algip6hints...)
	x := &ansMulti{
		algip:        algips,
		realip:       realip,
		secondaryips: secres.ips,
		domain:       targets,
		qname:        qname,
		blocklists:   secres.summary.Blocklists,
		// qname->realip valid for next ttl seconds
		ttl: time.Now().Add(ttl * time.Second),
	}

	log.Debugf("alg: ok; domains %s ips %s => subst %s", targets, realip, algips)

	if rout, err := ansout.Pack(); err == nil {
		if t.registerMultiLocked(qname, x) {
			t.withAlgSummaryIfNeeded(ansout, summary)
			return rout, nil
		} else {
			return r, errCannotRegisterAlg
		}
	} else {
		log.Warnf("alg: unpacking err(%v)", err)
		return r, err
	}
}

func (t *dnsgateway) ID() string {
	return Alg
}

func (t *dnsgateway) Type() string {
	if t.Transport != nil {
		return t.Transport.Type()
	} else if t.secondary != nil {
		return t.secondary.Type()
	} else {
		return NoTransport
	}
}

func (t *dnsgateway) GetAddr() string {
	if t.Transport != nil {
		return algprefix + t.Transport.GetAddr()
	} else if t.secondary != nil {
		return algprefix + t.secondary.GetAddr()
	} else {
		return NoTransport
	}
}

func (t *dnsgateway) withAlgSummaryIfNeeded(algans *dns.Msg, s *Summary) {
	if settings.Debug {
		s.RData = xdns.GetInterestingRData(algans) + "," + s.RData
		s.RTtl = xdns.RTtl(algans)
		s.Server = t.GetAddr()
	}
}

func (am *ansMulti) ansViewLocked(i int) *ans {
	return &ans{
		algip:        am.algip[i],
		realip:       am.realip,
		secondaryips: am.secondaryips,
		domain:       am.domain,
		qname:        am.qname,
		blocklists:   am.blocklists,
		ttl:          am.ttl,
	}
}

func (t *dnsgateway) registerMultiLocked(q string, am *ansMulti) bool {
	for i := range am.algip {
		if ok := t.registerLocked(q, i, am.ansViewLocked(i)); !ok {
			return false
		}
	}
	return true
}

func (t *dnsgateway) registerLocked(q string, idx int, x *ans) bool {
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

func (t *dnsgateway) take4Locked(q string, idx int) (*netip.Addr, bool) {
	k := q + key4 + strconv.Itoa(idx)
	if ans, ok := t.alg[k]; ok {
		ip := ans.algip
		if ip.Is4() {
			ans.ttl = time.Now().Add(ttl * time.Second)
			return ip, true
		} else {
			// shouldn't happen; if it does, rm erroneous entry
			delete(t.alg, k)
			delete(t.nat, *ip)
		}
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
				log.Infof("alg: reuse stale alg %s for %s", kx, k)
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
		log.Warnf("alg: no more IP4s (%v)", t.octets)
	}
	return nil, false
}

func (t *dnsgateway) take6Locked(q string, idx int) (*netip.Addr, bool) {
	k := q + key6 + strconv.Itoa(idx)
	if ans, ok := t.alg[k]; ok {
		ip := ans.algip
		if ip.Is6() {
			ans.ttl = time.Now().Add(ttl * time.Second)
			return ip, true
		} else {
			// shouldn't happen; if it does, rm erroneous entry
			delete(t.alg, k)
			delete(t.nat, *ip)
		}
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
		log.Warnf("alg: no more IP6s (%x)", t.hexes)
	}
	return nil, false
}

// Implements Gateway
func (t *dnsgateway) WithTransport(inner Transport) bool {
	if inner == nil {
		return false
	}
	log.Infof("alg: NewTransport %s / %s", inner.GetAddr(), inner.Type())
	if inner.ID() == Default {
		// default transport is primary
		t.Transport = NewCachingTransport(inner, ttl)
	} else if inner.ID() == Preferred {
		// if preferred transport is a rdns transport, use BlockFree as the primary
		// that's because a rdns transport can be a filtering dns server whereas
		// alg works best with a non-filtering dns server (which BlockFree is)
		for _, dom := range RdnsDomains {
			if strings.Contains(inner.GetAddr(), dom) {
				blkfree := t.rdns.BlockFreeTransport()
				if blkfree == nil {
					log.Warnf("alg: rdns.BlockFree preferred primary missing %s", inner.GetAddr())
					t.Transport = nil
					t.secondary = nil
					return false
				} else {
					log.Infof("alg: primary for preferred rdns %s / sec %s", blkfree.GetAddr(), inner.GetAddr())
					t.Transport = NewCachingTransport(blkfree, ttl)
					t.secondary = NewDefaultCachingTransport(inner)
					return true
				}
			}
		}
		log.Infof("alg: primary preferred for %s / sec nil", inner.GetAddr())
		// use the preferred transport as primary
		t.Transport = NewCachingTransport(inner, ttl)
		// and disable the secondary
		t.secondary = nil
	} else {
		log.Infof("alg: sec set %s / primary %s", inner.GetAddr(), t.GetAddr())
		// any other transport is secondary
		t.secondary = NewDefaultCachingTransport(inner)
	}
	return true
}

// Implements Gateway
func (t *dnsgateway) WithoutTransport(goner Transport) (ok bool) {
	if goner == nil || len(goner.ID()) == 0 {
		return
	}

	// pimary and secondary transports could be the same transport
	if t.Transport != nil && goner.ID() == t.Transport.ID() {
		t.Transport = nil
	}
	if t.secondary != nil && t.secondary.ID() == goner.ID() {
		t.secondary = nil
	}
	log.Infof("alg: %s RemoveTransport %s / %s; Done? %t", goner.GetAddr(), goner.Type(), goner.ID(), ok)
	return ok
}

func (t *dnsgateway) X(algip []byte) (ips string) {
	t.RLock()
	defer t.RUnlock()

	if fip, ok := netip.AddrFromSlice(algip); ok {
		rip := t.x(&fip)
		if len(rip) > 0 {
			var s []string
			for _, r := range rip {
				s = append(s, r.String())
			}
			ips = strings.Join(s, ",")
		} // else: algip isn't really an alg ip, nothing to do
	} else {
		log.Warnf("alg: invalid algip(%s)", algip)
	}

	return ips
}

func (t *dnsgateway) PTR(algip []byte) (domains string) {
	t.RLock()
	defer t.RUnlock()

	if fip, ok := netip.AddrFromSlice(algip); ok {
		d := t.ptr(&fip)
		if len(d) > 0 {
			domains = strings.Join(d, ",")
		} // else: algip isn't really an alg ip, nothing to do
	} else {
		log.Warnf("alg: invalid algip(%s)", algip)
	}
	return domains
}

func (t *dnsgateway) RDNSBL(algip []byte) (blocklists string) {
	t.RLock()
	defer t.RUnlock()

	if fip, ok := netip.AddrFromSlice(algip); ok {
		blocklists = t.rdnsbl(&fip)
	} else {
		log.Warnf("alg: invalid algip(%s)", algip)
	}
	return blocklists
}

// locked
func (t *dnsgateway) x(algip *netip.Addr) (realip []*netip.Addr) {
	// alg ips are always unmappped; see take4Locked
	unmapped := algip.Unmap()
	if ans, ok := t.nat[unmapped]; ok {
		realip = append(ans.realip, ans.secondaryips...)
	}
	return
}

// locked
func (t *dnsgateway) ptr(algip *netip.Addr) (domains []string) {
	// alg ips are always unmappped; see take4Locked
	unmapped := algip.Unmap()
	if ans, ok := t.nat[unmapped]; ok {
		domains = ans.domain
	}
	return
}

// locked
func (t *dnsgateway) rdnsbl(algip *netip.Addr) (bcsv string) {
	// alg ips are always unmappped; see take4Locked
	unmapped := algip.Unmap()
	if ans, ok := t.nat[unmapped]; ok {
		bcsv = ans.blocklists
	}
	return bcsv
}
