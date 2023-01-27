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
	"strings"
	"sync"
	"time"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

const (
	timeout = 10 * time.Second
	ttl     = 120 // 2m
	key4    = ":a"
	key6    = ":aaaa"
)

var (
	errNotAvailableAlg   = errors.New("no valid alg ips")
	errCannotRegisterAlg = errors.New("cannot register alg ip")
)

type Gateway interface {
	// given an alg ip, retrieve its actual ips as csv, if any
	X(algip []byte) (realipcsv string)
	// given an alg ip, retrieve its dns names as csv, if any
	PTR(algip []byte) (domaincsv string)
	// set Transport as the underlying upstream DNS for alg queries
	WithTransport(Transport) bool
	// clear obj state
	Stop()
}

type ans struct {
	algip  *netip.Addr   // generated answer
	realip []*netip.Addr // all ip answers
	domain []string      // all domain names in an answer (incl qname)
	qname  string        // the query domain name
	ttl    time.Time
}

// TODO: Keep a context here so that queries can be canceled.
type dnsgateway struct {
	sync.RWMutex // locks alg, nat, octets, hexes
	Transport
	Gateway
	alg    map[string]*ans     // domain+type -> ans
	nat    map[netip.Addr]*ans // algip -> ans
	octets []uint8             // ip4 octets, 100.x.y.z
	hexes  []uint16            // ip6 hex, 64:ff9b:1:da19:0100.x.y.z
}

// NewDNSGateway returns a DNS ALG, ready for use.
func NewDNSGateway(inner Transport) (t *dnsgateway) {
	alg := make(map[string]*ans)
	nat := make(map[netip.Addr]*ans)

	t = &dnsgateway{
		Transport: inner, // may be overriden, see: WithTransport
		alg:       alg,
		nat:       nat,
		octets:    []uint8{100, 0, 0, 1},
		hexes:     []uint16{0x64, 0xff9b, 0x1, 0xda19, 0x100, 0x0, 0x0, 0x0},
	}
	log.Infof("alg(%s) setup: %s/%s", inner.ID(), inner.GetAddr(), inner.Type())
	return
}

func (t *dnsgateway) Query(network string, q []byte, summary *Summary) (r []byte, err error) {

	r, err = t.Transport.Query(network, q, summary)
	if err != nil {
		return
	}

	// override relevant values in summary
	summary.ID = t.ID()
	summary.Type = t.Type()

	ansin := &dns.Msg{}
	err = ansin.Unpack(r)
	if err != nil {
		return nil, err
	}

	qname, _ := xdns.NormalizeQName(xdns.QName(ansin))
	// TODO: Handle SVCB/HTTPS records
	hasq := xdns.HasAQuadAQuestion(ansin)
	hasans := xdns.HasAnyAnswer(ansin)
	rgood := xdns.HasRcodeSuccess(ansin)
	ans0000 := xdns.AQuadAUnspecified(ansin)
	if !hasans || !hasq || !rgood || ans0000 {
		log.Debugf("alg: skip; query(n:%s / a:%d) hasq(%t) hasans(%t) rgood(%t), ans0000(%t)", qname, len(ansin.Answer), hasq, hasans, rgood, ans0000)
		return
	}

	var ipok bool
	a6 := xdns.AAAAAnswer(ansin)
	a4 := xdns.AAnswer(ansin)
	targets := xdns.Targets(ansin)
	rr := make([]dns.RR, 0)
	realip := make([]*netip.Addr, 0)
	var algip *netip.Addr

	t.Lock()
	defer t.Unlock()

	if len(a6) > 0 {
		realip = append(realip, a6...)
		algip, ipok = t.take6Locked(qname)
		if !ipok {
			return r, errNoAlg
		}
		// get fully qualified query-name (str qname is normalized)
		nn := xdns.QName(ansin)
		rr = append(rr, xdns.MakeAAAARecord(nn, algip.String(), ttl))
	} else if len(a4) > 0 {
		realip = append(realip, a4...)
		algip, ipok = t.take4Locked(qname)
		if !ipok {
			return r, errNoAlg
		}
		// get fully qualified query-name (str qname is normalized)
		nn := xdns.QName(ansin)
		rr = append(rr, xdns.MakeARecord(nn, algip.String(), ttl))
	} else {
		// TODO: Handle SVCB/HTTPS records
	}

	if len(rr) <= 0 {
		// may be there were no A or AAAA records
		log.Debugf("alg: no translations done; a6(%d)/a4(%d)", len(a6), len(a4))
		return
	}

	x := &ans{
		algip:  algip,
		realip: realip,
		domain: targets,
		qname:  qname,
		// qname->realip valid for next ttl seconds
		ttl: time.Now().Add(ttl * time.Second),
	}
	ansout := xdns.EmptyResponseFromMessage(ansin)
	ansout.Answer = append(ansout.Answer, rr...)
	if rout, err := ansout.Pack(); err == nil {
		if t.registerLocked(qname, x) {
			return rout, nil
		} else {
			return rout, errCannotRegister
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
	return t.Transport.Type()
}

func (t *dnsgateway) GetAddr() string {
	return t.Transport.GetAddr()
}

func (t *dnsgateway) registerLocked(q string, x *ans) bool {
	ip := x.algip
	var k string
	if ip.Is4() {
		k = q + key4
	} else if ip.Is6() {
		k = q + key6
	} else {
		return false
	}
	t.alg[k] = x
	t.nat[*ip] = x
	return true
}

func (t *dnsgateway) take4Locked(q string) (*netip.Addr, bool) {
	k := q + key4
	if ans, ok := t.alg[k]; ok {
		ip := ans.algip
		if ip.Is4() {
			return ans.algip, true
		} else {
			// shouldn't happen; if it does, rm erroneous entry
			delete(t.alg, k)
			delete(t.nat, *ip)
		}
	}

	gen := true
	// 100.x.y.z: 16m+ ip4s
	if z := t.octets[3]; z < 253 {
		t.octets[3] += 1 // z
	} else if y := t.octets[2]; y < 253 {
		t.octets[2] += 1 // y
		t.octets[3] = 1  // z
	} else if x := t.octets[1]; x < 253 {
		t.octets[1] += 1 // x
		t.octets[2] = 0  // y
		t.octets[3] = 1  // z
	} else {
		gen = false
	}
	if gen {
		// 100.x.y.z: big endian is network-order, which netip expects
		b4 := [4]byte{t.octets[0], t.octets[1], t.octets[2], t.octets[3]}
		genip := netip.AddrFrom4(b4)
		return &genip, genip.IsValid()
	} else {
		log.Warnf("alg: no more IP4s (%v)", t.octets)
	}
	return nil, false
}

func (t *dnsgateway) take6Locked(q string) (*netip.Addr, bool) {
	k := q + key6
	if ans, ok := t.alg[k]; ok {
		ip := ans.algip
		if ip.Is6() {
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
	log.Infof("alg: NewTransport %s / %s", inner.GetAddr(), inner.Type())
	t.Transport = inner
	return true
}

func (t *dnsgateway) Stop() {
	t.Lock()
	defer t.Unlock()
	t.alg = make(map[string]*ans)
	t.nat = make(map[netip.Addr]*ans)
	t.octets = []uint8{100, 0, 0, 1}
	t.hexes = []uint16{0x64, 0xff9b, 0x1, 0xda19, 0x100, 0x0, 0x0, 0x0}
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

// locked
func (t *dnsgateway) x(algip *netip.Addr) (realip []*netip.Addr) {
	if ans, ok := t.nat[*algip]; ok {
		return ans.realip
	}
	return nil
}

// locked
func (t *dnsgateway) ptr(algip *netip.Addr) (domains []string) {
	if ans, ok := t.nat[*algip]; ok {
		return ans.domain
	}
	return nil
}

func isAlgErr(err error) bool {
	return (err == errCannotRegisterAlg || err == errNotAvailableAlg)
}
