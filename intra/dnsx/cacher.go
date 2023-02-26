// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

import (
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

// ideally set by clients via dnsx.cache-opts
const (
	// time to live for a cached response
	defttl = 2 * time.Hour
	// max size of the response cache
	defsize = 10000
	// min duration between scrubs
	scrubgap = 1 * time.Minute
	// how many entries to scrub at a time
	maxscrubs = defsize / 10
	// prefix for cached transport addresses
	addrprefix = "cached."
)

var (
	errCacheResponseEmpty = errors.New("empty cache response")
)

type cres struct {
	ans   *dns.Msg
	s     *Summary
	ttl   time.Time
	bumps int
}

// TODO: Keep a context here so that queries can be canceled.
type ctransport struct {
	sync.RWMutex
	Transport
	cache     map[string]*cres // query -> response
	scrubtime time.Time
	ipport    string
	status    int
	ttl       time.Duration // how long to cache the valid dns response
	bumpttl   time.Duration // how much to bump ttl by on each read
	bumps     int           // max bumps before we stop bumping a response
	size      int           // max size of the cache
}

func NewDefaultCachingTransport(t Transport) (ct Transport) {
	return NewCachingTransport(t, defttl)
}

func NewCachingTransport(t Transport, ttl time.Duration) Transport {
	if t == nil {
		return nil
	}
	// is type casting is a better way to do this?
	if strings.HasPrefix(t.GetAddr(), addrprefix) {
		log.Infof("caching(%s) no-op: %s", t.ID(), t.GetAddr())
		return t
	}
	if strings.HasPrefix(t.GetAddr(), algprefix) {
		log.Warnf("caching(%s) no-op for alg: %s", t.ID(), t.GetAddr())
		return t
	}
	ct := &ctransport{
		Transport: t,
		cache:     make(map[string]*cres),
		ipport:    "[fdaa:cac::ed:3]:53",
		status:    Start,
		ttl:       ttl,
		bumpttl:   ttl / 10,
		bumps:     10,
		size:      defsize,
	}
	log.Infof("caching(%s) setup: %s; opts: %s", ct.ID(), ct.GetAddr(), ct.str())
	return ct
}

func (t *ctransport) str() string {
	return "ttl=" + t.ttl.String() + ";bumps=" + strconv.Itoa(t.bumps) + ";size=" + strconv.Itoa(t.size)
}

func (*ctransport) ckey(q *dns.Msg) string {
	if q == nil {
		return ""
	}
	qtyp := strconv.Itoa(int(xdns.QType(q)))
	return xdns.QName(q) + ":" + qtyp
}

func (t *ctransport) scrub() {
	t.Lock()
	defer t.Unlock()

	now := time.Now()
	if now.Sub(t.scrubtime) < scrubgap {
		return
	}

	t.scrubtime = now
	i := 0
	for k, v := range t.cache {
		if time.Since(v.ttl) > 0 {
			delete(t.cache, k)
		}
		i++
		if i > maxscrubs {
			break
		}
	}
}

func (t *ctransport) fresh(msg *dns.Msg) (v *cres, ok bool) {
	key := t.ckey(msg)
	if len(key) <= 0 {
		return
	}

	t.RLock()
	defer t.RUnlock()

	if v, ok = t.cache[key]; !ok {
		return
	}

	return v, time.Since(v.ttl) <= 0
}

func (t *ctransport) put(q *dns.Msg, response []byte, s *Summary) (ok bool) {
	key := t.ckey(q)

	if len(key) <= 0 || len(response) <= 0 {
		return false
	}

	ans := xdns.AsMsg(response)
	// only cache successful responses
	if !xdns.HasRcodeSuccess(ans) || xdns.HasTCFlag(response) {
		return false
	}

	t.Lock()
	defer t.Unlock()

	// scrub the cache if it's getting too big
	if len(t.cache) > t.size*75/100 {
		go t.scrub()
	}
	if len(t.cache) > t.size {
		return false
	}

	ansttl := time.Duration(xdns.RTtl(ans)) * time.Second
	if ansttl < t.ttl {
		ansttl = t.ttl
	}
	t.cache[key] = &cres{
		ans:   ans,
		s:     s,
		ttl:   time.Now().Add(ansttl),
		bumps: 0,
	}

	return true
}

func (t *ctransport) touch(q *dns.Msg, v *cres) (r []byte, s *Summary, err error) {
	t.Lock()
	defer t.Unlock()

	if v.bumps < t.bumps {
		v.ttl = time.Now().Add(t.bumpttl)
		v.bumps = v.bumps + 1
	}
	a := v.ans

	if a != nil {
		a.Id = q.Id
		s = v.s
		r, err = a.Pack()
	} else {
		err = errCacheResponseEmpty
	}
	return
}

func (t *ctransport) ID() string {
	// must always return underlying transport's ID; alg relies on this
	return t.Transport.ID()
}

func (t *ctransport) Type() string {
	return t.Transport.Type()
}

func (t *ctransport) Query(network string, q []byte, summary *Summary) ([]byte, error) {
	var response []byte
	var s *Summary
	var err error

	msg := xdns.AsMsg(q)

	if v, ok := t.fresh(msg); !ok {
		response, err = t.Transport.Query(network, q, summary)
		if err == nil {
			t.put(msg, response, summary)
		}
	} else {
		response, s, err = t.touch(msg, v)
	}

	if err != nil {
		t.status = BadResponse
	} else {
		t.status = Complete
	}
	summary.Status = t.Status()

	if s != nil { // nil when response is not from cache
		summary.Latency = 0 // instantaneous
		summary.RData = s.RData
		summary.RCode = s.RCode
		summary.RTtl = s.RTtl
		summary.Blocklists = s.Blocklists
		summary.Server = t.GetAddr()
	}

	return response, err
}

func (t *ctransport) GetAddr() string {
	return addrprefix + t.Transport.GetAddr()
}

func (t *ctransport) Status() int {
	return t.status
}
