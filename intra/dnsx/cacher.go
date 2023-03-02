// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

import (
	"errors"
	"math/rand"
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
	// max bumps before we stop bumping a response
	defbumps = 10
	// max size of the response cache
	defsize = 10000
	// min duration between scrubs
	scrubgap = 5 * time.Minute
	// how many entries to scrub at a time
	maxscrubs = defsize / 4 // 25% of the cache
	// prefix for cached transport addresses
	addrprefix = "cached."
)

var (
	errCacheResponseEmpty = errors.New("empty cache response")
)

type cres struct {
	ans    *dns.Msg
	s      *Summary
	expiry time.Time
	bumps  int
}

// TODO: Keep a context here so that queries can be canceled.
type ctransport struct {
	sync.RWMutex                        // protects the barrier
	Transport                           // the underlying transport
	barrier      map[string]*sync.Mutex // coalesce requests for the same query
	cache        map[string]*cres       // query -> response
	scrubtime    time.Time              // last time cache was scrubbed / purged
	ipport       string                 // a fake ip:port
	status       int                    // status of this transport
	ttl          time.Duration          // how long to cache the valid dns response
	halflife     time.Duration          // how much to increment ttl on each read
	bumps        int                    // max bumps before we stop bumping a response
	size         int                    // max size of the cache
}

func NewDefaultCachingTransport(t Transport) (ct Transport) {
	return NewCachingTransport(t, defttl)
}

func NewCachingTransport(t Transport, ttl time.Duration) Transport {
	if t == nil {
		return nil
	}

	rand.Seed(time.Now().UnixNano())

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
		barrier:   make(map[string]*sync.Mutex),
		cache:     make(map[string]*cres),
		ipport:    "[fdaa:cac::ed:3]:53",
		status:    Start,
		ttl:       ttl,
		halflife:  ttl / 2,
		bumps:     defbumps,
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

	qname, err := xdns.NormalizeQName(xdns.QName(q))
	if len(qname) <= 0 || err != nil {
		return ""
	}
	qtyp := strconv.Itoa(int(xdns.QType(q)))

	return qname + ":" + qtyp
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
		if time.Since(v.expiry) > 0 {
			delete(t.cache, k)
			delete(t.barrier, k)
		}
		i++
		if i > maxscrubs {
			break
		}
	}
}

func (t *ctransport) freshLocked(key string) (v *cres, ok bool) {
	if v, ok = t.cache[key]; !ok {
		return
	}
	r80 := rand.Intn(1000) < 700 // 70% chance of reusing from the cache
	return v, r80 && time.Since(v.expiry) < 0
}

func (t *ctransport) putLocked(key string, response []byte, s *Summary) (ok bool) {
	if len(response) <= 0 {
		return false
	}

	ans := xdns.AsMsg(response)
	// only cache successful responses
	// TODO: implement negative caching
	if !xdns.HasRcodeSuccess(ans) || xdns.HasTCFlag(response) {
		return false
	}

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
	} else {
		// bump up a bit longer than the ttl
		ansttl = ansttl + t.halflife
	}
	exp := time.Now().Add(ansttl)
	t.cache[key] = &cres{
		ans:    ans,
		s:      s,
		expiry: exp,
		bumps:  0,
	}

	return true
}

func (t *ctransport) getLocked(q *dns.Msg, v *cres) (r []byte, s *Summary, err error) {
	if v.bumps < t.bumps {
		v.bumps = v.bumps + 1
		n := time.Duration(v.bumps) * t.halflife
		// if the expiry time is already n duration in the future, don't incr ttl
		if time.Since(v.expiry.Add(-n)) < 0 {
			v.expiry = v.expiry.Add(n)
		}
	}
	a := v.ans

	if a != nil {
		a.Id = q.Id
		// dns 0x20 may mangle the question section, so preserve it
		// github.com/jedisct1/edgedns#correct-support-for-the-dns0x20-extension
		a.Question = q.Question
		s = v.s // copy the summary
		r, err = a.Pack()
	} else {
		err = errCacheResponseEmpty
	}
	return
}

func (t *ctransport) ID() string {
	// must match with how wrapping transports like DcProxy / Gateway rely on the ID
	return CT + t.Transport.ID()
}

func (t *ctransport) Type() string {
	return t.Transport.Type()
}

func (t *ctransport) Query(network string, q []byte, summary *Summary) ([]byte, error) {
	var response []byte
	var s *Summary
	var err error
	var mu *sync.Mutex

	msg := xdns.AsMsg(q)

	start := time.Now()
	if key := t.ckey(msg); len(key) > 0 {
		t.Lock()
		mu = t.barrier[key]
		if mu == nil {
			mu = &sync.Mutex{}
			t.barrier[key] = mu
		}
		t.Unlock()

		mu.Lock()
		if v, ok := t.freshLocked(key); !ok {
			response, err = t.Transport.Query(network, q, summary)
			if err == nil {
				t.putLocked(key, response, summary)
			}
		} else {
			response, s, err = t.getLocked(msg, v)
		}
		mu.Unlock()
	} else {
		err = errMissingQueryName
	}
	elapsed := time.Since(start)

	if err != nil {
		t.status = BadResponse
	} else {
		t.status = Complete
	}
	summary.Status = t.Status()

	if s != nil { // nil when response is not from cache
		summary.Latency = elapsed.Seconds()
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
