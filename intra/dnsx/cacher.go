// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

import (
	"errors"
	"hash/fnv"
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
	// max size per cache bucket
	defsize = 256
	// total cache buckets; can't be more than 256 (uint8 255)
	defbuckets = 128
	// min duration between scrubs
	scrubgap = 5 * time.Minute
	// how many entries to scrub at a time per cache bucket
	maxscrubs = defsize / 4 // 25% of the cache
	// prefix for cached transport addresses
	addrprefix = "cached."
)

var (
	errCacheResponseEmpty = errors.New("empty cache response")
)

type cache struct {
	c         map[string]*cres // query -> response
	mu        *sync.RWMutex    // protects the cache
	ttl       time.Duration    // how long to cache the valid dns response
	halflife  time.Duration    // how much to increment ttl on each read
	bumps     int              // max bumps before we stop bumping a response
	size      int              // max size of the cache
	scrubtime time.Time        // last time cache was scrubbed / purged
}

type cres struct {
	ans    *dns.Msg
	s      *Summary
	expiry time.Time
	bumps  int
}

// TODO: Keep a context here so that queries can be canceled.
type ctransport struct {
	sync.RWMutex               // protects the barrier
	Transport                  // the underlying transport
	store        []*cache      // coalesce requests for the same query
	ipport       string        // a fake ip:port
	status       int           // status of this transport
	ttl          time.Duration // lifetime duration of a cached dns entry
	halflife     time.Duration // increment ttl on each read
	bumps        int           // max bumps in lifetime of a cached response
	size         int           // max size of a cache bucket
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
		log.I("caching(%s) no-op: %s", t.ID(), t.GetAddr())
		return t
	}
	if strings.HasPrefix(t.GetAddr(), algprefix) {
		log.W("caching(%s) no-op for alg: %s", t.ID(), t.GetAddr())
		return t
	}
	ct := &ctransport{
		Transport: t,
		store:     make([]*cache, defbuckets),
		ipport:    "[fdaa:cac::ed:3]:53",
		status:    Start,
		ttl:       ttl,
		halflife:  ttl / 2,
		bumps:     defbumps,
		size:      defsize,
	}
	log.I("caching(%s) setup: %s; opts: %s", ct.ID(), ct.GetAddr(), ct.str())
	return ct
}

func (t *ctransport) str() string {
	return "ttl=" + t.ttl.String() + ";bumps=" + strconv.Itoa(t.bumps) + ";size=" + strconv.Itoa(t.size)
}

func hash(s string) uint8 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return uint8(h.Sum32() % defbuckets)
}

func (*ctransport) ckey(q *dns.Msg) (string, uint8, bool) {
	if q == nil {
		return "", 0, false
	}

	qname, err := xdns.NormalizeQName(xdns.QName(q))
	if len(qname) <= 0 || err != nil {
		return "", 0, false
	}
	qtyp := strconv.Itoa(int(xdns.QType(q)))

	return qname + ":" + qtyp, hash(qname), true
}

func (cb *cache) scrub() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// scrub the cache if it's getting too big
	if len(cb.c) > cb.size*75/100 {
		return
	}

	now := time.Now()
	if now.Sub(cb.scrubtime) < scrubgap {
		return
	}
	cb.scrubtime = now

	i := 0
	for k, v := range cb.c {
		if time.Since(v.expiry) > 0 {
			delete(cb.c, k)
		}
		i++
		if i > maxscrubs {
			break
		}
	}
}

func (cb *cache) fresh(key string) (v *cres, ok bool) {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	if v, ok = cb.c[key]; !ok {
		return
	}

	if v.bumps < cb.bumps {
		v.bumps = v.bumps + 1
		n := time.Duration(v.bumps) * cb.halflife
		// if the expiry time is already n duration in the future, don't incr ttl
		if time.Since(v.expiry.Add(-n)) < 0 {
			v.expiry = v.expiry.Add(n)
		}
	}

	r80 := rand.Intn(1000) < 700 // 70% chance of reusing from the cache
	return v, r80 && time.Since(v.expiry) < 0
}

func (cb *cache) put(key string, response []byte, s *Summary) (ok bool) {
	if len(response) <= 0 {
		return false
	}

	ans := xdns.AsMsg(response)
	// only cache successful responses
	// TODO: implement negative caching
	if !xdns.HasRcodeSuccess(ans) || xdns.HasTCFlag(response) {
		return false
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()

	go cb.scrub()

	if len(cb.c) > cb.size {
		return false
	}

	ansttl := time.Duration(xdns.RTtl(ans)) * time.Second
	if ansttl < cb.ttl {
		ansttl = cb.ttl
	} else {
		// bump up a bit longer than the ttl
		ansttl = ansttl + cb.halflife
	}
	exp := time.Now().Add(ansttl)
	cb.c[key] = &cres{
		ans:    ans,
		s:      s,
		expiry: exp,
		bumps:  0,
	}

	return true
}

func asResponse(q *dns.Msg, v *cres) (r []byte, s *Summary, err error) {
	// TODO: needs read lock?
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
	var cb *cache

	msg := xdns.AsMsg(q)

	start := time.Now()
	if key, h, ok := t.ckey(msg); ok {
		t.Lock()
		cb = t.store[h]
		if cb == nil {
			cb = &cache{
				c:        make(map[string]*cres),
				mu:       &sync.RWMutex{},
				ttl:      t.ttl,
				bumps:    t.bumps,
				halflife: t.halflife,
			}
			t.store[h] = cb
		}
		t.Unlock()

		if v, ok := cb.fresh(key); !ok {
			if response, err = t.Transport.Query(network, q, summary); err == nil {
				cb.put(key, response, summary)
			} else if v != nil {
				response, s, err = asResponse(msg, v)
			}
		} else {
			response, s, err = asResponse(msg, v)
		}
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
