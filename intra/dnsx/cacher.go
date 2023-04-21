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
	// separator qname, qtype cache-key
	keysep = ":"
)

var (
	errCacheResponseEmpty = errors.New("empty cache response")
)

type cache struct {
	c         map[string]*cres       // query -> response
	mu        *sync.RWMutex          // protects the cache
	ttl       time.Duration          // how long to cache the valid dns response
	halflife  time.Duration          // how much to increment ttl on each read
	bumps     int                    // max bumps before we stop bumping a response
	size      int                    // max size of the cache
	scrubtime time.Time              // last time cache was scrubbed / purged
	qbarrier  map[string]*sync.Mutex // coalesce requests for the same query
	qmu       sync.RWMutex           // protects qbarrier
	bgRefresh bool                   // background refresh of cache
}

type cres struct {
	ans    *dns.Msg
	s      *Summary
	expiry time.Time
	bumps  int
}

// TODO: Keep a context here so that queries can be canceled.
type ctransport struct {
	sync.RWMutex               // protects store
	Transport                  // the underlying transport
	store        []*cache      // cache buckets
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
		log.I("cache: (%s) no-op: %s", t.ID(), t.GetAddr())
		return t
	}
	if strings.HasPrefix(t.GetAddr(), algprefix) {
		log.W("cache: (%s) no-op for alg: %s", t.ID(), t.GetAddr())
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
	log.I("cache: (%s) setup: %s; opts: %s", ct.ID(), ct.GetAddr(), ct.str())
	return ct
}

func (cr *cres) str() string {
	return "bumps=" + strconv.Itoa(cr.bumps) + " ;expiry=" + cr.expiry.String() + " ;s=" + cr.s.str()
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

	return qname + keysep + qtyp, hash(qname), true
}

func (cb *cache) refreshCache(t Transport, crch <-chan *cres) {
	if !cb.bgRefresh {
		return
	}
	net := "udp" // todo: change to tcp if the response is truncated

	for cr := range crch {
		// refresh the cache entry
		req := xdns.RequestFromResponse(cr.ans)
		if q, err := req.Pack(); err == nil {
			log.I("cache: prefetch refresh: %s", cr.str())
			go t.Query(net, q, cr.s)
		}
	}
}

func (cb *cache) queryBarrier(key string) (ba *sync.Mutex) {
	cb.qmu.Lock()
	defer cb.qmu.Unlock()

	if ba = cb.qbarrier[key]; ba == nil {
		ba = &sync.Mutex{}
		cb.qbarrier[key] = ba
	}
	return
}

func (cb *cache) purgeQBarrier(kch <-chan string) {
	var keys []string
	for k := range kch {
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return
	}

	cb.qmu.Lock()
	for _, k := range keys {
		delete(cb.qbarrier, k)
	}
	cb.qmu.Unlock()

	log.I("cache: cleaned up: %d", len(keys))
}

func (cb *cache) scrubCache(kch chan<- string, vch chan<- *cres) {
	defer close(kch)
	defer close(vch)

	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()
	if now.Sub(cb.scrubtime) < scrubgap {
		return
	}
	cb.scrubtime = now

	// scrub the cache if it's getting too big
	highload := len(cb.c) >= cb.size*75/100

	i, j, m := 0, 0, 0
	for k, v := range cb.c {
		i++
		if v.bumps >= (cb.bumps / 2) {
			// invalidate cached entry
			v.expiry = time.Now()
			// bump it to the highest to keep its freshness locked
			v.bumps = cb.bumps
			vch <- v
			m++
		} else if highload && time.Since(v.expiry) > 0 {
			// evict expired entries on high load, otherwise keep them
			// around for use in cases where transport errors out
			delete(cb.c, k)
			kch <- k
			j++
		}
		if i > maxscrubs {
			break
		}
	}
	log.I("cache: del: %d; ref: %d; tot: %d / high? %t", j, m, i, highload)
}

func (cb *cache) fresh(key string) (v *cres, ok bool) {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	if v, ok = cb.c[key]; !ok {
		return
	}

	recent := v.bumps <= 1
	alive := time.Since(v.expiry) <= 0
	if v.bumps < cb.bumps {
		n := time.Duration(v.bumps) * cb.halflife
		// if the expiry time is already n duration in the future, don't incr ttl
		// or if the entry is already expired, don't incr ttl
		if alive && time.Since(v.expiry.Add(-n)) < 0 {
			v.expiry = v.expiry.Add(n)
		}
		v.bumps += 1
	}

	r75 := rand.Intn(99999) < 75000 // 75% chance of reusing from the cache
	return v, (r75 || recent) && alive
}

func (cb *cache) put(t Transport, key string, response []byte, s *Summary) (ok bool) {
	ok = false

	if len(response) <= 0 {
		return
	}
	// do not cache .onion addresses
	if strings.Contains(key, ".onion"+keysep) {
		return
	}

	ans := xdns.AsMsg(response)
	// only cache successful responses
	// TODO: implement negative caching
	if !xdns.HasRcodeSuccess(ans) || xdns.HasTCFlag(response) {
		return
	}

	kch := make(chan string) // delete
	vch := make(chan *cres)  // renew
	go cb.scrubCache(kch, vch)
	go cb.purgeQBarrier(kch)
	go cb.refreshCache(t, vch)

	cb.mu.Lock()
	defer cb.mu.Unlock()

	if len(cb.c) >= cb.size {
		return
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

	ok = true
	return
}

func asResponse(q *dns.Msg, v *cres) (r []byte, s *Summary, err error) {
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

func (t *ctransport) fetch(network string, q []byte, msg *dns.Msg, summary *Summary, cb *cache, key string) ([]byte, error) {
	start := time.Now()

	sendRequest := func() (r []byte, err error) {
		ba := cb.queryBarrier(key)

		ba.Lock() // per query-name lock
		r, err = t.Transport.Query(network, q, summary)
		ba.Unlock()
		if err == nil && len(r) > 0 {
			cb.put(t, key, r, summary)
		}
		return
	}

	if v, ok := cb.fresh(key); v != nil {
		if !ok { // not fresh, fetch in the background
			go sendRequest()
		}
		log.D("cache: hit %s, but stale? %t", v.str(), ok)

		r, s, err := asResponse(msg, v) // return cached response, may be stale

		if s != nil {
			summary.Latency = time.Since(start).Seconds()
			summary.RData = s.RData
			summary.RCode = s.RCode
			summary.RTtl = s.RTtl
			summary.Blocklists = s.Blocklists
			summary.Server = t.GetAddr()
		}

		return r, err
	} else {
		r, err := sendRequest()
		return r, err
	}
}

func (t *ctransport) Query(network string, q []byte, summary *Summary) ([]byte, error) {
	var response []byte
	var err error
	var cb *cache

	msg := xdns.AsMsg(q)

	if key, h, ok := t.ckey(msg); ok {
		t.Lock()
		cb = t.store[h]
		if cb == nil {
			cb = &cache{
				c:         make(map[string]*cres),
				mu:        &sync.RWMutex{},
				size:      t.size,
				ttl:       t.ttl,
				bumps:     t.bumps,
				halflife:  t.halflife,
				qbarrier:  make(map[string]*sync.Mutex),
				bgRefresh: false,
			}
			t.store[h] = cb
		}
		t.Unlock()

		response, err = t.fetch(network, q, msg, summary, cb, key)

	} else {
		err = errMissingQueryName
	}

	if err != nil {
		t.status = BadResponse
	} else {
		t.status = Complete
	}
	summary.Status = t.Status()

	return response, err
}

func (t *ctransport) GetAddr() string {
	return addrprefix + t.Transport.GetAddr()
}

func (t *ctransport) Status() int {
	return t.status
}
