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

	"github.com/celzero/firestack/intra/core"
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
	// ttl for expired response
	stalettl = 15 // seconds
	// ttl for response from requests that were barriered
	ttl10s = 10 * time.Second
	// how many entries to scrub at a time per cache bucket
	maxscrubs = defsize / 4 // 25% of the cache
	// prefix for cached transport addresses
	addrprefix = "cached."
	// separator qname, qtype cache-key
	keysep = ":"
)

var (
	errNoQuestion            = errors.New("no question")
	errCacheResponseEmpty    = errors.New("empty cache response")
	errCacheResponseMismatch = errors.New("cache response mismatch")
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
	sync.RWMutex               // protects store
	Transport                  // the underlying transport
	store        []*cache      // cache buckets
	ipport       string        // a fake ip:port
	status       int           // status of this transport
	ttl          time.Duration // lifetime duration of a cached dns entry
	halflife     time.Duration // increment ttl on each read
	bumps        int           // max bumps in lifetime of a cached response
	size         int           // max size of a cache bucket
	reqbarrier   *core.Barrier // coalesce requests for the same query
	est          core.P2QuantileEstimator
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
		log.I("cache: (%s) no-op: %s", t.ID(), t.GetAddr())
		return t
	}
	if strings.HasPrefix(t.GetAddr(), algprefix) {
		log.W("cache: (%s) no-op for alg: %s", t.ID(), t.GetAddr())
		return t
	}
	ct := &ctransport{
		Transport:  t,
		store:      make([]*cache, defbuckets),
		ipport:     "[fdaa:cac::ed:3]:53",
		status:     Start,
		ttl:        ttl,
		halflife:   ttl / 2,
		bumps:      defbumps,
		size:       defsize,
		reqbarrier: core.NewBarrier(ttl10s),
		est:        core.NewP50Estimator(),
	}
	log.I("cache: (%s) setup: %s; opts: %s", ct.ID(), ct.GetAddr(), ct.str())
	return ct
}

func (c *cres) copy() *cres {
	return &cres{
		ans:    c.ans.Copy(),
		s:      c.s.Copy(),
		expiry: c.expiry,
		bumps:  c.bumps,
	}
}

func (cr *cres) str() string {
	return "bumps=" + strconv.Itoa(cr.bumps) + "; expiry=" + cr.expiry.String() + "; s=" + cr.s.Str()
}

func (t *ctransport) str() string {
	return "ttl=" + t.ttl.String() + ";bumps=" + strconv.Itoa(t.bumps) + ";size=" + strconv.Itoa(t.size)
}

func hash(s string) uint8 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return uint8(h.Sum32() % defbuckets)
}

func mkcachekey(q *dns.Msg) (string, uint8, bool) {
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

func (cb *cache) scrubCache() {
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
		if highload && time.Since(v.expiry) > 0 {
			// evict expired entries on high load, otherwise keep them
			// around for use in cases where transport errors out
			delete(cb.c, k)
			j++
		}
		if i > maxscrubs {
			break
		}
	}
	log.I("cache: del: %d; ref: %d; tot: %d / high? %t", j, m, i, highload)
}

func (cb *cache) freshCopy(key string) (v *cres, ok bool) {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	if v, ok = cb.c[key]; !ok {
		return
	}

	recent := v.bumps <= 2
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

	r50 := rand.Intn(99999) < 50000 // 50% chance of reusing from the cache
	return v.copy(), (r50 || recent) && alive
}

func (cb *cache) put(response []byte, s *Summary) (ok bool) {
	ok = false

	if len(response) <= 0 {
		return
	}

	ans := xdns.AsMsg(response)
	// only cache successful responses
	// TODO: implement negative caching
	if ans == nil || !xdns.HasRcodeSuccess(ans) || xdns.HasTCFlag(response) {
		return
	}

	key, _, ok := mkcachekey(ans)
	// do not cache .onion addresses
	if !ok || strings.Contains(key, ".onion"+keysep) {
		return
	}
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if rand.Intn(99999) < 33000 { // 33% of the time
		go cb.scrubCache()
	}

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
	v := &cres{
		ans:    ans,
		s:      s,
		expiry: exp,
		bumps:  0,
	}
	cb.c[key] = v

	log.D("cache: put(%s): %s", key, v.str())

	ok = true
	return
}

func asResponse(q *dns.Msg, v *cres, fresh bool) (r []byte, s *Summary, err error) {
	if q == nil {
		err = errNoQuestion
		return
	}
	a := v.ans
	if a == nil {
		err = errCacheResponseEmpty
		return
	}
	aname, _ := xdns.NormalizeQName(xdns.QName(q))
	qname, _ := xdns.NormalizeQName(xdns.QName(a))
	if aname != qname {
		log.E("cache: asResponse: qname mismatch: a(%s) != q(%s)", aname, qname)
		err = errCacheResponseMismatch
		return
	}

	a.Id = q.Id
	// dns 0x20 may mangle the question section, so preserve it
	// github.com/jedisct1/edgedns#correct-support-for-the-dns0x20-extension
	a.Question = q.Question
	// if the v is not fresh, set the ttl to the minimum
	if !fresh {
		xdns.WithTtl(a, stalettl)
	}
	s = v.s
	r, err = a.Pack()
	return
}

func (t *ctransport) ID() string {
	// must match with how wrapping transports like DcProxy / Gateway rely on the ID
	return CT + t.Transport.ID()
}

func (t *ctransport) Type() string {
	return t.Transport.Type()
}

func (t *ctransport) fetch(network string, q []byte, msg *dns.Msg, summary *Summary, cb *cache, key string) (r []byte, err error) {
	sendRequest := func(async bool) ([]byte, error) {
		var finalsumm *Summary
		if async {
			finalsumm = new(Summary)
		} else {
			finalsumm = summary
		}

		finalsumm.ID = t.Transport.ID()
		finalsumm.Type = t.Transport.Type()

		rv := t.reqbarrier.Do(key, func() (any, error) {
			ans, err := t.Transport.Query(network, q, finalsumm)
			cb.put(ans, finalsumm)
			return &cres{ans: xdns.AsMsg(ans), s: finalsumm}, err
		})

		cachedres, ok := rv.Val.(*cres)
		if !ok {
			return nil, errCacheResponseMismatch
		}

		finalres, origsumm, finalerr := asResponse(msg, cachedres, true)
		// fill summary regardless of errors
		origsumm.FillInto(finalsumm) // origsumm may be equal to s

		return finalres, errors.Join(rv.Err, finalerr)
	}

	// check if underlying transport can connect fine, if not treat cache
	// as stale regardless of its freshness. this avoids scenario when there's
	// no network connectivity but cache returns proper responses to queries,
	// which results in confused apps that think there's network connectivity,
	// that is, these confused apps go bezerk resulting in battery drain.
	tok := t.Status() != SendFailed

	if v, isfresh := cb.freshCopy(key); tok && v != nil {
		var cachedsummary *Summary

		log.D("cache: hit(%s): %s, but stale? %t", key, v.str(), !isfresh)
		r, cachedsummary, err = asResponse(msg, v, isfresh) // return cached response, may be stale
		if err != nil {
			log.W("cache: hit(%s) %s, but err? %v", key, v.str(), err)
			if err == errCacheResponseMismatch {
				// FIXME: this is a hack to fix the issue where the cache
				// returns a response that does not match the query.
				cb.mu.Lock()
				delete(cb.c, key) // del the corrupted entry
				cb.mu.Unlock()
			}
			// fallthrough to sendRequest
		} else if cachedsummary != nil {
			if !isfresh { // not fresh, fetch in the background
				go sendRequest(true)
			}
			// change summary fields to reflect cached response, except for latency
			cachedsummary.FillInto(summary)
			summary.Latency = 0 // don't use cached latency
			t.est.Add(0)        // however, update the estimator
			return
		} // else: fallthrough to sendRequest
	}
	return sendRequest(false) // summary is filled by underlying transport
}

func (t *ctransport) Query(network string, q []byte, summary *Summary) ([]byte, error) {
	var response []byte
	var err error
	var cb *cache

	msg := xdns.AsMsg(q)

	if key, h, ok := mkcachekey(msg); ok {
		t.Lock()
		cb = t.store[h]
		if cb == nil {
			cb = &cache{
				c:        make(map[string]*cres),
				mu:       &sync.RWMutex{},
				size:     t.size,
				ttl:      t.ttl,
				bumps:    t.bumps,
				halflife: t.halflife,
			}
			t.store[h] = cb
		}
		t.Unlock()

		response, err = t.fetch(network, q, msg, summary, cb, key)

	} else {
		err = errMissingQueryName // not really a transport error
	}

	return response, err
}

func (t *ctransport) P50() int64 {
	return t.est.Get()
}

func (t *ctransport) GetAddr() string {
	return addrprefix + t.Transport.GetAddr()
}

func (t *ctransport) Status() int {
	return t.Transport.Status()
}
