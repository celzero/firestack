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

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
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
	// separator qname, qtype cache-key
	cacheKeySep = ":"
)

var (
	errNoQuestion            = errors.New("no question")
	errNoAnswer              = errors.New("no answer")
	errHangover              = errors.New("no connectivity")
	errNilCacheResponse      = errors.New("nil cache response")
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
	s      *x.DNSSummary
	expiry time.Time
	bumps  int
}

// TODO: Keep a context here so that queries can be canceled.
type ctransport struct {
	sync.RWMutex                      // protects store
	Transport                         // the underlying transport
	store        []*cache             // cache buckets
	ipport       string               // a fake ip:port
	status       int                  // status of this transport
	ttl          time.Duration        // lifetime duration of a cached dns entry
	halflife     time.Duration        // increment ttl on each read
	bumps        int                  // max bumps in lifetime of a cached response
	size         int                  // max size of a cache bucket
	reqbarrier   *core.Barrier[*cres] // coalesce requests for the same query
	hangover     *core.Hangover       // tracks send failure threshold
	est          core.P2QuantileEstimator
}

func NewDefaultCachingTransport(t Transport) Transport {
	return NewCachingTransport(t, defttl)
}

func NewCachingTransport(t Transport, ttl time.Duration) Transport {
	if t == nil {
		return nil
	}

	// is type casting is a better way to do this?
	if cachedTransport(t) {
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
		reqbarrier: core.NewBarrier[*cres](ttl10s),
		hangover:   core.NewHangover(),
		est:        core.NewP50Estimator(),
	}
	log.I("cache: (%s) setup: %s; opts: %s", ct.ID(), ct.GetAddr(), ct.str())
	return ct
}

func (c *cres) copy() *cres {
	var anscopy *dns.Msg
	if c.ans != nil {
		anscopy = c.ans.Copy()
	}
	return &cres{
		ans:    anscopy, // may be nil
		s:      copySummary(c.s),
		expiry: c.expiry, // may be zero
		bumps:  c.bumps,
	}
}

func (cr *cres) String() string {
	return cr.str()
}

func (cr *cres) str() string {
	return "bumps=" + strconv.Itoa(cr.bumps) + "; expiry=" + cr.expiry.String() + "; s=" + cr.s.Str()
}

func (t *ctransport) str() string {
	return "ttl=" + t.ttl.String() + ";bumps=" + strconv.Itoa(t.bumps) + ";size=" + strconv.Itoa(t.size)
}

func hash(s string) uint8 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
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

	return qname + cacheKeySep + qtyp, hash(qname), true
}

// scrubCache deletes expired entries from the cache.
// Must be called from a goroutine.
func (cb *cache) scrubCache() {
	defer core.Recover(core.Exit11, "c.scrubCache")
	// must unlock from deferred since panics are recovered above
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

// put caches val against key, and returns true if the cache was updated.
// val must be a valid dns packet with successful rcode with no truncation.
func (cb *cache) put(key string, ans *dns.Msg, s *x.DNSSummary) (ok bool) {
	ok = false
	// only cache successful responses
	// TODO: implement negative caching
	if ans == nil || !xdns.HasRcodeSuccess(ans) || xdns.HasTCFlag(ans) {
		return
	}

	// do not cache .onion addresses
	if strings.Contains(key, ".onion"+cacheKeySep) {
		return
	}
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if rand33pc() { // 33% of the time
		go cb.scrubCache()
	}

	if len(cb.c) >= cb.size {
		log.W("cache: put: cache overflow %d > %d", len(cb.c), cb.size)
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

	log.D("cache: put(%s): l(%t/%d); %s", key, xdns.HasAnyAnswer(ans), xdns.Len(ans), v.str())

	ok = true
	return
}

func asResponse(q *dns.Msg, v *cres, fresh bool) (a *dns.Msg, s *x.DNSSummary, err error) {
	s = v.s // v must never be nil
	a = v.ans

	if q == nil || !xdns.HasAnyQuestion(q) {
		err = errNoQuestion
		return
	}
	if a == nil { // cache ans may be "empty" but should not be nil
		err = errNilCacheResponse
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
	if !fresh { // if the v is not fresh, set the ttl to the minimum
		xdns.WithTtl(a, stalettl) // only set for Answer records
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

func (t *ctransport) hangoverCheckpoint() {
	if t.Status() == SendFailed {
		t.hangover.Note()
	} else {
		t.hangover.Break()
	}
}

func (t *ctransport) fetch(network string, q *dns.Msg, summary *x.DNSSummary, cb *cache, key string) (*dns.Msg, error) {
	sendRequest := func(fsmm *x.DNSSummary) (*dns.Msg, error) {
		if false && settings.Debug && rand10pc() {
			panic("test crash")
		}

		fsmm.ID = t.ID()
		fsmm.Type = t.Type()

		v, _ := t.reqbarrier.Do(key, func() (*cres, error) {
			// ans may be nil
			ans, qerr := Req(t.Transport, network, q, fsmm)
			t.hangoverCheckpoint()
			// cb.put no-ops when ans is nil or xdns.Len(ans) is 0
			cb.put(key, ans, fsmm)
			// cres.ans may be nil
			return &cres{ans: ans, s: copySummary(fsmm)}, qerr
		})

		err := v.Err

		cachedres, fresh := cb.freshCopy(key) // always prefer value from cache
		if cachedres == nil {                 // v.Val may be uncacheable (ex: rcode != 0)
			cachedres = v.Val.copy() // v.Val (cres) never nil; but cres.ans may be nil
			log.D("cache: barrier: empty(k: %s); barrier: %s", key, v.String())
		} else if !fresh { // expect fresh values, except on verrs
			log.W("cache: barrier: stale(k: %s); barrier: %s (cache: %s)", key, v.String(), cachedres.String())
		}

		// nil ans when Transport returns err (no servfail) and cache is empty
		hasans := cachedres.ans != nil
		// if there's no network connectivity (in hangover for 10s) don't
		// return cached/barriered response, instead return an error
		inhangover := t.hangover.Exceeds(ttl10s)
		if inhangover {
			err = errors.Join(err, errHangover)
			log.W("cache: barrier: hangover(k: %s); discard ans (has? %t)", key, hasans)
			fillSummary(cachedres.s, fsmm)
			// mimic send fail
			fsmm.Msg = err.Error()
			fsmm.RCode = dns.RcodeServerFailure
			fsmm.Status = SendFailed
			// do not return any response (stall / drop silently)
			return nil, err
		}

		fres, cachedsmm, ferr := asResponse(q, cachedres, fresh)
		// fill summary regardless of errors
		fillSummary(cachedsmm, fsmm) // cachedsmm may itself be fsmm

		return fres, errors.Join(err, ferr)
	}

	// check if underlying transport can connect fine, if not treat cache
	// as stale regardless of its freshness. this avoids scenario when there's
	// no network connectivity but cache returns proper responses to queries,
	// which results in confused apps that think there's network connectivity,
	// that is, these confused apps go bezerk resulting in battery drain.
	// has 10s elapsed since the first send failure
	trok := t.hangover.Within(ttl10s)

	if v, isfresh := cb.freshCopy(key); trok && v != nil {
		var cachedsummary *x.DNSSummary
		hasans := v.ans != nil

		log.D("cache: hit(k: %s / stale? %t / ans? %t): %s", key, !isfresh, hasans, v.str())
		r, cachedsummary, err := asResponse(q, v, isfresh) // return cached response, may be stale
		if err != nil {
			log.W("cache: hit(k: %s) %s, but err? %v", key, v.str(), err)
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
				core.Gx("c.sendRequest: "+t.ID()+t.Type(), func() {
					_, _ = sendRequest(new(x.DNSSummary))
				})
			}
			// change summary fields to reflect cached response, except for latency
			fillSummary(cachedsummary, summary)
			summary.Latency = 0 // don't use cached latency
			t.est.Add(0)        // however, update the estimator
			return r, nil
		} // else: fallthrough to sendRequest
	} else {
		log.D("cache: miss(k: %s): cached? %t, hangover? %t, stale? %t", key, v != nil, !trok, !isfresh)
	}

	return sendRequest(summary) // summary is filled by underlying transport
}

func (t *ctransport) Query(network string, q *dns.Msg, summary *x.DNSSummary) (*dns.Msg, error) {
	var response *dns.Msg
	var err error
	var cb *cache

	if key, h, ok := mkcachekey(q); ok {
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

		response, err = t.fetch(network, q, summary, cb, key)

	} else {
		err = errMissingQueryName // not really a transport error
	}

	return response, err
}

func (t *ctransport) P50() int64 {
	return t.est.Get()
}

func (t *ctransport) GetAddr() string {
	prefix := PrefixFor(CT)
	return prefix + t.Transport.GetAddr()
}

func (t *ctransport) Status() int {
	return t.Transport.Status()
}

func copySummary(from *x.DNSSummary) (to *x.DNSSummary) {
	to = new(x.DNSSummary)
	*to = *from
	return
}

// fillSummary copies non-zero values into other.
func fillSummary(s *x.DNSSummary, other *x.DNSSummary) {
	if other == nil || s == other {
		return
	}
	if len(s.Type) != 0 {
		other.Type = s.Type
	}
	if len(s.ID) != 0 {
		other.ID = s.ID
	}
	if s.Latency != 0 {
		other.Latency = s.Latency
	}

	// query portions are only filled in if they are empty
	if len(other.QName) == 0 {
		other.QName = s.QName
	}
	// dns.TypeNone = 0
	if other.QType == 0 {
		other.QType = s.QType
	}

	if len(s.RData) != 0 {
		other.RData = s.RData
	}
	other.RCode = s.RCode
	other.RTtl = s.RTtl
	other.Server = s.Server
	other.RelayServer = s.RelayServer
	other.Status = s.Status
	other.Blocklists = s.Blocklists
	other.UpstreamBlocks = s.UpstreamBlocks
}

func rand33pc() bool {
	return rand.Intn(99999) < 33000
}

func rand10pc() bool {
	return rand.Intn(99999) < 10000
}
