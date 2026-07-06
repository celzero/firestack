// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	x "github.com/celzero/firestack/intra/backend"
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
	// (ideally, longer than request timeouts)
	battl = 30 * time.Second
	// threshold for hangover responses
	httl = 10 * time.Second
	// how many entries to scrub at a time per cache bucket
	maxscrubs = defsize / 4 // 25% of the cache
	// separator qname, qtype cache-key
	cacheKeySep = ":"
)

var (
	errNoQuestion            = errors.New("dns: no question")
	errNoAnswer              = errors.New("dns: no answer")
	errServFail              = errors.New("dns: answer servfail")
	errBlocked               = errors.New("dns: answer blocked")
	errHangover              = errors.New("dns: no connectivity")
	errNilCacheResponse      = errors.New("dns: nil cache response")
	errCannotUseStaleCache   = errors.New("dns: cannot use stale cache response")
	errSkipInternalCache     = errors.New("dns: skip internal cache")
	errCacheResponseMismatch = errors.New("dns: cache response mismatch")
)

type Cacher interface {
	Transport
	Clear()
}

type cache struct {
	mu *sync.RWMutex    // protects cache, cres, and scrubtime
	c  map[string]*cres // query -> response

	scrubtime time.Time // last time cache was scrubbed / purged

	// constants:

	ttl      time.Duration // how long to cache the valid dns response
	halflife time.Duration // how much to increment ttl on each read
	bumps    int           // max bumps before we stop bumping a response
	size     int           // max size of the cache
}

type cres struct {
	ans    *dns.Msg
	s      *x.DNSSummary
	expiry time.Time
	bumps  int
}

// todo: 0s answer ttl? native caching in alg?
type ctransport struct {
	sync.RWMutex // protects store
	Transport    // embeds the underlying transport

	ctx        context.Context
	done       context.CancelFunc
	store      []*cache                     // cache buckets
	ipport     string                       // a fake ip:port
	ttl        time.Duration                // lifetime duration of a cached dns entry
	halflife   time.Duration                // increment ttl on each read
	bumps      int                          // max bumps in lifetime of a cached response
	size       int                          // max size of a cache bucket
	reqbarrier *core.Barrier[*cres, string] // coalesce requests for the same query
	hangover   *core.Hangover               // tracks send failure threshold
}

var _ Cacher = (*ctransport)(nil)

func NewDefaultCachingTransport(t Transport) Transport {
	return NewCachingTransport(context.Background(), t, defttl)
}

func NewCachingTransport(pctx context.Context, t Transport, ttl time.Duration) Transport {
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
	ctx, done := context.WithCancel(pctx)
	ct := &ctransport{
		Transport:  t,
		ctx:        ctx,
		done:       done,
		store:      make([]*cache, defbuckets),
		ipport:     "[fdaa:cac::ed:3]:53",
		ttl:        ttl,
		halflife:   ttl / 2,
		bumps:      defbumps,
		size:       defsize,
		reqbarrier: core.NewBarrier[*cres](ctx, "dnsx.c.reqbar", battl),
		hangover:   core.NewHangover(),
	}
	context.AfterFunc(ctx, ct.Clear)
	log.I("cache: (%s) setup: %s; opts: %s", ct.ID(), ct.GetAddr(), ct)
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

// String implements fmt.Stringer
func (cr *cres) String() string {
	if cr == nil {
		return "<nil>"
	}
	return fmt.Sprintf("bumps=%d; expiry=%s; s=%s", cr.bumps, timestamp(cr.expiry), cr.s)
}

func timestamp(t time.Time) string {
	return t.Format(time.Stamp)
}

// String implements fmt.Stringer
func (t *ctransport) String() string {
	if t == nil {
		return "<nil>"
	}
	return fmt.Sprintf("ttl=%s; bumps=%d; size=%d", t.ttl, t.bumps, t.size)
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
	do := "0"
	if xdns.IsDNSSECRequested(q) {
		do = "1"
	}

	return qname + cacheKeySep + qtyp + cacheKeySep + do, hash(qname), true
}

// scrubCache deletes expired entries from the cache.
// Must be called from a goroutine.
func (cb *cache) scrubCache() {
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
	cb.mu.Lock() // write lock: bumps expiry/count on the shared *cres in-place
	defer cb.mu.Unlock()

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
func (cb *cache) put(key string, cc *cres) (ok bool) {
	ok = false
	if cc == nil {
		return
	}

	ans := cc.ans
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
		core.Gx("c.scrubCache", cb.scrubCache)
	}

	if len(cb.c) >= cb.size {
		log.W("cache: put: cache overflow %d > %d", len(cb.c), cb.size)
	}

	// 1. ansttl is 0 for synthesized "block" answers (see xdns.BlockTTL)
	// 2. for most empty ans (like qtype:65), ansttl is 0
	ansttl := time.Duration(xdns.RTtl(ans)) * time.Second

	// cache must keep the answer alive for a min of cb.ttl
	// because the client code may fail if the cache marks
	// a recently incubated answer as stale.
	if ansttl < cb.ttl {
		ansttl = cb.ttl
	} else { // bump up a bit longer than the ttl
		ansttl = ansttl + cb.halflife
	}

	exp := time.Now().Add(ansttl)
	v := &cres{ // TODO: copy is not required?
		ans:    cc.ans.Copy(),
		s:      copySummary(cc.s),
		expiry: exp,
		bumps:  0,
	}
	cb.c[key] = v

	log.D("cache: put(%s): l(%t/%d); %s", key, xdns.HasAnyAnswer(ans), xdns.Len(ans), v)

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
	if !fresh && xdns.IsDNSSECAnswerAuthenticated(a) {
		// for stale responses, TTL is modified which violates DNSSEC?
		err = errCannotUseStaleCache
		return
	}
	aname := qname(a)
	qname := qname(q)
	if aname != qname {
		log.E("cache: asResponse: qname mismatch: a(%s) != q(%s)", aname, qname)
		err = errCacheResponseMismatch
		return
	}

	a.Id = q.Id // OK to change even if dnssec?
	// dns 0x20 may mangle the question section, so preserve it
	// github.com/jedisct1/edgedns#correct-support-for-the-dns0x20-extension
	a.Question = q.Question
	a.Response = true // just to be sure
	if !fresh {       // if the v is not fresh, set the ttl to the minimum
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

func (t *ctransport) fetch(network string, q *dns.Msg, smmout *x.DNSSummary, cb *cache, key string) (*dns.Msg, error) {
	sendRequest := func(q2 *dns.Msg, smm2 *x.DNSSummary) (*dns.Msg, error) {
		reqsent := false

		defer func() {
			// fill after summaries are filled
			if !reqsent {
				smm2.Cached = true
			}
		}()

		ccx := &cres{ans: nil, s: copySummary(smm2)}
		cc, err := t.reqbarrier.DoIt(key, func() (_ *cres, qerr error) {
			reqsent = true
			// ans may be nil
			ccx.ans, qerr = Req(t.Transport, network, q2, smm2)
			ccx.s = copySummary(smm2) // copy summary to cc
			t.hangoverCheckpoint()
			// cb.put no-ops when ans is nil or rcode != success (0)
			cb.put(key, ccx)
			return ccx, qerr
		})

		if cc == nil { // may be nil for example when barrier times outs
			log.E("cache: barrier: %s; nil return for %s; err? %v", t.ID(), key, err)
			cc = ccx
		}

		cachedres, fresh := cb.freshCopy(key) // always prefer value from cache
		cachehit := cachedres != nil
		// nil ans when Transport returns err (no servfail) and cache is empty
		cachedans := cachedres != nil && cachedres.ans != nil

		// if there's no network connectivity (in hangover for 10s) don't
		// return cached/barriered response, instead return an error
		inhangover := t.hangover.Exceeds(httl)

		// expect fresh values, except on verrs
		logwif(cachehit && !fresh || err != nil)("cache: barrier: (k: %s) hit? %t / hitans? %t / stale? %t / sent? %t / hangover? %t, barrier: %s (cache: %s); qerr? %v",
			key, cachehit, cachedans, !fresh, reqsent, inhangover, cc, cachedres, err)

		if !cachehit || !cachedans { // cc.Val may be uncacheable (ex: rcode != 0)
			cachedres = cc // cc (cres) never nil; but cc.ans may be nil
		}

		if inhangover {
			err = core.JoinErr(err, errHangover)
			log.W("cache: barrier: hangover(k: %s); sent? %t, discard ans (has? %t)",
				key, reqsent, cachedans)
			fillSummary(cachedres.s, smm2)
			// mimic send fail
			smm2.Msg = err.Error()
			smm2.RCode = dns.RcodeBadTime
			smm2.Status = SendFailed
			smm2.Cached = true
			// do not return any response (stall / drop silently)
			return nil, err
		}

		// fres may be nil
		fres, cachedsmm, ferr := asResponse(q2, cachedres, fresh)
		fillSummary(cachedsmm, smm2) // cachedsmm may itself be smm2
		smm2.Cached = true

		return fres, core.JoinErr(err, ferr)
	}

	// check if underlying transport can connect fine, if not treat cache
	// as stale regardless of its freshness. this avoids scenario when there's
	// no network connectivity but cache returns proper responses to queries,
	// which results in confused apps that think there's network connectivity,
	// that is, these confused apps go bezerk resulting in battery drain.
	// has 10s elapsed since the first send failure
	trok := t.hangover.Within(httl)

	if v, isfresh := cb.freshCopy(key); trok && v != nil {
		var cachedsmm *x.DNSSummary
		hasans := v.ans != nil

		log.D("cache: hit(k: %s / stale? %t / ans? %t): %s", key, !isfresh, hasans, v)
		r, cachedsmm, err := asResponse(q, v, isfresh) // return cached response, may be stale
		if err != nil {
			nilOrMismatch := errors.Is(err, errNilCacheResponse) ||
				errors.Is(err, errCacheResponseMismatch)

			logeif(nilOrMismatch)("cache: hit(k: %s) %s, but err? %v", key, v, err)

			if nilOrMismatch {
				// FIXME: this is a hack to fix an issue where the cache
				// returns a response that does not match the fqdn in query
				// or somehow has wrapper cache-obj but not the dns answer.
				cb.mu.Lock()
				delete(cb.c, key) // del the corrupted entry
				cb.mu.Unlock()
			}
			// fallthrough to sendRequest
		} else if cachedsmm != nil {
			if !isfresh { // not fresh, fetch in the background
				core.Gx("c.sendRequest: "+key+t.ID(), func() {
					_, _ = sendRequest(q.Copy(), copySummary(smmout)) // summary may be cached
				})
			}
			// change summary fields to reflect cached response, except for latency
			fillSummary(cachedsmm, smmout)
			smmout.Latency = 0 // don't use cached latency
			smmout.Cached = true
			return r, nil
		} // else: fallthrough to sendRequest
	} else {
		log.D("cache: miss(k: %s): cached? %t, hangover? %t, stale? %t",
			key, v != nil, !trok, !isfresh)
	}

	// send request in the foreground, and return the response
	return sendRequest(q, smmout) // summary is filled by underlying transport
}

func (t *ctransport) Query(network string, q *dns.Msg, smm *x.DNSSummary) (*dns.Msg, error) {
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

		response, err = t.fetch(network, q, smm, cb, key)
	} else {
		err = errMissingQueryName // not really a transport error
	}

	return response, err
}

func (t *ctransport) P50() int64 {
	return 0
}

func (t *ctransport) GetAddr() string {
	prefix := TransportPrefix(CT)
	return prefix + t.Transport.GetAddr()
}

func (t *ctransport) IPPorts() []netip.AddrPort {
	return t.Transport.IPPorts()
}

func (t *ctransport) Status() int32 {
	return t.Transport.Status()
}

func (t *ctransport) Stop() error {
	t.done()
	// does not call stop on underlying transport as
	// it does not "own" it but merely "decorates" it
	return nil
}

func (t *ctransport) Clear() {
	t.Lock()
	defer t.Unlock()

	defer clear(t.store)
	for _, c := range t.store {
		if c != nil {
			c.mu.Lock()
			clear(c.c)
			c.mu.Unlock()
		}
	}
}

func copySummary(from *x.DNSSummary) (to *x.DNSSummary) {
	to = new(x.DNSSummary)
	*to = *from // go.dev/play/p/rcGKAcju0FU
	return
}

// fillSummary copies non-zero values into out.
func fillSummary(s *x.DNSSummary, out *x.DNSSummary) {
	if out == nil || s == out {
		return
	}

	// prefer out

	if len(out.Type) == 0 {
		out.Type = s.Type
	}
	if len(out.Origin) <= 0 {
		out.Origin = s.Origin
	}

	if len(out.ID) <= 0 {
		out.ID = s.ID
		out.Server = s.Server
	} else if len(out.Server) <= 0 {
		out.Server = s.Server
	}

	if len(out.FID) <= 0 {
		out.FID = s.FID
	}
	if len(out.Origin) <= 0 {
		out.Origin = s.Origin
	}
	if out.Start <= 0 {
		out.Start = s.Start
	}
	if out.Latency <= 0 {
		out.Latency = s.Latency
	}
	if len(out.UID) <= 0 {
		out.UID = s.UID
	}
	if len(out.QName) == 0 {
		// query portions are only filled in if they are empty
		out.QName = s.QName
	}
	if out.QType == 0 { // dns.TypeNone = 0
		out.QType = s.QType
	}
	if len(out.Region) == 0 { // fill in region if empty
		out.Region = s.Region
	}

	// prefer s

	if len(s.RData) != 0 {
		out.RData = s.RData
		out.AD = s.AD
		out.DO = s.DO
	}

	if len(s.PID) > 0 {
		out.PID = s.PID
		out.RPID = s.RPID
	}
	out.ECH = s.ECH
	out.Cached = s.Cached
	out.RCode = s.RCode
	out.RTtl = s.RTtl
	out.Status = s.Status
	out.Blocklists = s.Blocklists
	out.BlockedTarget = s.BlockedTarget
	out.Msg = s.Msg
	out.UpstreamBlocks = s.UpstreamBlocks
	out.Extra = s.Extra
}

func rand33pc() bool {
	return rand.Intn(99999) < 33000
}
