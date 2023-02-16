// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

import (
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

// ideally set by clients via dnsx.cache-opts
const (
	// time to live for a cached response
	initialttl = 2 * time.Hour
	// bump ttl by this much on each read
	touchttl = initialttl / 10
	// max bumps before we stop bumping a response
	maxbumps = int(initialttl / touchttl)
	// max size of the response cache
	maxsize = 10000
	// min duration between scrubs
	scrubgap = 1 * time.Minute
	// how many entries to scrub at a time
	maxscrubs = maxsize / 10
)

var (
	errCacheResponseEmpty = errors.New("empty cache response")
)

type cres struct {
	ans   *dns.Msg
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
}

func NewCachingTransport(t Transport) (ct Transport) {
	ct = &ctransport{
		Transport: t,
		cache:     make(map[string]*cres),
		ipport:    "[fdaa:cac::ed:3]:53",
		status:    Start,
	}
	log.Infof("caching(%s) setup: %s", ct.ID(), ct.GetAddr())
	return
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

func (t *ctransport) put(q *dns.Msg, response []byte) (ok bool) {
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
	if len(t.cache) > maxsize*0.75 {
		go t.scrub()
	}
	if len(t.cache) > maxsize {
		return false
	}

	t.cache[key] = &cres{
		ans:   ans,
		ttl:   time.Now().Add(initialttl),
		bumps: 0,
	}

	return true
}

func (t *ctransport) touch(q *dns.Msg, v *cres) ([]byte, error) {
	t.Lock()
	defer t.Unlock()

	if v.bumps < maxbumps {
		v.ttl = time.Now().Add(touchttl)
		v.bumps = v.bumps + 1
	}
	a := v.ans

	if a != nil {
		a.Id = q.Id
		return a.Pack()
	} else {
		return nil, errCacheResponseEmpty
	}
}

func (t *ctransport) Query(network string, q []byte, summary *Summary) ([]byte, error) {
	var response []byte
	var err error

	msg := xdns.AsMsg(q)

	if v, ok := t.fresh(msg); !ok {
		response, err = t.Transport.Query(network, q, summary)
		if err == nil {
			t.put(msg, response)
		}
	} else {
		response, err = t.touch(msg, v)
	}

	if err != nil {
		t.status = BadResponse
	} else {
		t.status = Complete
	}

	ans := xdns.AsMsg(response)
	elapsed := 0 * time.Second
	summary.Latency = elapsed.Seconds()
	summary.RData = xdns.GetInterestingRData(ans)
	summary.RCode = xdns.Rcode(ans)
	summary.RTtl = xdns.RTtl(ans)
	summary.Server = t.GetAddr()
	summary.Status = t.Status()
	summary.Blocklists = ""

	return response, err
}

func (t *ctransport) GetAddr() string {
	return "cached." + t.Transport.GetAddr()
}

func (t *ctransport) Status() int {
	return t.status
}
