// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

const plusSupportsCachedTransports = false
const plusUsesPreferred = false
const plusUsesSystem = false
const plusSupportsRelay = false

const plusMaxTries = 6

const ttl10s = 10 * time.Second

var fakePlusIpports = []netip.AddrPort{
	netip.MustParseAddrPort("[fdaa:9125::9125:9]:53"),
}

type plus struct {
	mu sync.RWMutex // protects all
	// id => transport; should contain transports owned by Plus
	transports map[string]Transport

	r       TransportProviderInternal
	ctx     context.Context
	done    context.CancelFunc
	ipports []netip.AddrPort

	ba *core.Barrier[[]Transport, string]

	closed atomic.Bool
	last   core.Volatile[Transport]
}

var _ Transport = (*plus)(nil)
var _ TransportMult = (*plus)(nil)

func NewPlusTransport(ctx context.Context, r TransportProviderInternal, ts ...Transport) Transport {
	ctx, done := context.WithCancel(ctx)
	t := &plus{
		ctx:        ctx,
		transports: make(map[string]Transport, len(ts)),
		ba:         core.NewBarrier[[]Transport](ctx, "dnsx.p.bar", ttl10s),
		r:          r,
		done:       done,
		ipports:    fakePlusIpports,
	}

	for _, tr := range ts {
		if len(idstr(tr)) > 0 {
			t.transports[tr.ID()] = tr
		}
	}

	log.I("plus: at %s; added: %d/%d", t.GetAddr(), len(t.transports), len(ts))
	context.AfterFunc(ctx, t.stopAll)
	return t
}

func (t *plus) stopAll() {
	t.closed.Store(true)

	t.mu.Lock()
	defer t.mu.Unlock()

	for _, tr := range t.transports {
		if err := tr.Stop(); err != nil {
			log.E("plus: (%s) stop: %v", t.ID(), err)
		}
	}
	clear(t.transports)
	t.last.Store(nil)
}

// String implements fmt.Stringer
func (t *plus) all() []Transport {
	t.mu.RLock()
	defer t.mu.RUnlock()

	const all = 0
	return vals(t.transports, all)
}

func (t *plus) ID() string {
	// must match with how wrapping transports like DcProxy / Gateway rely on the ID
	return Plus
}

func (t *plus) Type() string {
	return DOH
}

func (t *plus) latest() Transport {
	if t.closed.Load() {
		return nil
	}

	if l := t.last.Load(); l != nil {
		return l
	}

	if ts := t.all(); len(ts) > 0 {
		return ts[0]
	}
	return nil
}

func (t *plus) defaultdns() (Transport, error) {
	return t.r.GetInternal(Default)
}

func (t *plus) systemdns() (Transport, error) {
	if !plusUsesSystem {
		return nil, errNoSuchTransport
	}
	return t.r.GetInternal(System) // may return Goos or Default
}

func (t *plus) preferreddns() (Transport, error) {
	if !plusUsesPreferred {
		return nil, errNoSuchTransport
	}
	return t.r.GetInternal(Preferred) // may return Default
}

func (t *plus) ordered() ([]Transport, error) {
	_, _, best, preferred, recov, errored, ended := Categorize(t.all())

	expected := len(best) + len(preferred) + len(recov) + 1

	ord := make([]Transport, 0, expected)

	if l := t.latest(); l != nil {
		ord = append(ord, l) // latest may be nil
	}
	ord = append(ord, best...)
	d, _ := t.defaultdns()
	if d != nil {
		ord = append(ord, d)
	}
	sys, _ := t.systemdns()
	if sys != nil && idstr(d) != idstr(sys) {
		ord = append(ord, sys)
	}
	p, _ := t.preferreddns()
	if p != nil && idstr(d) != idstr(p) {
		ord = append(ord, p)
	}
	ord = append(ord, preferred...)
	ord = append(ord, recov...)

	ord = core.CopyUniq(ord)

	prev := ord
	strat := settings.PlusStrat.Load()

	refiltered := false
refilter:
	switch strat {
	case settings.PlusFilterSafest:
		ord = core.FilterLeft(ord, IsEncrypted)
	case settings.PlusOrderRandom:
		ord = core.ShuffleInPlace(ord)
	case settings.PlusOrderFastest:
		ord = core.Sort(ord, Fastest)
	case settings.PlusOrderRobust:
		// nothing to do
	}

	if !refiltered && len(ord) < plusMaxTries {
		ord = core.CopyUniq(ord, errored)
		refiltered = true
		goto refilter
	}

	if len(ord) <= 0 {
		log.W("plus: strat %d: zero transports avail [exp: %d]: sys? %s / pref: %s / errored: %v / ended: %v",
			strat, expected, idstr(sys), infcsv(preferred...), infcsv(errored...), infcsv(ended...))
		return nil, errNoSuchTransport
	} else if len(ord) < len(prev) {
		log.VV("plus: strat %d: filtered %d < chosen %d; chosen: %s / pref: %v",
			strat, len(ord), len(prev), infcsv(ord...), infcsv(preferred...))
	}

	return ord, nil
}

func (t *plus) Query(network string, q *dns.Msg, smm *x.DNSSummary) (ans *dns.Msg, err error) {
	if t.closed.Load() {
		return nil, NewEndQueryError()
	}

	ord, err := t.ba.DoIt("plus.q."+network, t.ordered)
	if err != nil {
		return nil, err
	}
	return t.forward(network, q, smm, ord...)
}

func (t *plus) forward(network string, q *dns.Msg, outSmm *x.DNSSummary, all ...Transport) (finalans *dns.Msg, errs error) {
	qname := qname(q)
	qtyp := qtype(q)
	tries := plusMaxTries
	visited := make(map[string]struct{}, len(all))
	finalsmm := copySummary(outSmm)

	defer func() {
		fillSummary(finalsmm, outSmm)
		if finalans != nil { // suppress errors
			log.D("plus: suppressing errors for %s:%d[%s]: %v", qname, qtyp, outSmm.RData, errs)
			errs = nil
		}
	}()

	for _, tr := range all {
		cursmm := copySummary(outSmm)

		if len(visited) > tries {
			break
		}

		if tr == nil { // unlikely
			errs = core.JoinErr(errs, errNoSuchTransport)
			continue
		}

		id := tr.ID()
		if plusSupportsCachedTransports {
			id, _ = strings.CutPrefix(id, CT)
		}
		if _, ok := visited[id]; ok {
			continue
		}
		visited[id] = struct{}{}

		ans, err := tr.Query(network, q, cursmm)

		failed := xdns.IsServFailOrInvalid(ans)
		noans := !failed && !xdns.HasAnyAnswer(ans)
		ipblock := xdns.HasAQuadAQuestion(q) && xdns.AQuadAUnspecified(ans)
		// HTTPS/SVCB blocks have 0 answer records when blocked
		svcbblock := (xdns.HasHTTPQuestion(q) || xdns.HasSVCBQuestion(q)) && noans

		finalsmm = cursmm

		loged(err != nil || failed)("plus: queried %s for %s:%d (fid: %s); data: %s [noans? %t], code: %d, err? %v",
			idstr(tr), qname, qtyp, outSmm.FID, finalsmm.RData, noans, finalsmm.RCode, err)

		if err != nil || ans == nil {
			errs = core.JoinErr(errs, core.OneErr(err, errNoAnswer))
			continue
		}

		finalans = ans // may be this is the final answer

		if failed {
			errs = core.JoinErr(errs, errServFail)
			continue
		}

		if ipblock || svcbblock {
			errs = core.JoinErr(errs, errBlocked)
			continue
		}

		// an ipv4 only service/website will always return nxdomain (no answer)
		// for ipv6 queries, and so, always treating those as errors is not
		// what we want but instead to note the nxdomain response down and see
		// if other resolvers return an answer or not (censoring resolvers may
		// also return nxdomain or blocked answers, which is why we must continue
		// to try other resolvers).
		if noans { // servfail, nxdomain, etc.
			errs = core.JoinErr(errs, errNoAnswer)
			// wind down faster if multiple transports return no answer
			if len(visited) <= tries/2 {
				continue
			} // fallthrough and return current finalans
		}

		t.last.Store(tr)
		return // current finalans
	}

	log.W("plus: [exp: %d / tried: %d]: all transports failed: %v", len(all), len(visited), errs)
	return // finalans probably nil
}

func (t *plus) P50() int64 {
	if l := t.latest(); l != nil {
		return l.P50()
	}
	return 0
}

func (t *plus) GetAddr() string {
	return TransportPrefix(t.ID()) + t.ipports[0].String()
}

func (t *plus) Measure(mid string, n, seconds int32) x.DNSMeasurement {
	return Perf(t, mid, n, seconds)
}

func (t *plus) GetRelay() x.Proxy {
	return nil
}

// Relaying implements dnsx.Transport
func (t *plus) Relaying() bool {
	return false // never implements relays
}

func (t *plus) IPPorts() []netip.AddrPort {
	return t.ipports
}

func (t *plus) GetIPs(id string) string {
	if tr, err := t.GetInternal(id); err == nil {
		return GetIPCsv(tr)
	}
	return ""
}

func (t *plus) Status() int32 {
	if l := t.latest(); l != nil {
		return l.Status()
	}
	return ClientError // see also: bootstrap.go
}

func (t *plus) Stop() error {
	t.done()
	return nil
}

// Add implements TransportMult.
func (t *plus) Add(tr x.DNSTransport) bool {
	if tr == nil || core.IsNil(tr) || t.closed.Load() {
		return false
	}

	newt, ok := tr.(Transport)
	if !ok { // unlikely
		log.W("plus: add %s: cannot cast %T to Transport", tr.ID(), tr)
		return false
	}

	relayingTransport := newt.Relaying()
	if relayingTransport && !plusSupportsRelay {
		log.E("plus: add %s@%s: no relaying transports", newt.ID(), newt.GetAddr())
		return false
	}

	cachingTransport := cachedTransport(newt)
	oldTransportStopped := false
	if !plusSupportsCachedTransports && cachingTransport {
		log.W("plus: add %s@%s: err no cached transports", newt.ID(), newt.GetAddr())
		return false
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if oldt, ok := t.transports[tr.ID()]; ok {
		if core.PtrEq(oldt, newt) {
			log.I("plus: add %s@%s: already present", newt.ID(), newt.GetAddr())
			return true
		}
		core.Gxe("plus.stop."+oldt.ID(), oldt.Stop)
		oldTransportStopped = true
	}

	t.transports[tr.ID()] = newt

	log.I("plus: add %s@%s; old stopped? %t, cacher? %t",
		newt.ID(), newt.GetAddr(), oldTransportStopped, cachingTransport)
	return true
}

// Remove implements TransportMult.
func (t *plus) Remove(id string) (y bool) {
	t.mu.Lock()
	tr := t.transports[id]
	delete(t.transports, id)
	t.mu.Unlock()

	if tr != nil {
		tr.Stop()
		y = true
	}

	log.I("plus: remove: %s? %t", id, y)

	return
}

// Get implements TransportMult.
func (t *plus) Get(id string) (x.DNSTransport, error) {
	return t.GetInternal(id)
}

// GetInternal implements TransportMult.
func (t *plus) GetInternal(id string) (Transport, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if tr, ok := t.transports[id]; ok {
		return tr, nil
	}
	return nil, errNoSuchTransport
}

func (t *plus) refresh() {
	if !plusSupportsCachedTransports {
		return
	}
	for _, t := range t.all() {
		// clear caches of cached transports:
		if ct := asCachedTransport(t); ct != nil {
			ct.Clear() // one at a time ...
		}
	}
}

// Refresh implements TransportMult.
func (t *plus) Refresh() (string, error) {
	// dialers.Clear in transport.go already clears the cache
	// that holds ips <> doh hostnames mapping.
	core.Gx("plus.refresh", t.refresh)
	return t.LiveTransports(), nil
}

// LiveTransports implements TransportMult.
func (t *plus) LiveTransports() string {
	var ids []string
	for _, tr := range t.all() {
		if activeTransport(tr) {
			ids = append(ids, tr.ID())
		}
	}

	return strings.Join(ids, ",")
}

func loged(cond bool) log.LogFn {
	if cond {
		return log.E
	}
	return log.D
}
