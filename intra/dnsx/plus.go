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
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

const plusSupportsCachedTransports = false

const plusMaxTries = 6

const ttl10s = 10 * time.Second

var fakePlusIpports = []netip.AddrPort{
	netip.MustParseAddrPort("[fdaa:9125::9125:9]:53"),
}

type plus struct {
	mu         sync.RWMutex         // protects all
	transports map[string]Transport // id => transport

	r       TransportProviderInternal
	ctx     context.Context
	done    context.CancelFunc
	ipports []netip.AddrPort

	ba *core.Barrier[[]Transport, string]

	closed *core.Volatile[bool]
	last   *core.Volatile[Transport]
}

var _ Transport = (*plus)(nil)
var _ TransportMult = (*plus)(nil)

func NewPlusTransport(ctx context.Context, r TransportProviderInternal, ts ...Transport) Transport {
	ctx, done := context.WithCancel(ctx)
	t := &plus{
		ctx:        ctx,
		transports: make(map[string]Transport, len(ts)),
		ba:         core.NewBarrier[[]Transport](ttl10s),
		r:          r,
		done:       done,
		ipports:    fakePlusIpports,
		closed:     core.NewVolatile(false),
		last:       core.NewZeroVolatile[Transport](),
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
	return flatten(t.transports, all)
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
	return t.r.GetInternal(System) // may return Goos or Default
}

func (t *plus) preferreddns() (Transport, error) {
	return t.r.GetInternal(Preferred) // may return Default
}

func (t *plus) ordered() ([]Transport, error) {
	best, preferred, recov, errored, ended := Categorize(t.all())

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

	if len(ord) <= 0 {
		log.W("plus: zero transports avail [exp: %d]: errored: %v / ended: %v",
			expected, errored, ended)
		return nil, errNoSuchTransport
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

func (t *plus) forward(network string, q *dns.Msg, smm *x.DNSSummary, all ...Transport) (*dns.Msg, error) {
	var errs []error
	tries := plusMaxTries
	visited := make(map[string]struct{}, len(all))
	for _, tr := range all {
		if len(visited) > tries {
			break
		}

		if tr == nil { // unlikely
			errs = append(errs, errNoSuchTransport)
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

		ans, err := tr.Query(network, q, smm)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if xdns.IsServFailOrInvalid(ans) {
			errs = append(errs, errServFail)
			continue
		}
		if !xdns.HasAnyAnswer(ans) {
			errs = append(errs, errNoAnswer)
			// wind down faster if multiple transports return no answer
			if len(visited) >= tries/2 {
				return ans, nil
			}
			continue
		}

		t.last.Store(tr)
		return ans, nil
	}

	log.W("plus: [exp: %d / tried: %d]: all transports failed: %v", len(all), len(visited), errs)
	return nil, core.UniqErr(errs...)
}

func (t *plus) P50() int64 {
	if l := t.latest(); l != nil {
		return l.P50()
	}
	return 0
}

func (t *plus) GetAddr() string {
	return PrefixFor(t.ID()) + t.ipports[0].String()
}

func (t *plus) IPPorts() []netip.AddrPort {
	return t.ipports
}

func (t *plus) Status() int {
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

	cachingTransport := cachedTransport(newt)
	oldTransportStopped := false
	if !plusSupportsCachedTransports && cachingTransport {
		log.W("plus: add %s@%s: err no cached transports", newt.ID(), newt.GetAddr())
		return false
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if oldt, ok := t.transports[tr.ID()]; ok {
		if oldt == newt {
			log.I("plus: add %s@%s: already present", newt.ID(), newt.GetAddr())
			return true
		}
		go oldt.Stop()
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
	t.mu.RLock()
	defer t.mu.RUnlock()

	if tr, ok := t.transports[id]; ok {
		return tr, nil
	}
	return nil, errNoSuchTransport
}

// Refresh implements TransportMult.
func (t *plus) Refresh() (string, error) {
	// no-op as dialers.Clear in transport.go already clears the cache
	// that holds ips <> doh hostnames mapping.
	return t.ID(), nil
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
