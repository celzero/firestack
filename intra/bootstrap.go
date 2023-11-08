// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package intra

import (
	"errors"
	"net/url"
	"strings"

	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/dns53"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/doh"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
)

const (
	defaultAddrPrefix = "d."
	bootid            = dnsx.BlockFree
)

var (
	errDefaultTransportType     = errors.New("unknown default transport type")
	errDefaultTransportNotReady = errors.New("default transport not ready")
	errCannotStart              = errors.New("missing proxies or controller")
	errAlreadyStarted           = errors.New("already started")
)

type DefaultDNS interface {
	dnsx.Transport
	kickstart(px ipn.Proxies, g Bridge) error
	reinit(typ, ipOrUrl, ips string) error
}

type bootstrap struct {
	dnsx.Transport             // the underlying transport
	proxies        ipn.Proxies // never nil if underlying transport is set
	bridge         Bridge      // never nil if underlying transport is set
	typ            string      // DOH or DNS53
	ipports        string      // never empty
	url            string      // never empty
	hostname       string      // never empty
}

func NewDefaultDNS(typ, url, ips string) (DefaultDNS, error) {
	b := new(bootstrap)

	if err := b.reinit(typ, url, ips); err != nil {
		return nil, err
	}

	log.I("dns: default: %s new %s %s %s", typ, url, b.hostname, ips)

	return b, nil
}

func newDefaultDohTransport(url string, ipcsv string, p ipn.Proxies, g Bridge) (dnsx.Transport, error) {
	ips := strings.Split(ipcsv, ",")
	if len(url) > 0 && len(ips) > 0 {
		return doh.NewTransport(bootid, url, ips, p, g)
	}
	return nil, errCannotStart
}

func newDefaultTransport(ipcsv string, p ipn.Proxies, g Bridge) (dnsx.Transport, error) {
	if len(ipcsv) > 0 {
		specialHostname := protect.UidSelf
		return dns53.NewTransportFromHostname(bootid, specialHostname, ipcsv, p, g)
	}
	return nil, errCannotStart
}

func (b *bootstrap) reinit(typ, u, ipcsv string) error {
	if len(ipcsv) <= 0 {
		log.E("dns: default: reinit: empty url %s / ips %s", u, ipcsv)
		return dnsx.ErrNotDefaultTransport
	}
	if typ != dnsx.DOH || b.typ != dnsx.DNS53 {
		log.E("dns: default: reinit: unknown type %s", b.typ)
		return dnsx.ErrNotDefaultTransport
	}
	if len(u) <= 0 {
		u = protect.UidSelf
	}
	b.url = u // may be localhost or protect.UidSelf; see: ipmap.LookupNetIP
	b.typ = typ
	b.ipports = ipcsv
	ips := strings.Split(ipcsv, ",")
	if len(ips) <= 0 {
		log.E("dns: default: reinit: zero valid ipports in %s (url? %s)", ipcsv, b.url)
		return dnsx.ErrNotDefaultTransport
	}

	b.hostname = b.url // may be a special name like protect.UidSelf
	if parsed, err := url.Parse(b.url); err == nil {
		b.hostname = parsed.Hostname()
	}
	// hydrate ipmap with the new ips against incoming hostname
	ok := dialers.Renew(b.hostname, ips)

	log.I("dns: default: %s reinit %s %s w/ %s; resolved? %t", typ, b.url, b.hostname, ips, ok)

	// if proxies and bridges are set, restart to create new transport
	if b.proxies != nil && b.bridge != nil {
		return b.recreate()
	}
	return nil
}

func (t *bootstrap) recreate() error {
	return t.kickstart(t.proxies, t.bridge)
}

func (t *bootstrap) kickstart(px ipn.Proxies, g Bridge) error {
	if t.Transport != nil {
		return errAlreadyStarted
	}
	if px == nil || g == nil {
		return errCannotStart
	}

	t.proxies = px
	t.bridge = g
	var tr dnsx.Transport
	var err error
	switch t.typ {
	case dnsx.DNS53:
		tr, err = newDefaultTransport(t.ipports, px, g)
	case dnsx.DOH:
		tr, err = newDefaultDohTransport(t.url, t.ipports, px, g)
	default:
		err = errDefaultTransportType
	}

	t.Transport = tr // override previous transport; may be nil
	if err != nil {
		log.E("dns: default: start; err %v", err)
		return err
	}

	log.I("dns: default: start; %s with %s[%s]", t.typ, t.hostname, t.Transport.GetAddr())
	return nil
}

func (t *bootstrap) ID() string {
	// never assume underlying transport's identity
	return dnsx.Default
}

func (t *bootstrap) Type() string {
	return t.typ // DOH or DNS53
}

func (t *bootstrap) Query(network string, q []byte, summary *dnsx.Summary) ([]byte, error) {
	if t.Transport == nil {
		return nil, errDefaultTransportNotReady
	}
	log.V("dns: default: query %s %s", network, len(q))
	return t.Transport.Query(network, q, summary)
}

func (t *bootstrap) P50() int64 {
	if t.Transport == nil {
		return 0
	}
	return t.Transport.P50()
}

func (t *bootstrap) GetAddr() string {
	if t.Transport != nil {
		return defaultAddrPrefix + t.Transport.GetAddr()
	}
	return ""
}

func (t *bootstrap) Status() int {
	if t.Transport == nil {
		return dnsx.ClientError
	}
	return t.Transport.Status()
}
