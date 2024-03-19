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

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/dns53"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/doh"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/xdns"
)

const (
	bootid          = dnsx.Bootstrap
	specialHostname = protect.UidSelf
)

var (
	errDefaultTransportType     = errors.New("unknown default transport type")
	errDefaultTransportNotReady = errors.New("default transport not ready")
	errCannotStart              = errors.New("missing proxies or controller")
)

// DefaultDNS is the resolver used by all dialers.
type DefaultDNS interface {
	x.DNSTransport
	kickstart(px ipn.Proxies, g Bridge) error
	reinit(typ, ipOrUrl, ips string) error
}

type bootstrap struct {
	dnsx.Transport             // the underlying transport
	proxies        ipn.Proxies // never nil if underlying transport is set
	bridge         Bridge      // never nil if underlying transport is set
	typ            string      // DOH or DNS53
	ipports        string      // never empty for DNS53
	url            string      // never empty for DOH
	hostname       string      // never empty
}

// NewDefaultDNS creates a new DefaultDNS resolver of type typ. For typ DOH,
// url scheme is http or https; for typ DNS53, url is ipport or csv(ipport).
// ips is a csv of ipports for typ DOH, and nil for typ DNS53.
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
		return dns53.NewTransportFromHostname(bootid, specialHostname, ipcsv, p, g)
	}
	return nil, errCannotStart
}

func (b *bootstrap) reinit(trtype, ippOrUrl, ipcsv string) error {
	if len(ippOrUrl) <= 0 {
		log.E("dns: default: reinit: empty url %s! ips? %s", ippOrUrl, ipcsv)
		return dnsx.ErrNotDefaultTransport
	}

	if trtype == dnsx.DOH {
		// note: plain ip4 address is a valid url; ex: 1.2.3.4
		if parsed, err := url.Parse(ippOrUrl); err != nil { // ippOrUrl is a url?
			log.E("dns: default: reinit: not %s url %s", trtype, ippOrUrl)
			return dnsx.ErrNotDefaultTransport
		} else if len(ipcsv) <= 0 {
			// if ips are empty, bootstrap will be stuck in a catch-22 where
			// dialers.New(...) in doh calls back into ipmapper to resolve the hostname
			// in ippOrUrl, which calls into Default DNS (aka bootstrap) via resolver
			// to resolve the hostname in ippOrUrl.
			log.E("dns: default: reinit: doh: empty ips %s", ipcsv)
			return dnsx.ErrNotDefaultTransport
		} else {
			b.url = ippOrUrl
			b.hostname = parsed.Hostname()
			b.ipports = ipcsv // should never be empty
			b.typ = dnsx.DOH
		}
	} else { // ippOrUrl is an ipport?
		if trtype != dnsx.DNS53 {
			log.E("dns: default: reinit: ipport %s; %s != %s", ippOrUrl, trtype, dnsx.DNS53)
			return dnsx.ErrNotDefaultTransport
		}
		ips := strings.Split(ippOrUrl, ",")
		if len(ips) <= 0 {
			log.E("dns: default: reinit: empty ipport %s", ippOrUrl)
			return dnsx.ErrNotDefaultTransport
		}
		// todo: tests just the first ipport; test all?
		if _, err := xdns.DnsIPPort(ips[0]); err != nil {
			return err
		} else {
			b.url = ""
			b.hostname = specialHostname
			b.ipports = ippOrUrl // always ipaddrs or csv(ipaddrs), never empty
			b.typ = dnsx.DNS53
		}
	}

	log.I("dns: default: %s reinit %s %s w/ %s", trtype, b.url, b.hostname, ipcsv)

	// if proxies and bridges are set, restart to create new transport
	if b.proxies != nil && b.bridge != nil {
		return b.recreate()
	}
	return nil
}

func (b *bootstrap) recreate() error {
	return b.kickstart(b.proxies, b.bridge)
}

func (b *bootstrap) kickstart(px ipn.Proxies, g Bridge) error {
	if px == nil || g == nil {
		return errCannotStart
	}

	b.proxies = px
	b.bridge = g
	var tr dnsx.Transport
	var err error
	switch b.typ {
	case dnsx.DNS53:
		tr, err = newDefaultTransport(b.ipports, px, g)
	case dnsx.DOH:
		tr, err = newDefaultDohTransport(b.url, b.ipports, px, g)
	default:
		err = errDefaultTransportType
	}

	if b.Transport != nil {
		log.I("dns: default: removing %s %s[%s]", b.typ, b.hostname, b.GetAddr())
	}

	// always override previous transport with (new) tr; even if nil
	b.Transport = tr
	if err != nil {
		log.E("dns: default: start; err %v", err)
		return err
	}
	if tr == nil {
		log.W("dns: default: start; nil transport %s %s", b.typ, b.hostname)
		return errCannotStart
	}

	log.I("dns: default: start; %s with %s[%s]; ok? %t", b.typ, b.hostname, b.GetAddr(), len(b.ipports) > 0)
	return nil
}

func (*bootstrap) ID() string {
	// never assume underlying transport's identity
	return dnsx.Default
}

func (b *bootstrap) Type() string {
	return b.typ // DOH or DNS53
}

func (b *bootstrap) Query(network string, q []byte, summary *x.DNSSummary) ([]byte, error) {
	tr := b.Transport
	if tr != nil {
		log.V("dns: default: query %s %d", network, len(q))
		return tr.Query(network, q, summary)
	}
	return nil, errDefaultTransportNotReady
}

func (b *bootstrap) P50() int64 {
	tr := b.Transport
	if tr != nil {
		return tr.P50()
	}
	return 0
}

func (b *bootstrap) GetAddr() string {
	tr := b.Transport
	if tr != nil {
		prefix := dnsx.PrefixFor(b.ID())
		return prefix + tr.GetAddr()
	}
	return ""
}

func (b *bootstrap) Status() int {
	tr := b.Transport
	if tr != nil {
		return tr.Status()
	}
	return dnsx.ClientError
}
