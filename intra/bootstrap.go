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
	"github.com/celzero/firestack/intra/xdns"
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
	ipports        string      // never empty for DNS53
	url            string      // never empty for DOH
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
		} else {
			b.url = ippOrUrl
			b.hostname = parsed.Hostname()
			b.ipports = ipcsv // may be empty
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
		if _, err := xdns.DnsIPPort(ips[0]); err == nil {
			b.url = ""
			b.hostname = protect.UidSelf
			b.ipports = ippOrUrl
			b.typ = dnsx.DNS53
		} else {
			return err
		}
	}

	// hydrate ipmap with the new ips against incoming hostname
	ok := dialers.Renew(b.hostname, strings.Split(b.ipports, ","))

	log.I("dns: default: %s reinit %s %s w/ %s; resolved? %t", trtype, b.url, b.hostname, ipcsv, ok)

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

	if t.Transport != nil {
		log.I("dns: default: removing %s %s[%s]", t.typ, t.GetAddr())
	}

	// always override previous transport with (new) tr; even if nil
	t.Transport = tr
	if err != nil {
		log.E("dns: default: start; err %v", err)
		return err
	}
	if tr == nil {
		log.W("dns: default: start; nil transport %s[%s]", t.typ, t.hostname)
		return nil
	}

	log.I("dns: default: start; %s with %s[%s]", t.typ, t.hostname, t.GetAddr())
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
