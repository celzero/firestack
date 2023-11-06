// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package intra

import (
	"errors"
	"net/netip"
	"strings"

	"github.com/celzero/firestack/intra/dns53"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/doh"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/xdns"
)

const (
	defaultAddrPrefix = "d."
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
	dnsx.Transport                  // the underlying transport
	proxies        ipn.Proxies      // never nil if underlying transport is set
	bridge         Bridge           // never nil if underlying transport is set
	typ            string           // DOH or DNS53
	ipports        []netip.AddrPort // never empty
	url            string           // may be empty
}

func NewDefaultDNS(typ, ippOrUrl, ips string) (DefaultDNS, error) {
	if len(ippOrUrl) <= 0 {
		return nil, dnsx.ErrNotDefaultTransport
	}

	b := new(bootstrap)
	if err := b.reinit(typ, ippOrUrl, ips); err != nil {
		return nil, err
	}

	log.I("dns: default: %s done with %s %s", typ, ippOrUrl, ips)

	return b, nil
}

func newDefaultDohTransport(url string, ipp []netip.AddrPort, p ipn.Proxies, g Bridge) (dnsx.Transport, error) {
	ips := ipport2ipstr(ipp)
	if len(url) > 0 && len(ips) > 0 {
		return doh.NewTransport(dnsx.BlockFree, url, ips, p, g)
	}
	return nil, errCannotStart
}

func newDefaultTransport(ipp []netip.AddrPort, p ipn.Proxies, g Bridge) (dnsx.Transport, error) {
	if len(ipp) > 0 {
		return dns53.NewTransportFrom(dnsx.BlockFree, ipp[0], p, g)
	}
	return nil, errCannotStart
}

func (b *bootstrap) reinit(typ, ippOrUrl, ips string) error {
	b.typ = typ
	b.ipports = make([]netip.AddrPort, 0)
	if b.typ == dnsx.DOH {
		b.url = ippOrUrl
		for _, x := range strings.Split(ips, ",") {
			ipport, err := xdns.DnsIPPort(x)
			if err != nil {
				log.W("dns: default: ignoring invalid ipport %s; err %v", x, err)
				continue
			}
			b.ipports = append(b.ipports, ipport)
		}
	} else if b.typ == dnsx.DNS53 {
		if ipport, err := xdns.DnsIPPort(ippOrUrl); err != nil {
			log.E("dns: default: invalid ipport %s; err %v", ippOrUrl, err)
			return err
		} else {
			b.ipports = append(b.ipports, ipport)
		}
	} else {
		log.E("dns: default: unknown type %s", b.typ)
		return dnsx.ErrNotDefaultTransport
	}

	if len(b.ipports) <= 0 {
		log.E("dns: default: zero valid ipports in %s (url? %s)", ips, b.url)
		return dnsx.ErrNotDefaultTransport
	}

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

	log.I("dns: default: %s with %s", t.typ, t.Transport.GetAddr())
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
	return defaultAddrPrefix + t.ipports[0].String()
}

func (t *bootstrap) Status() int {
	if t.Transport == nil {
		return dnsx.ClientError
	}
	return t.Transport.Status()
}

func ipport2ipstr(ipp []netip.AddrPort) []string {
	ipstr := make([]string, 0, len(ipp))
	for _, x := range ipp {
		if x.IsValid() {
			ipstr = append(ipstr, x.Addr().String())
		}
	}
	return ipstr
}
