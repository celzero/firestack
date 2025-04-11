// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package intra

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"sync"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/dns53"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/doh"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

const (
	// bootid marks the transports as "Protected" with internal
	// hostname to ip cache (in ipmap.go via dnsx.RegisterAddrs)
	bootid = dnsx.Bootstrap
	// protected hostnames are only used by dnsx.DNS53 transport.
	protectedHostname = protect.UidSelf // or protect.UidSystem
	// special hostname is used only by dnsx.Goos transport.
	builtinHostname = protect.Localhost
)

var (
	errDefaultTransportType     = errors.New("unknown default transport type")
	errDefaultTransportNotReady = errors.New("default transport not ready")
	errCannotStart              = errors.New("missing proxies or controller")
)

var (
	localip4 = "127.0.0.1"
	localip6 = "::1"
)

// DefaultDNS is the resolver used by all dialers.
type DefaultDNS interface {
	x.DNSTransport
	kickstart(px ipn.ProxyProvider) error
	reinit(typ, ipOrUrl, ips string) error
}

type bootstrap struct {
	ctx     context.Context
	proxies ipn.ProxyProvider // never nil if underlying transport is set

	mu       sync.RWMutex   // protects following fields:
	tr       dnsx.Transport // the underlying transport
	typ      string         // DOH or DNS53
	ipports  string         // never empty for DNS53
	url      string         // never empty for DOH
	hostname string         // never empty
}

var _ DefaultDNS = (*bootstrap)(nil)
var _ dnsx.Transport = (*bootstrap)(nil)

// NewDefaultDNS creates a new DefaultDNS resolver of type typ. For typ DOH,
// url scheme is http or https; for typ DNS53, url is ipport or csv(ipport).
// ips is a csv of ipports for typ DOH, and nil for typ DNS53.
func NewDefaultDNS(typ, url, ips string) (DefaultDNS, error) {
	b := new(bootstrap)
	b.ctx = context.TODO()

	if err := b.reinit(typ, url, ips); err != nil {
		return nil, err
	}

	// context.AfterFunc(b.ctx, func() { b.Stop() })
	log.I("dns: default: %s new %s %s %s", typ, url, b.hostname, ips)

	return b, nil
}

// NewBuiltinDefaultDNS creates a new DefaultDNS resolver of type dnsx.DNS53.
// It may either use OS provided or network provided DNS resolver, & will not
// work if the tunnel is in "Loopback" mode; create w/ NewDefaultDNS instead.
func NewBuiltinDefaultDNS() (DefaultDNS, error) {
	b := new(bootstrap)
	b.ctx = context.TODO()

	if err := b.reinit("", "", ""); err != nil {
		return nil, err
	}

	// context.AfterFunc(b.ctx, func() { b.Stop() })
	log.I("dns: default: built-in")

	return b, nil
}

func (b *bootstrap) newDefaultDohTransportLocked() (dnsx.Transport, error) {
	ips := strings.Split(b.ipports, ",")
	if len(b.url) > 0 && len(ips) > 0 {
		return doh.NewTransport(b.ctx, bootid, b.url, ips, b.proxies)
	}
	return nil, errCannotStart
}

func (b *bootstrap) newDefaultTransportLocked() (dnsx.Transport, error) {
	if ipcsv := b.ipports; len(ipcsv) > 0 {
		return dns53.NewTransportFromHostname(b.ctx, bootid, b.hostname, ipcsv, b.proxies)
	}
	return nil, errCannotStart
}

func (b *bootstrap) reinit(trtype, ippOrUrl, ipcsv string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(ippOrUrl) <= 0 && len(ipcsv) <= 0 {
		b.url = ""
		b.hostname = builtinHostname // use Goos
		b.ipports = localip4 + "," + localip6
		b.typ = dnsx.DNS53 // ignore trtype
	} else if trtype == dnsx.DOH {
		if len(ippOrUrl) <= 0 {
			log.E("dns: default: reinit: empty url! ips? %s", ipcsv)
			return dnsx.ErrNotDefaultTransport
		}

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
		if len(ippOrUrl) <= 0 {
			log.I("dns: default: reinit: empty ipport %s; using: ", ippOrUrl, ipcsv)
			ippOrUrl = ipcsv
		}
		if len(ippOrUrl) <= 0 {
			log.E("dns: default: reinit: empty url! ips? %s", ipcsv)
			return dnsx.ErrNotDefaultTransport
		}

		// may be set to localhost (in which case it is equivalent to x.Goos)
		// when no other system resolver could be determined
		if strings.HasPrefix(ippOrUrl, builtinHostname) {
			// note: this is not goos; for goos, trtype, ippOrUrl, ipcsv are all empty!
			log.I("dns: default: reinit: loopback %s", ippOrUrl)
			ippOrUrl = localip4 + "," + localip6 // see also dns53/ipmapper.go
		}
		ips := strings.Split(ippOrUrl, ",")
		if len(ips) <= 0 {
			log.E("dns: default: reinit: empty ipport %s", ippOrUrl)
			return dnsx.ErrNotDefaultTransport
		}
		first := ips[0]
		// todo: tests just the first ipport; test all?
		if _, err := xdns.DnsIPPort(first); err != nil {
			return err
		} else {
			b.url = ""
			b.hostname = protectedHostname // override all incoming hostnames
			b.ipports = ippOrUrl           // always ipaddrs or csv(ipaddrs), never empty
			b.typ = dnsx.DNS53
		}
	}

	log.I("dns: default: %s reinit %s %s w/ %s", trtype, b.url, b.hostname, b.ipports)

	// if proxies is set, restart to create new transport
	if b.proxies != nil {
		return b.recreateLocked()
	}
	return nil
}

func (b *bootstrap) recreateLocked() error {
	return b.kickstartLocked(b.proxies) // restart with new proxies
}

func (b *bootstrap) kickstart(px ipn.ProxyProvider) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.kickstartLocked(px)
}

func (b *bootstrap) kickstartLocked(px ipn.ProxyProvider) error {
	if px == nil {
		return errCannotStart
	}

	b.proxies = px
	useGoos := b.hostname == builtinHostname

	var tr dnsx.Transport
	var err error
	switch b.typ {
	case dnsx.DNS53:
		if useGoos {
			tr, err = dns53.NewGoosTransport(b.ctx, px)
		} else {
			tr, err = b.newDefaultTransportLocked()
		}
	case dnsx.DOH:
		tr, err = b.newDefaultDohTransportLocked()
	default:
		err = errDefaultTransportType
	}

	if prev := b.tr; prev != nil {
		go prev.Stop() // stop after new transport is ready
		log.I("dns: default: removing %s %s[%s]; using %s %s",
			b.typ, b.hostname, b.IPPorts(), typstr(tr), ippstr(tr))
	}

	// always override previous transport with (new) tr; even if nil
	b.tr = tr

	if err != nil {
		log.E("dns: default: start; err %v", err)
		return err
	} else if b.tr == nil {
		log.W("dns: default: start; nil transport %s %s", b.typ, b.hostname)
		return errCannotStart
	}

	log.I("dns: default: start; %s with %s[%s]; ok? %t",
		b.typ, b.hostname, b.GetAddr(), len(b.ipports) > 0)
	return nil
}

func (*bootstrap) ID() string {
	// never assume underlying transport's identity
	return dnsx.Default
}

func (b *bootstrap) Type() string {
	return b.typ // DOH or DNS53
}

func (b *bootstrap) Query(network string, q *dns.Msg, smm *x.DNSSummary) (*dns.Msg, error) {
	smm.ID = dnsx.Default
	smm.Type = b.typ
	smm.UID = protect.UidSelf
	if tr := b.tr; tr != nil {
		log.V("dns: default: %s query? %t", network, q != nil)
		return dnsx.Req(tr, network, q, smm)
	}
	smm.Status = dnsx.TransportError // InternalError?
	return nil, errDefaultTransportNotReady
}

func (b *bootstrap) P50() int64 {
	if tr := b.tr; tr != nil {
		return tr.P50()
	}
	return 0
}

func (b *bootstrap) GetAddr() string {
	if tr := b.tr; tr != nil {
		return tr.GetAddr()
	}
	return dnsx.NoDNS
}

func (b *bootstrap) IPPorts() []netip.AddrPort {
	if tr := b.tr; tr != nil {
		return tr.IPPorts()
	}
	return dnsx.NoIPPort
}

func (b *bootstrap) Status() int {
	if tr := b.tr; tr != nil {
		return tr.Status()
	}
	return dnsx.ClientError
}

func (b *bootstrap) Stop() error {
	log.I("dns: default: stopping %s %s", b.typ, b.hostname)
	if tr := b.tr; tr != nil {
		return tr.Stop()
	}
	return nil
}

func typstr(tr dnsx.Transport) string {
	if tr == nil {
		return "<notype>"
	}
	return tr.Type()
}

func ippstr(tr dnsx.Transport) string {
	if tr == nil {
		return "<noaddr>"
	}
	return fmt.Sprintf("%v", tr.IPPorts())
}
