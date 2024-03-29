// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
)

const (
	Block   = x.Block
	Base    = x.Base
	Exit    = x.Exit
	OrbotS5 = x.OrbotS5
	OrbotH1 = x.OrbotH1

	SOCKS5   = x.SOCKS5
	HTTP1    = x.HTTP1
	WG       = x.WG
	PIPH2    = x.PIPH2
	PIPWS    = x.PIPWS
	NOOP     = x.NOOP
	INTERNET = x.INTERNET

	TZZ = x.TZZ
	TUP = x.TUP
	TOK = x.TOK
	TKO = x.TKO
	END = x.END

	// DNS addrs, urls, or stamps
	nodns = "" // no DNS
)

var (
	errProxyScheme          = errors.New("unsupported proxy scheme")
	errUnexpectedProxy      = errors.New("unexpected proxy type")
	errAddProxy             = errors.New("add proxy failed")
	errProxyNotFound        = errors.New("proxy not found")
	errMissingProxyOpt      = errors.New("proxyopts nil")
	errNoProxyConn          = errors.New("not a tcp/udp proxy conn")
	errAnnounceNotSupported = errors.New("announce not supported")
	errProxyStopped         = errors.New("proxy stopped")
	errProxyConfig          = errors.New("invalid proxy config")
	errNoProxyResponse      = errors.New("no response from proxy")
	errNoSig                = errors.New("auth missing sig")

	udptimeoutsec = 5 * 60                    // 5m
	tcptimeoutsec = (2 * 60 * 60) + (40 * 60) // 2h40m
)

const (
	tlsHandshakeTimeout   time.Duration = 30 * time.Second // some proxies take a long time to handshake
	responseHeaderTimeout time.Duration = 60 * time.Second
	tzzTimeout            time.Duration = 2 * time.Minute // time between new connections before proxies transition to idle
)

// type checks
var _ Proxy = (*base)(nil)
var _ Proxy = (*exit)(nil)
var _ Proxy = (*socks5)(nil)
var _ Proxy = (*http1)(nil)
var _ Proxy = (*wgproxy)(nil)
var _ Proxy = (*ground)(nil)
var _ Proxy = (*pipws)(nil)
var _ Proxy = (*piph2)(nil)

// Proxy implements the RDialer interface.
var _ protect.RDialer = (Proxy)(nil)

type Proxy interface {
	x.Proxy
	// Dial returns a connection to this proxy.
	Dial(network, addr string) (protect.Conn, error)
	// Announce returns a packet-oriented udp connection on this proxy.
	Announce(network, local string) (protect.PacketConn, error)
	// Accept returns a listener for this proxy.
	Accept(network, local string) (protect.Listener, error)
	// fetch response for this request over HTTP.
	fetch(req *http.Request) (*http.Response, error)
	// Dialer returns the dialer for this proxy, which is an
	// adapter for protect.RDialer interface, but with the caveat that
	// not all Proxy instances implement DialTCP and DialUDP, though are
	// guaranteed to implement Dial.
	Dialer() *protect.RDial
}

type Proxies interface {
	x.Proxies
	// Get returns a transport from this multi-transport.
	ProxyFor(id string) (Proxy, error)
}

type proxifier struct {
	sync.RWMutex
	p   map[string]Proxy
	ctl protect.Controller
	obs x.ProxyListener
}

type gw struct{ ok bool }

var _ x.Router = (*gw)(nil)
var _ x.Router = (*proxifier)(nil)

var _ Proxies = (*proxifier)(nil)
var _ protect.RDialer = (Proxy)(nil)

// PROXYGATEWAY is a Router that routes everything.
var PROXYGATEWAY = &gw{ok: true}

// PROXYNOGATEWAY is a Router that routes nothing.
var PROXYNOGATEWAY = &gw{ok: false}

type nofwd struct{}

// Announce implements Proxy.
func (nofwd) Announce(network, local string) (protect.PacketConn, error) {
	return nil, errAnnounceNotSupported
}

// Accept implements Proxy.
func (nofwd) Accept(network, local string) (protect.Listener, error) {
	return nil, errAnnounceNotSupported
}

func (w *gw) IP4() bool            { return w.ok }
func (w *gw) IP6() bool            { return w.ok }
func (w *gw) Contains(string) bool { return w.ok }

func NewProxifier(c protect.Controller, o x.ProxyListener) Proxies {
	if c == nil || o == nil {
		return nil
	}

	pxr := &proxifier{
		p:   make(map[string]Proxy),
		ctl: c,
		obs: o,
	}
	pxr.add(NewExitProxy(c))  // fixed
	pxr.add(NewBaseProxy(c))  // fixed
	pxr.add(NewGroundProxy()) // fixed
	log.I("proxy: new")

	return pxr
}

func (px *proxifier) add(p Proxy) (ok bool) {
	px.Lock()
	defer px.Unlock()

	if pp := px.p[p.ID()]; pp != nil {
		// new proxy, invoke Stop on old proxy
		if pp != p {
			go pp.Stop()
		}
	}

	px.p[p.ID()] = p
	go px.obs.OnProxyAdded(p.ID())
	return true
}

func (px *proxifier) RemoveProxy(id string) bool {
	px.Lock()
	defer px.Unlock()

	if p, ok := px.p[id]; ok {
		go p.Stop()
		delete(px.p, id)
		go px.obs.OnProxyRemoved(id)
		log.I("proxy: removed %s", id)
		return true
	}
	return false
}

func (px *proxifier) ProxyFor(id string) (Proxy, error) {
	if len(id) <= 0 {
		return nil, errProxyNotFound
	}

	px.RLock()
	defer px.RUnlock()

	if p, ok := px.p[id]; ok {
		return p, nil
	}
	return nil, errProxyNotFound
}

func (px *proxifier) GetProxy(id string) (x.Proxy, error) {
	return px.ProxyFor(id)
}

func (px *proxifier) Router() x.Router {
	return px
}

func (px *proxifier) StopProxies() error {
	px.Lock()
	defer px.Unlock()

	l := len(px.p)
	for _, p := range px.p {
		go p.Stop()
	}
	px.p = make(map[string]Proxy)

	go px.obs.OnProxiesStopped()
	log.I("proxy: all(%d) stopped and removed", l)
	return nil
}

func (px *proxifier) RefreshProxies() (string, error) {
	px.Lock()
	defer px.Unlock()

	var active []string
	for _, p := range px.p {
		if err := p.Refresh(); err != nil {
			log.E("proxy: refresh (%s/%s/%s) failed: %v", p.ID(), p.Type(), p.GetAddr(), err)
			continue
		}
		active = append(active, p.ID())
	}
	return strings.Join(active, ","), nil
}

// Implements Router.
func (px *proxifier) IP4() bool {
	px.RLock()
	defer px.RUnlock()

	for _, p := range px.p {
		if local(p.ID()) {
			continue
		}
		if r := p.Router(); r != nil && !r.IP4() {
			return false
		}
	}
	return len(px.p) > 0
}

// Implements Router.
func (px *proxifier) IP6() bool {
	px.RLock()
	defer px.RUnlock()

	for _, p := range px.p {
		if local(p.ID()) {
			continue
		}
		if r := p.Router(); r != nil && !r.IP6() {
			return false
		}
	}

	return len(px.p) > 0
}

// Implements Router.
func (px *proxifier) Contains(ipprefix string) bool {
	px.RLock()
	defer px.RUnlock()

	for _, p := range px.p {
		// always present local proxies route either everything or
		// nothing: not useful for making routing decisions
		if local(p.ID()) {
			continue
		}
		if r := p.Router(); r != nil && r.Contains(ipprefix) {
			return true
		}
	}
	return false
}

func local(id string) bool {
	return id == Base || id == Block || id == Exit
}

func idling(t time.Time) bool {
	return time.Since(t) > tzzTimeout
}
