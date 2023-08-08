// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"errors"
	"strings"
	"sync"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
)

const (
	// IDs for default proxies
	Block    = "Block"       // proxy that blocks all traffic
	Base     = "Base"        // proxy that does not proxy traffic
	Grounded = "Grounded"    // proxy that blocks all traffic
	OrbotS5  = "OrbotSocks5" // Orbot: Tor-as-a-SOCKS5 proxy
	OrbotH1  = "OrbotHttp1"  // Orbot: Tor-as-a-HTTP/1.1 proxy

	// type of proxies
	SOCKS5 = "socks5" // SOCKS5 proxy
	HTTP1  = "http1"  // HTTP/1.1 proxy
	WG     = "wg"     // WireGuard-as-a-proxy
	PIPH2  = "piph2"  // PIP: HTTP/2 proxy
	PIPWS  = "pipws"  // PIP: WebSockets proxy
	NOOP   = "noop"   // No proxy

	// status of proxies
	TOK = 0  // proxy OK
	TKO = -1 // proxy not OK
	END = -2 // proxy stopped
)

var (
	errProxyScheme     = errors.New("unsupported proxy scheme")
	errUnexpectedProxy = errors.New("unexpected proxy type")
	errAddProxy        = errors.New("add proxy failed")
	errProxyNotFound   = errors.New("proxy not found")
	errMissingProxyOpt = errors.New("proxyopts nil")
	errNoProxyConn     = errors.New("not a tcp/udp proxy conn")
	errProxyStopped    = errors.New("proxy stopped")
	errProxyConfig     = errors.New("invalid proxy config")
	errNoProxyResponse = errors.New("no response from proxy")
	errNoSig           = errors.New("auth missing sig")

	udptimeoutsec = 5 * 60                    // 5m
	tcptimeoutsec = (2 * 60 * 60) + (40 * 60) // 2h40m
)

// type checks
var _ Proxy = (*base)(nil)
var _ Proxy = (*socks5)(nil)
var _ Proxy = (*http1)(nil)
var _ Proxy = (*wgproxy)(nil)
var _ Proxy = (*ground)(nil)

// Adapter to keep gomobile happy as it can't export net.Conn
type Conn interface {
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	Close() error
}

type Proxy interface {
	// Dial creates a new connection to the given address.
	// gomobile cannot export proxy.Dialer (net.Conn)
	Dial(network, addr string) (Conn, error)
	// ID returns the ID of this proxy.
	ID() string
	// Type returns the type of this proxy.
	Type() string
	// GetAddr returns the address of this proxy.
	GetAddr() string
	// Status returns the status of this proxy.
	Status() int
	// Stop stops this proxy.
	Stop() error
}

type Proxies interface {
	// Add adds a proxy to this multi-transport.
	AddProxy(id, url string) (Proxy, error)
	// Remove removes a transport from this multi-transport.
	RemoveProxy(id string) bool
	// Get returns a transport from this multi-transport.
	GetProxy(id string) (Proxy, error)
	// Stop stops all proxies.
	StopProxies() error
	// Refresh re-registers proxies and returns a csv of active ones.
	RefreshProxies() (string, error)
}

type proxifier struct {
	Proxies
	sync.RWMutex
	p   map[string]Proxy
	ctl protect.Controller
}

func NewProxifier(c protect.Controller) Proxies {
	pxr := &proxifier{
		p:   make(map[string]Proxy),
		ctl: c,
	}
	pxr.add(NewBaseProxy(c))
	pxr.add(NewGroundProxy())
	log.I("proxy: new")

	return pxr
}

func (px *proxifier) add(p Proxy) bool {
	px.Lock()
	defer px.Unlock()

	if pp, ok := px.p[p.ID()]; ok {
		// new proxy, invoke Stop on old proxy
		if pp != p {
			go pp.Stop()
		}
	}

	px.p[p.ID()] = p
	return true
}

func (px *proxifier) RemoveProxy(id string) bool {
	px.Lock()
	defer px.Unlock()

	if p, ok := px.p[id]; ok {
		go p.Stop()
		delete(px.p, id)
		log.I("proxy: removed %s", id)
		return true
	}
	return false
}

func (px *proxifier) GetProxy(id string) (Proxy, error) {
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

func (px *proxifier) StopProxies() error {
	px.Lock()
	defer px.Unlock()

	l := len(px.p)
	for _, p := range px.p {
		go p.Stop()
	}
	px.p = make(map[string]Proxy)

	log.I("proxy: all(%d) stopped and removed", l)
	return nil
}

func (px *proxifier) RefreshProxies() (string, error) {
	px.Lock()
	defer px.Unlock()

	var active []string
	for _, p := range px.p {
		active = append(active, p.ID())
	}
	return strings.Join(active, ","), nil
}
