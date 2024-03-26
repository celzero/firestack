// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package backend

const ( // see ipn/proxies.go
	// nb: Base proxies are Catch-All / fallback proxies
	// IDs for default proxies
	Block   = "Block"       // blocks all traffic
	Base    = "Base"        // does not proxy traffic; in sync w dnsx.NetNoProxy
	Exit    = "Exit"        // always connects to the Internet (exit node); in sync w dnsx.NetExitProxy
	OrbotS5 = "OrbotSocks5" // Orbot: Base Tor-as-a-SOCKS5 proxy
	OrbotH1 = "OrbotHttp1"  // Orbot: Base Tor-as-a-HTTP/1.1 proxy

	// type of proxies
	SOCKS5   = "socks5" // SOCKS5 proxy
	HTTP1    = "http1"  // HTTP/1.1 proxy
	WG       = "wg"     // WireGuard-as-a-proxy
	WGFAST   = "gsro"   // WireGuard-as-a-proxy w/ UDP GRO/GSO prefix
	PIPH2    = "piph2"  // PIP: HTTP/2 proxy
	PIPWS    = "pipws"  // PIP: WebSockets proxy
	NOOP     = "noop"   // No proxy, ex: Base, Block
	INTERNET = "net"    // egress network, ex: Exit

	// status of proxies
	TZZ = 1  // proxy idle
	TUP = 0  // proxy UP but not yet OK
	TOK = -1 // proxy OK
	TKO = -2 // proxy not OK
	END = -3 // proxy stopped
)

type Proxy interface {
	// ID returns the ID of this proxy.
	ID() string
	// Type returns the type of this proxy.
	Type() string
	// Returns routes.
	Router() Router
	// GetAddr returns the address of this proxy.
	GetAddr() string
	// DNS returns the ip:port or doh/dot url or dnscrypt stamp for this proxy.
	DNS() string
	// Status returns the status of this proxy.
	Status() int
	// Stop stops this proxy.
	Stop() error
	// Refresh re-registers this proxy.
	Refresh() error
}

type Proxies interface {
	// Add adds a proxy to this multi-transport.
	AddProxy(id, url string) (Proxy, error)
	// Remove removes a transport from this multi-transport.
	RemoveProxy(id string) bool
	// GetProxy returns a transport from this multi-transport.
	GetProxy(id string) (Proxy, error)
	// Router returns a lowest common denomination router for this multi-transport.
	Router() Router
	// Stop stops all proxies.
	StopProxies() error
	// Refresh re-registers proxies and returns a csv of active ones.
	RefreshProxies() (string, error)
}

type Router interface {
	IP4() bool
	IP6() bool
	Contains(ipprefix string) bool
}

type ProxyListener interface {
	OnProxyAdded(id string)
	OnProxyRemoved(id string)
	OnProxiesStopped()
}
