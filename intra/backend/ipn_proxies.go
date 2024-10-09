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
	Ingress = "Ingress"     // incoming connections
	Auto    = "rpn"         // auto uses ipn.Exit or any of the RPN proxies
	RpnWg   = WG + RPN      // RPN Warp
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
	RPN      = "rpn"    // Rethink Proxy Network

	// status of proxies

	TNT = 2  // proxy UP but not responding
	TZZ = 1  // proxy idle
	TUP = 0  // proxy UP but not yet OK
	TOK = -1 // proxy OK
	TKO = -2 // proxy not OK
	END = -3 // proxy stopped
)

type Rpn interface {
	RegisterWarp(b64 string) ([]byte, error)
}

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
	// Ping pings this proxy.
	Ping() bool
	// Stop stops this proxy.
	Stop() error
	// Refresh re-registers this proxy, if necessary.
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
	// RPN returns the Rethink Proxy Network interface.
	Rpn() Rpn
	// Refresh re-registers proxies and returns a csv of active ones.
	RefreshProxies() (string, error)
}

type Router interface {
	// IP4 returns true if this router supports IPv4.
	IP4() bool
	// IP6 returns true if this router supports IPv6.
	IP6() bool
	// MTU returns the MTU of this router.
	MTU() (int, error)
	// Stats returns the stats of this router.
	Stat() *RouterStats
	// Contains returns true if this router can route ipprefix.
	Contains(ipprefix string) bool
}

// ProxyListener is a listener for proxy events.
type ProxyListener interface {
	// OnProxyAdded is called when a proxy is added.
	OnProxyAdded(id string)
	// OnProxyRemoved is called when a proxy is removed except when all
	// proxies are stopped, in which case OnProxiesStopped is called.
	OnProxyRemoved(id string)
	// OnProxiesStopped is called when all proxies are stopped.
	// Note: OnProxyRemoved is not called for each proxy.
	OnProxiesStopped()
}

// RouterStats lists interesting stats of a Router.
type RouterStats struct {
	Addr   string // address of the router
	Rx     int64  // bytes received
	Tx     int64  // bytes transmitted
	ErrRx  int64  // receive errors
	ErrTx  int64  // transmit errors
	LastRx int64  // last receive in millis
	LastTx int64  // last transmit in millis
	LastOK int64  // last handshake or ping or connect millis
	Since  int64  // uptime in millis
}
