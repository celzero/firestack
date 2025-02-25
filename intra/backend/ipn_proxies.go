// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package backend

const ( // see ipn/proxies.go
	// IDs for default proxies

	Block    = "Block"        // blocks all traffic
	Base     = "Base"         // does not proxy traffic; in sync w dnsx.NetNoProxy
	Exit     = "Exit"         // always connects to the Internet (exit node); in sync w dnsx.NetExitProxy
	Ingress  = "Ingress"      // incoming connections
	Auto     = "Auto"         // auto uses ipn.Exit or any of the RPN proxies
	RpnWg    = WG + "w" + RPN // RPN Warp
	RpnAmz   = WG + "a" + RPN // RPN Amnezia
	RpnPro   = WG + "p" + RPN // RPN Proton
	RpnWs    = PIPWS + RPN    // RPN WebSockets
	RpnH2    = PIPH2 + RPN    // RPN HTTP/2
	Rpn64    = NAT64 + RPN    // RPN Exit hopping over NAT64
	RpnSE    = SE + RPN       // RPN SurfEasy
	OrbotS5  = "OrbotSocks5"  // Orbot: Base Tor-as-a-SOCKS5 proxy
	OrbotH1  = "OrbotHttp1"   // Orbot: Base Tor-as-a-HTTP/1.1 proxy
	GlobalH1 = "GlobalHttp1"  // Global: Global HTTP/1.1 proxy

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
	NAT64    = "nat64"  // A NAT64 router
	SE       = "se"     // SurfEasy

	// status of proxies

	// proxy UP but not responding
	TNT = 2
	// proxy idle
	TZZ = 1
	// proxy UP but not yet OK
	TUP = 0
	// proxy OK
	TOK = -1
	// proxy not OK
	TKO = -2
	// proxy stopped
	END = -3
)

type Rpn interface {
	// RegisterWarp registers a new Warp installation.
	RegisterWarp(existingStateJson []byte) (json []byte, err error)
	// RegisterSE registers a new SurfEasy user.
	RegisterSE() error
	// RegisterAmnezia registers a new Amnezia installation.
	RegisterAmnezia(existingStateJson []byte) (json []byte, err error)
	// RegisterProton registers a new Proton installation.
	RegisterProton(existingStateJson []byte) (json []byte, err error)
	// UnregisterWarp unregisters a Warp public key.
	UnregisterWarp() bool
	// UnregisterAmnezia unregisters an Amnezia installation.
	UnregisterAmnezia() bool
	// UnregisterProton unregisters a Proton installation.
	UnregisterProton() bool
	// UnregisterSE unregisters a SurfEasy user.
	UnregisterSE() bool
	// TestWarp connects to some Warp IPs and returns reachable ones.
	TestWarp() (ips string, errs error)
	// TestAmnezia connects to the Amnezia gateway and returns its IP if reachable.
	TestAmnezia() (ips string, errs error)
	// TestProton connects to the Proton gateway and returns its IP if reachable.
	TestProton() (ips string, errs error)
	// TestSE connects to some SurfEasy IPs and returns reachable ones.
	TestSE() (ips string, errs error)
	// TestExit64 connects to public NAT64 endpoints and returns reachable ones.
	TestExit64() (ips string, errs error)
	// Warp returns a RpnWg proxy.
	Warp() (wg RpnProxy, err error)
	// Proton returns a Proton WireGuard proxy.
	Proton() (wg RpnProxy, err error)
	// Amnezia returns a Amnezia WireGuard proxy.
	Amnezia() (awg RpnProxy, err error)
	// Pip returns a RpnWs proxy.
	Pip() (ws RpnProxy, err error)
	// Exit64 returns a Exit proxy hopping over NAT64.
	Exit64() (nat64 RpnProxy, err error)
	// SE returns a SurfEasy proxy.
	SE() (se RpnProxy, err error)
}

type Proxy interface {
	// ID returns the ID of this proxy.
	ID() string
	// Type returns the type of this proxy.
	Type() string
	// Returns x.Router.
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

type RpnProxy interface {
	Proxy
	RpnAcc
	// Fork adds proxy for country code, cc.
	Fork(cc string) (Proxy, error)
	// Purge removes proxy for country code, cc.
	Purge(cc string) bool
	// Get returns proxy for country code, cc.
	Get(cc string) (Proxy, error)
	// Kids returns csv of forked proxy PIDs, excluding this one.
	Kids() (csvpids string)
}

type RpnAcc interface {
	// Who returns identifier for this account; may be empty.
	Who() string
	// State returns the state (as json) of the account.
	State() ([]byte, error)
	// Created returns the time (unix millis) currently active account was created.
	Created() int64
	// Expires returns the time (unix millis) currently active account expires.
	Expires() int64
	// Update updates the account creating new state.
	Update() (newstate []byte, err error)
}

type Proxies interface {
	// Add adds a proxy to this multi-transport.
	AddProxy(id, url string) (Proxy, error)
	// Remove removes a transport from this multi-transport.
	RemoveProxy(id string) bool
	// GetProxy returns a transport from this multi-transport.
	GetProxy(id string) (Proxy, error)
	// Hop chains two proxies in the order of origin dialing through via.
	Hop(via, origin string) error
	// Router returns a lowest common denomination router for this multi-transport.
	Router() Router
	// RPN returns the Rethink Proxy Network interface.
	Rpn() Rpn
	// Refresh re-registers proxies and returns a csv of active ones.
	RefreshProxies() (string, error)
}

type Router interface {
	// IP4 returns true if this router supports IPv4.
	IP4() (y bool)
	// IP6 returns true if this router supports IPv6.
	IP6() (y bool)
	// MTU returns the MTU of this router.
	MTU() (mtu int, err error)
	// Stats returns the stats of this router.
	Stat() (s *RouterStats)
	// Via returns the gateway for this router, if any.
	Via() (gw Proxy, err error)
	// Reaches returns true if any host:port or ip:port is dialable.
	Reaches(hostportOrIPPortCsv string) (y bool)
	// Contains returns true if this router can route ipprefix.
	Contains(ipprefix string) (y bool)
}

// ProxyListener is a listener for proxy events.
type ProxyListener interface {
	// OnProxyAdded is called when a proxy is added.
	OnProxyAdded(id string)
	// OnProxyRemoved is called when a proxy is removed except when all
	// proxies are stopped, in which case OnProxiesStopped is called.
	OnProxyRemoved(id string)
	// OnProxyStopped is called when a proxy is stopped.
	OnProxyStopped(id string)
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
