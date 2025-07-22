// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package backend

const ( // see ipn/proxies.go
	// IDs for default proxies

	// blocks all traffic (built-in)
	Block = "Block"
	// may send traffic out via underlying network (built-in)
	// see: tun2socks.Loopback; alias for dnsx.NetNoProxy
	Base = "Base"
	// always sends traffic out via underlying network (built-in)
	// see: Controller.Protect; alias for dnsx.NetExitProxy
	Exit = "Exit"
	// proxies incoming connections (built-in)
	Ingress = "Ingress"
	// Auto uses ipn.Exit or any of the RPN proxies (built-in)
	Auto = "Auto"
	// RPN Warp (must be registered by Rpn.RegisterWarp)
	RpnWg = WG + "w" + RPN
	// RPN Amnezia (must be registered by Rpn.RegisterAmnezia)
	RpnAmz = WG + "a" + RPN
	// RPN Win proxy (must be registered by Rpn.RegisterWin)
	RpnWin = WG + "y" + RPN
	// Alias for RPN Win
	RpnPro = RpnWin
	// RPN WebSockets (unused)
	RpnWs = PIPWS + RPN
	// RPN HTTP/2 (unused)
	RpnH2 = PIPH2 + RPN
	// RPN Exit hopping over NAT64 (built-in)
	Rpn64 = NAT64 + RPN
	// RPN SurfEasy (must be registered by Rpn.RegisterSE)
	RpnSE = SE + RPN
	// Orbot: Base Tor-as-a-SOCKS5 proxy
	OrbotS5 = "OrbotSocks5"
	// Orbot: Base Tor-as-a-HTTP/1.1 proxy
	OrbotH1 = "OrbotHttp1"
	// Global: HTTP/1.1 proxy if required by underlying network.
	GlobalH1 = "GlobalHttp1"

	// type of proxies

	// SOCKS5 proxy type
	SOCKS5 = "socks5"
	// HTTP/1.1 proxy type
	HTTP1 = "http1"
	// WireGuard-as-a-proxy type and prefix
	WG = "wg"
	// No proxy (uses underlying network), ex: Base, Block, Ingress
	NOOP = "noop"
	// Egress, ex: Exit
	INTERNET = "net"
	// WireGuard-as-a-proxy w/ UDP GRO/GSO prefix (experimental)
	WGFAST = "gsro"
	// PIP: HTTP/2 proxy prefix (unused)
	PIPH2 = "piph2"
	// PIP: WebSockets proxy prefix (unused)
	PIPWS = "pipws"
	// A NAT64 router (prefix)
	NAT64 = "nat64"
	// SurfEasy proxy (prefix)
	SE = "se"
	// Rethink Proxy Network (suffix)
	RPN = "rpn"

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
	RegisterWarp(existingStateJson *Gobyte) (json *Gobyte, err error)
	// RegisterSE registers a new SurfEasy user.
	RegisterSE() error
	// RegisterAmnezia registers a new Amnezia installation.
	RegisterAmnezia(existingStateJson *Gobyte) (json *Gobyte, err error)
	// RegisterProton is alias for RegisterWin.
	RegisterProton(entitlementOrStateJson *Gobyte) (json *Gobyte, err error)
	// RegisterWin is alias for RegisterWin.
	RegisterWin(entitlementOrStateJson *Gobyte) (json *Gobyte, err error)
	// UnregisterWarp unregisters a Warp public key.
	UnregisterWarp() bool
	// UnregisterAmnezia unregisters an Amnezia installation.
	UnregisterAmnezia() bool
	// UnregisterProton is an alias for UnregisterWin.
	UnregisterProton() bool
	// UnregisterWin unregisters a Windscribe installation.
	UnregisterWin() bool
	// UnregisterSE unregisters a SurfEasy user.
	UnregisterSE() bool
	// TestWarp connects to some Warp IPs and returns reachable ones.
	TestWarp() (ips *Gostr, errs error)
	// TestAmnezia connects to the Amnezia gateway and returns its IP if reachable.
	TestAmnezia() (ips *Gostr, errs error)
	// TestWin connects to the Windscribe gateway and returns its IP if reachable.
	TestWin() (ips *Gostr, errs error)
	// TestProton is an alias for TestWin.
	TestProton() (ips *Gostr, errs error)
	// TestSE connects to some SurfEasy IPs and returns reachable ones.
	TestSE() (ips *Gostr, errs error)
	// TestExit64 connects to public NAT64 endpoints and returns reachable ones.
	TestExit64() (ips *Gostr, errs error)
	// Warp returns a Cloudflare Warp WireGuard proxy.
	Warp() (wg RpnProxy, err error)
	// Win returns a Windscribe WireGuard proxy.
	Win() (wg RpnProxy, err error)
	// Proton is an alias for Win.
	Proton() (wg RpnProxy, err error)
	// Amnezia returns a Amnezia WireGuard proxy.
	Amnezia() (awg RpnProxy, err error)
	// Pip returns a RpnWs proxy.
	Pip() (ws RpnProxy, err error)
	// Exit64 returns a Exit proxy hopping over preset publicly-available
	// NAT64 proxies.
	Exit64() (nat64 RpnProxy, err error)
	// SE returns a SurfEasy proxy.
	SE() (se RpnProxy, err error)
}

type Proxy interface {
	// ID returns the ID of this proxy.
	ID() *Gostr
	// Type returns the type of this proxy.
	Type() *Gostr
	// Returns x.Router.
	Router() Router
	// GetAddr returns the address of this proxy.
	GetAddr() *Gostr
	// DNS returns the ip:port or doh/dot url or dnscrypt stamp for this proxy.
	DNS() *Gostr
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
	Fork(cc *Gostr) (Proxy, error)
	// Purge removes proxy for country code, cc.
	Purge(cc *Gostr) bool
	// Get returns proxy for country code, cc.
	Get(cc *Gostr) (Proxy, error)
	// Kids returns csv of forked proxy PIDs, excluding this one.
	Kids() (csvpids *Gostr)
}

type RpnAcc interface {
	// Who returns identifier for this account; may be empty.
	Who() *Gostr
	// State returns the state (as json) of the account.
	State() (*Gobyte, error)
	// Created returns the time (unix millis) currently active account was created.
	Created() int64
	// Expires returns the time (unix millis) currently active account expires.
	Expires() int64
	// Locations returns RpnServers encapsulating this proxy's worldwide server presence.
	Locations() (RpnServers, error)
	// Update updates the account creating new state.
	Update() (newstate *Gobyte, err error)
}

type Proxies interface {
	// Underlay creates a [NOOP] proxy (that always connects over underlying network),
	// but one that uses a custom Controller.
	// This proxy is not tracked (APIs like GetProxy won't return these).
	Underlay(id *Gostr, c Controller) Proxy
	// Add adds a proxy to this multi-transport.
	// "id" is a free-form unique identifier for this proxy, except:
	// "id" for WireGuard proxies must be prefixed with [WG]
	// "url" is WireGuard UAPI configuration.
	// For HTTP1 and SOCKS5 proxies, "url" must be of the form:
	// scheme://usr:pwd@domain.tld:port/p/a/t/h?q&u=e&r=y#f,r
	// where scheme is "http" or "socks5", usr and/or pwd are optional
	// port is the port number, and domain.tld could also be ip address.
	AddProxy(id, url *Gostr) (Proxy, error)
	// Remove removes a transport from this multi-transport.
	RemoveProxy(id *Gostr) bool
	// GetProxy returns a transport from this multi-transport.
	GetProxy(id *Gostr) (Proxy, error)
	// TestHop returns empty diag if origin can hop to via,
	// otherwise returns a diagnosis of why it couldn't.
	// Only WireGuard via & origin are supported, for now.
	TestHop(via, origin *Gostr) (diag *Gostr)
	// Hop chains two proxies in the order of origin dialing through via.
	// Only WireGuard via & origin are supported, for now.
	Hop(via, origin *Gostr) error
	// Router returns a lowest common denomination router for this multi-transport.
	Router() Router
	// RPN returns the Rethink Proxy Network api.
	Rpn() Rpn
	// Refresh re-registers proxies and returns a csv of active ones.
	RefreshProxies() (*Gostr, error)
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
	Reaches(hostportOrIPPortCsv *Gostr) (y bool)
	// Contains returns true if this router can route ipprefix.
	Contains(ipprefix *Gostr) (y bool)
}

// ProxyListener is a listener for proxy events.
type ProxyListener interface {
	// OnProxyAdded is called when a proxy is added.
	OnProxyAdded(id *Gostr)
	// OnProxyRemoved is called when a proxy is removed except when all
	// proxies are stopped, in which case OnProxiesStopped is called.
	OnProxyRemoved(id *Gostr)
	// OnProxyStopped is called when a proxy is stopped.
	OnProxyStopped(id *Gostr)
	// OnProxiesStopped is called when all proxies are stopped.
	// Note: OnProxyRemoved is not called for each proxy.
	OnProxiesStopped()
}

// RouterStats lists interesting stats of a Router.
type RouterStats struct {
	// address of the router
	Addr string
	// bytes received
	Rx int64
	// bytes transmitted
	Tx int64
	// receive errors
	ErrRx int64
	// transmit errors
	ErrTx int64
	// last (most recent) receive in millis
	LastRx int64
	// last (most recent) transmit in millis
	LastTx int64
	// last (most recent) handshake or ping or connect millis
	LastOK int64
	// uptime in millis
	Since int64
}

type RpnServers interface {
	// Get returns the RpnServer at index i; errors if i is out of bounds.
	Get(i int) (*RpnServer, error)
	// Len returns the number of RpnServers.
	Len() int
	// Json returns the RpnServer struct as JSON bytes.
	Json() (*Gobyte, error)
}

type RpnServer struct {
	// Name of the server, if any.
	Name string
	// CSV of IP:Port and/or Domain:Port
	Addrs string
	// Country code of the location.
	CC string
	// TODO: number of servers, health, link speed, etc?
}
