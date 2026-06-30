// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package backend

import (
	"fmt"
	"slices"
	"strings"
)

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
	// Rethink Proxy Network (suffix)
	RPN = "rpn"

	// status of proxies

	// proxy paused until resumed; will not dial
	TPU = 3
	// proxy UP but not responding
	TNT = 2
	// proxy idle
	TZZ = 1
	// proxy UP but not yet OK
	TUP = 0
	// proxy OK
	TOK = -1
	// proxy OK but erroring out
	TKO = -2
	// proxy stopped
	END = -3
)

// RpnOps carries options that control the behaviour of Update and RegisterWin.
// Fields are unexported; use the Set* methods to configure.
type RpnOps struct {
	rotateCreds       bool   // force a new WireGuard keypair on the next Update
	permaCreds        bool   // use permanent WireGuard (local) addresses if available
	forceFetchServers bool   // force server-list refresh on the next Update
	newPort           uint16 // fixed WireGuard port; 0 = random per wsRandomPort()
	dnsConfig         string // csv of DNS filter presets: "family", "security", "social", "privacy", "all", "none", "default"
	forceInit         bool   // when false, skips expensive ops unless absolutely required.
	excludeCCs        string // csv of (sorted) country codes to exclude from selection.
}

func NewRpnOps() *RpnOps {
	return &RpnOps{}
}

func (o *RpnOps) String() string {
	return fmt.Sprintf("rotate: %t; perma: %t; forceFetchServers: %t; port: %d; dns: %s; forceInit: %t; excludeCCs: %v",
		o.rotateCreds, o.permaCreds, o.forceFetchServers, o.newPort, o.dnsConfig, o.forceInit, o.excludeCCs)
}

// SetRotateCreds forces generation of a new WireGuard keypair on the next Update.
// Note: Rotate and Perma are mutually exclusive; setting one to true will set the other to false.
func (o *RpnOps) SetRotateCreds(v bool) { o.rotateCreds = v; o.permaCreds = false }

// SetPermaCreds enables/disables using the permanent WG credential set in Conf().
// Note: Rotate and Perma are mutually exclusive; setting one to true will set the other to false.
func (o *RpnOps) SetPermaCreds(v bool) { o.permaCreds = v; o.rotateCreds = false }

// SetForceFetchServers forces the server-list refresh on the next Update.
func (o *RpnOps) SetForceFetchServers(v bool) { o.forceFetchServers = v }

// SetPort pins a specific WireGuard port; 0 means random (default).
func (o *RpnOps) SetPort(port int32) {
	if port >= 0 && port <= 65535 {
		o.newPort = uint16(port)
	}
}

// SetDNSConfig sets the DNS filter preset configuration.
// v is a csv of filter presets: "family", "security", "social", "privacy", "all", "none", "default".
// "none" and "default" are aliases that disable all filters. Leave it empty for no-op.
func (o *RpnOps) SetDNSConfig(v string) {
	o.dnsConfig = v
}

// SetForceInit controls whether Update forces expensive re-setup.  When false,
// expensive ops are skipped if called within some threshold of the previous call.
func (o *RpnOps) SetForceInit(v bool) { o.forceInit = v }

// SetExcludeCCs sets a CSV of country codes to exclude from CC selection.
// Empty or whitespace entries are ignored; codes are normalised to upper-case.
func (o *RpnOps) SetExcludeCCs(v string) {
	if len(v) <= 0 {
		o.excludeCCs = ""
		return
	}

	parts := slices.Sorted(strings.SplitSeq(v, ","))
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToUpper(strings.TrimSpace(p))
		if len(p) > 0 {
			out = append(out, p)
		}
	}
	o.excludeCCs = strings.Join(out, ",")
}

// ExcludeCCs returns the CSV of country codes excluded from CC selection.
func (o RpnOps) ExcludeCCs() (csv string) { return o.excludeCCs }

// Rotate reports whether a new WG keypair should be generated.
func (o RpnOps) Rotate() bool { return o.rotateCreds }

// Perma reports whether permanent WG credentials should be used in Conf().
func (o RpnOps) Perma() bool { return o.permaCreds }

// FetchServers reports whether the server-list fetch should be forced.
func (o RpnOps) FetchServers() bool { return o.forceFetchServers }

// Port returns the pinned WireGuard port, or 0 if none is set.
func (o RpnOps) Port() uint16 {
	return o.newPort
}

// DNSConfig returns the DNS filter preset configuration csv.
func (o RpnOps) DNSConfig() string {
	return o.dnsConfig
}

// ForceInit returns false if expensive update ops may be skipped if approp.
func (o RpnOps) ForceInit() bool { return o.forceInit }

// ExcludeCCs returns csv of (to be) sorted excluded country codes.
func (o RpnOps) GetExcludeCCs() string { return o.excludeCCs }

// ChangesConfig reports whether this RpnOps would cause a change in wg config
// if applied to override "other".
func (o RpnOps) ChangesConfig(other RpnOps) bool {
	return o.rotateCreds != other.rotateCreds ||
		o.permaCreds != other.permaCreds ||
		o.newPort != other.newPort ||
		// excludeccs would cause change in wg config (RegionalWgConfs) in
		// needing to "purge" out existing countries to be excluded, if any.
		// (excludedccs is a sorted csv and so string equality should work)
		o.excludeCCs != other.excludeCCs
}

type Rpn interface {
	// EntitlementFrom returns the RpnEntitlement represented by entitlementOrStateJson.
	// `did` is the device identifier to use for this entitlement, if applicable; and `rpnProviderID` is the RPN provider for this entitlement, if applicable.
	// `rpnProviderID` is the RPN provider to use with this entitlement (ex: RpnWin, etc).
	EntitlementFrom(entitlementOrStateJson []byte, rpnProviderID, did string) (RpnEntitlement, error)
	// RegisterWin registers (or re-registers) a Windscribe account.
	// ops may be nil to use default behaviour.
	RegisterWin(entitlementOrStateJson []byte, did string, ops *RpnOps) (json []byte, err error)
	// UnregisterWin unregisters a Windscribe installation.
	UnregisterWin() bool
	// TestWin connects to the Windscribe gateway and returns its IP if reachable.
	TestWin() (ips string, errs error)
	// TestExit64 connects to public NAT64 endpoints and returns reachable ones.
	TestExit64() (ips string, errs error)
	// Win returns a Windscribe WireGuard proxy.
	Win() (wg RpnProxy, err error)
	// Pip returns a RpnWs proxy.
	Pip() (ws RpnProxy, err error)
	// Exit64 returns a Exit proxy hopping over preset publicly-available
	// NAT64 proxies.
	Exit64() (nat64 RpnProxy, err error)
}

type Proxy interface {
	// ID returns the ID of this proxy.
	ID() string
	// Type returns the type of this proxy.
	Type() string
	// Returns x.Router.
	Router() Router
	// Client returns a client that uses this proxy.
	Client() Client
	// GetAddr returns the address of this proxy.
	GetAddr() string
	// DNS returns the ip:port or doh/dot url or dnscrypt stamp for this proxy.
	DNS() string
	// Status returns the status of this proxy.
	Status() int
	// Ping pings this proxy.
	Ping() bool
	// Pause pauses this proxy.
	Pause() bool
	// Resume resumes this proxy.
	Resume() bool
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
	// Redo re-forks the main proxy and all its kids.
	Redo() (err error)
	// PingAll pings the main proxy and all its kids.
	PingAll() (csvpids string, err error)
	// Purge removes proxy for country code, cc.
	Purge(cc string) bool
	// Has returns true if a proxy for country code, cc, has been forked.
	Has(cc string) bool
	// Get returns proxy for country code, cc.
	Get(cc string) (Proxy, error)
	// Kids returns RpnServers describing all forked kids, excluding the main proxy.
	Kids() RpnServers
	// Main returns RpnServer describing the main proxy, if present.
	Main() *RpnServer
}

// RpnAcc represents an account with RPN provider.
type RpnAcc interface {
	// Who returns identifier for this account; may be empty.
	Who() string
	// State returns the state (as json) of the account.
	State() ([]byte, error)
	// Ops returns the RpnOps that control the behaviour of Update.
	Ops() *RpnOps
	// Created returns the time (unix millis) currently active account was created.
	Created() int64
	// Updated returns the time (unix millis) currently active account was updated.
	Updated() int64
	// Expires returns the time (unix millis) currently active account expires.
	Expires() int64
	// Locations returns RpnServers encapsulating this proxy's worldwide server presence.
	Locations() (RpnServers, error)
	// Update updates the account creating new state; ops may be nil to retain current RpnOps.
	Update(ops *RpnOps) (newstate []byte, err error)
}

// RpnEntitlement represents access to a proxy service.
type RpnEntitlement interface {
	// ProviderID is RPN provider for this entitlement.
	ProviderID() string
	// Cid is the Client identifier.
	CID() string
	// DID is the Device identifier, if any.
	DID() string
	// Token is the entitlement token, if any.
	Token() string
	// Expiry is the expiry time of this entitlement in Unix milliseconds, if any.
	Expiry() int64
	// "valid", "invalid", "banned", "expired", "unknown"
	Status() string
	// AllowRestore returns true if this entitlement can be transferred around for restores.
	AllowRestore() bool
	// Test is set if this entitlement is valid only in the test domain.
	Test() bool
	// Json returns entitlement (but not the state) as json.
	Json() ([]byte, error)
}

type Proxies interface {
	// Underlay creates a [NOOP] proxy (that always connects over underlying network),
	// but one that uses a custom Controller.
	// This proxy is not tracked (APIs like GetProxy won't return these).
	Underlay(id string, c Controller) Proxy
	// Add adds a proxy to this multi-transport.
	// "id" is a free-form unique identifier for this proxy, except:
	// "id" for WireGuard proxies must be prefixed with [WG]
	// "url" is WireGuard UAPI configuration.
	// For HTTP1 and SOCKS5 proxies, "url" must be of the form:
	// scheme://usr:pwd@domain.tld:port/p/a/t/h?q&u=e&r=y#f,r
	// where scheme is "http" or "socks5", usr and/or pwd are optional
	// port is the port number, and domain.tld could also be ip address.
	AddProxy(id, url string) (Proxy, error)
	// Remove removes a transport from this multi-transport.
	RemoveProxy(id string) bool
	// HasProxy returns true if a proxy with the given id is registered.
	HasProxy(id string) bool
	// GetProxy returns a transport from this multi-transport.
	GetProxy(id string) (Proxy, error)
	// TestHop returns empty diag if origin can hop to via,
	// otherwise returns a diagnosis of why it couldn't.
	// Only WireGuard via & origin are supported, for now.
	TestHop(via, origin string) (diag string)
	// Hop chains two proxies in the order of origin dialing through via.
	// Only WireGuard via & origin are supported, for now.
	Hop(via, origin string) error
	// Router returns a lowest common denomination router for this multi-transport.
	Router() Router
	// RPN returns the Rethink Proxy Network api.
	Rpn() Rpn
	// Refresh re-registers proxies and returns a csv of active ones.
	RefreshProxies() string
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

type Client interface {
	// IP4 returns information about this client's remote IPv4.
	IP4() (*IPMetadata, error)
	// IP6 returns information about this client's remote IPv6.
	IP6() (*IPMetadata, error)
	// TODO: Move Reaches here?
	// TODO: Fetch(method, url, headers, body) (status, headers, body, err)
}

// TODO: use type, handler uint64
// ProxyListener is a listener for proxy events.
type ProxyListener interface {
	// OnProxyAdded is called when a proxy is added.
	OnProxyAdded(id, handle string)
	// OnProxyRemoved is called when a proxy is removed except when all
	// proxies are stopped, in which case OnProxiesStopped is called.
	OnProxyRemoved(id, handle string)
	// OnProxyUpdated is called when a proxy's configuration is updated.
	OnProxyUpdated(id, handle string)
	// OnProxyStopped is called when a proxy is stopped instead of being
	// removed (that is, this callback is not called in all proxy stop scenarios).
	// A stopped proxy, if added again, is replaced/updated instead; and subsequently,
	// the onProxyAdded callback is invoked.
	OnProxyStopped(id, handle string)
	// OnProxiesStopped is called when all proxies are stopped.
	// Note: OnProxyRemoved is not called for each proxy, even
	// if they are removed instead of being merely "stopped".
	OnProxiesStopped()
}

// RouterStats lists interesting stats of a Router.
type RouterStats struct {
	Hdl string
	// addresses (csv) of the router
	Addrs string
	// bytes received
	Rx int64
	// bytes transmitted
	Tx int64
	// receive error count
	ErrRx int64
	// transmit error count
	ErrTx int64
	// last (most recent) receive in millis
	LastTx int64
	// last (most recent) transmit in millis
	LastRx int64
	// last non-wg (connect/dial) error
	LastErr string
	// last wg recv (read) error
	LastRxErr string
	// last wg send (write) error
	LastTxErr string
	// last successful receive in millis
	LastGoodRx int64
	// last successful transmit in millis
	LastGoodTx int64
	// last (most recent) handshake or ping or connect millis
	LastOK int64
	// last refresh time in millis
	LastRefresh int64
	// last re-connection opened in unix millis
	LastOpen int64
	// uptime in millis
	Since int64
	// Current proxy status
	Status string
	// Current reason for Status
	StatusReason string
	// Extra is extra info about this router
	Extra string
}

type RpnServers interface {
	// Get returns the RpnServer at index i; errors if i is out of bounds.
	Get(i int) (*RpnServer, error)
	// Len returns the number of RpnServers.
	Len() int
	// Json returns the RpnServer struct as JSON bytes.
	Json() ([]byte, error)
}

type RpnServer struct {
	// Name of the server, if any.
	Name string
	// CSV of IP:Port and/or Domain:Port
	Addrs string
	// CSV of IP subnets allowed to be used by this server.
	Allowed string
	// Public key pair for this peer (WireGuard).
	PubPub string
	// Country code of the location.
	CC string
	// City name of the location.
	City string
	// Key for RpnProxy.Fork() to get an RpnProxy instance for this RpnServer.
	Key string
	// Load score of this server (lower is better)
	Load int32
	// Link speed in Mbps (higher is better).
	Link int32
	// Number of active servers in this CC+City.
	Count int32
	// Premium server
	Premium bool
	// Excluded by end-user
	Excluded bool
}

type IPMetadata struct {
	// Proxy ID used to fetch this IP metadata.
	ID string
	// Provider that provided this IP metadata.
	ProviderURL string
	// IP address, never empty.
	IP string
	// ASN number, may be empty.
	ASN string
	// ASN organization name, may be empty.
	ASNOrg string
	// ASN domain, may be empty.
	ASNDom string
	// Country code, may be empty.
	CC string
	// City name, may be empty.
	City string
	// Address, may be empty.
	Addr string
	// Latitude, may be zero.
	Lat float64
	// Longitude, may be zero.
	Lon float64
}
