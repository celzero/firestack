// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package backend

const (
	// type of services
	SVCSOCKS5 = "svcsocks5" // SOCKS5
	SVCHTTP   = "svchttp"   // HTTP
	PXSOCKS5  = "pxsocks5"  // SOCKS5 with forwarding proxy
	PXHTTP    = "pxhttp"    // HTTP with forwarding proxy

	// status of proxies
	SUP = 0  // svc UP
	SOK = 1  // svc OK
	SKO = -1 // svc not OK
	SOP = -2 // svc stopped
)

type Server interface {
	// Sets the proxy as the next hop.
	Hop(p Proxy) error
	// ID returns the ID of the server.
	ID() string
	// Start starts the server.
	Start() error
	// Type returns the type of the server.
	Type() string
	// Addr returns the address of the server.
	GetAddr() string
	// Status returns the status of the server.
	Status() int
	// Stop stops the server.
	Stop() error
	// Refresh re-registers the server.
	Refresh() error
}

type Services interface {
	// Add adds a server.
	AddServer(id, url string) (Server, error)
	// Bridge bridges or unbridges server with proxy.
	Bridge(serverid, proxyid string) error
	// Remove removes a server.
	RemoveServer(id string) (ok bool)
	// RemoveAll removes all servers.
	RemoveAll()
	// Get returns a Server.
	GetServer(id string) (Server, error)
	// Refresh re-registers servces and returns a csv of active ones.
	RefreshServers() (active string)
}
