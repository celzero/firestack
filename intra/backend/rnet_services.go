// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package backend

const (
	// type of services

	// SOCKS5
	SVCSOCKS5 = "svcsocks5"
	// HTTP
	SVCHTTP = "svchttp"
	// SOCKS5 with forwarding proxy
	PXSOCKS5 = "pxsocks5"
	// HTTP with forwarding proxy
	PXHTTP = "pxhttp"

	// status of proxies

	// svc UP
	SUP = 0
	// svc OK
	SOK = 1
	// svc not OK
	SKO = -1
	// svc stopped
	SOP = -2
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
	Status() int32
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

type ServerSummary struct {
	// http1, socks5, etc.
	Type string
	// Server ID.
	SID string
	// Proxy ID (hop) that handled egress, if any.
	PID string
	// Connection id
	CID string
	// Total uploaded (bytes).
	Tx int64
	// Total downloaded (bytes).
	Rx int64
	// Conn open duration (millis).
	Duration int64
	// Error messages, if any.
	Msg string
}

// ServerListener receives Server events.
type ServerListener interface {
	// SvcRoute decides how to forward an incoming connection over service (sid).
	SvcRoute(sid, pid, network, sipport, dipport string) *Tab
	// OnSvcComplete reports summary after a connection closes.
	OnSvcComplete(*ServerSummary)
}

type Tab struct {
	// CID is the ID of this connection.
	CID string
	// Block is true if this connection should be blocked.
	Block bool
}
