// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/protect"
)

// ground is a proxy that does nothing.
type ground struct {
	protoagnostic
	skiprefresh
	gw
	addr string
}

var _ Proxy = (*ground)(nil)

// NewGroundProxy returns a new ground proxy.
func NewGroundProxy() *ground {
	h := &ground{
		gw:   proxynogateway,
		addr: "[::]:0",
	}
	return h
}

// Handle implements Proxy.
func (h *ground) Handle() uintptr {
	return core.Loc(h)
}

// Dial implements Proxy.
func (h *ground) Dial(network, addr string) (protect.Conn, error) {
	return nil, errNoProxyResponse
}

// Announce implements Proxy.
func (h *ground) Announce(network, local string) (protect.PacketConn, error) {
	return nil, errNoProxyResponse
}

// Accept implements Proxy.
func (h *ground) Accept(network, local string) (protect.Listener, error) {
	return nil, errNoProxyResponse
}

// Probe implements Proxy.
func (h *ground) Probe(network, local string) (protect.PacketConn, error) {
	return nil, errNoProxyResponse
}

func (h *ground) Dialer() protect.RDialer {
	return h // no-op dialer
}

func (h *ground) DNS() string {
	return nodns
}

func (h *ground) ID() string {
	return Block
}

func (h *ground) Type() string {
	return NOOP
}

func (h *ground) Router() x.Router {
	return h
}

func (h *ground) GetAddr() string {
	return h.addr
}

func (h *ground) Status() int {
	return TKO
}

func (h *ground) Stop() error {
	return nil
}
