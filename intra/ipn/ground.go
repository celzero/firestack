// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"net/http"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/protect"
)

type ground struct {
	addr string
}

var _ Proxy = (*ground)(nil)

func NewGroundProxy() *ground {
	h := &ground{
		addr: "[::]:0",
	}
	return h
}

// Dial implements Proxy.
func (h *ground) Dial(network, addr string) (c protect.Conn, err error) {
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

func (h *ground) Dialer() *protect.RDial {
	return &protect.RDial{Owner: h.ID()} // no-op dialer
}

func (h *ground) fetch(req *http.Request) (*http.Response, error) {
	return nil, errNoProxyResponse
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
	return PROXYNOGATEWAY
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

func (h *ground) Refresh() error { return nil }
