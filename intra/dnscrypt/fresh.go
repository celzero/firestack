// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnscrypt

import (
	"net/netip"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/miekg/dns"
)

type refreshingServer struct {
	id string
	p  *DcMulti
}

var _ dnsx.Transport = (*refreshingServer)(nil)

func (s *refreshingServer) t() dnsx.Transport {
	if t, err := s.p.GetInternal(s.id); err == nil {
		return t
	}
	panic("refreshingServer: " + s.id + "transport not found")
}

// GetRelay implements [dnsx.Transport].
func (s *refreshingServer) GetRelay() x.Proxy {
	return s.t().GetRelay()
}

// IPPorts implements [dnsx.Transport].
func (s *refreshingServer) IPPorts() []netip.AddrPort {
	return s.t().IPPorts()
}

// P50 implements [dnsx.Transport].
func (s *refreshingServer) P50() int64 {
	return s.t().P50()
}

// Query implements [dnsx.Transport].
func (s *refreshingServer) Query(network string, q *dns.Msg, summary *x.DNSSummary) (*dns.Msg, error) {
	return s.t().Query(network, q, summary)
}

// Status implements [dnsx.Transport].
func (s *refreshingServer) Status() int {
	return s.t().Status()
}

// Stop implements [dnsx.Transport].
func (s *refreshingServer) Stop() error {
	return s.t().Stop()
}

// Type implements [dnsx.Transport].
func (s *refreshingServer) Type() string {
	return s.t().Type()
}

func (s *refreshingServer) ID() string {
	return s.id
}

func (s *refreshingServer) GetAddr() string {
	return s.t().GetAddr()
}
