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

type severbyid struct {
	id string
	p  *DcMulti
}

var _ dnsx.Transport = (*severbyid)(nil)

func (s *severbyid) t() dnsx.Transport {
	if t, err := s.p.GetInternal(s.id); err == nil {
		return t
	}
	panic("refreshingServer: " + s.id + "transport not found")
}

// GetRelay implements [dnsx.Transport].
func (s *severbyid) GetRelay() x.Proxy {
	return s.t().GetRelay()
}

// Relaying implements [dnsx.Transport].
func (s *severbyid) Relaying() bool {
	return s.t().Relaying()
}

// IPPorts implements [dnsx.Transport].
func (s *severbyid) IPPorts() []netip.AddrPort {
	return s.t().IPPorts()
}

// P50 implements [dnsx.Transport].
func (s *severbyid) P50() int64 {
	return s.t().P50()
}

// Query implements [dnsx.Transport].
func (s *severbyid) Query(network string, q *dns.Msg, summary *x.DNSSummary) (*dns.Msg, error) {
	return s.t().Query(network, q, summary)
}

// Status implements [dnsx.Transport].
func (s *severbyid) Status() int32 {
	return s.t().Status()
}

// Stop implements [dnsx.Transport].
func (s *severbyid) Stop() error {
	return s.t().Stop()
}

// Type implements [dnsx.Transport].
func (s *severbyid) Type() string {
	return s.t().Type()
}

func (s *severbyid) ID() string {
	return s.id
}

func (s *severbyid) GetAddr() string {
	return s.t().GetAddr()
}
