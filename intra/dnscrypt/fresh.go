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

// t returns the underlying transport for s.id, or nil if the server has
// been unregistered/removed from the multi-server (e.g. by Remove or
// StopAll).
func (s *severbyid) t() dnsx.Transport {
	if t, err := s.p.GetInternal(s.id); err == nil {
		return t
	}
	return nil
}

// GetRelay implements [dnsx.Transport].
func (s *severbyid) GetRelay() x.Proxy {
	if t := s.t(); t != nil {
		return t.GetRelay()
	}
	return nil
}

// Relaying implements [dnsx.Transport].
func (s *severbyid) Relaying() bool {
	if t := s.t(); t != nil {
		return t.Relaying()
	}
	return false
}

// IPPorts implements [dnsx.Transport].
func (s *severbyid) IPPorts() []netip.AddrPort {
	if t := s.t(); t != nil {
		return t.IPPorts()
	}
	return dnsx.NoIPPort
}

// P50 implements [dnsx.Transport].
func (s *severbyid) P50() int64 {
	if t := s.t(); t != nil {
		return t.P50()
	}
	return 0
}

// Query implements [dnsx.Transport].
func (s *severbyid) Query(network string, q *dns.Msg, summary *x.DNSSummary) (*dns.Msg, error) {
	t := s.t()
	if t == nil {
		return nil, errNoServers
	}
	return t.Query(network, q, summary)
}

// Status implements [dnsx.Transport].
func (s *severbyid) Status() int32 {
	if t := s.t(); t != nil {
		return t.Status()
	}
	// an unregistered server is as good as ended; returning DEnd also
	// prevents resolver.stopIfExistsLocked from spawning a redundant Stop.
	return dnsx.DEnd
}

// Stop implements [dnsx.Transport].
func (s *severbyid) Stop() error {
	if t := s.t(); t != nil {
		return t.Stop()
	}
	// already unregistered/removed; nothing left to stop.
	return nil
}

// Type implements [dnsx.Transport].
func (s *severbyid) Type() string {
	// severbyid is only ever created for DNSCrypt servers (see AddTransport).
	return dnsx.DNSCrypt
}

func (s *severbyid) ID() string {
	return s.id
}

// GetAddr implements [dnsx.Transport].
func (s *severbyid) GetAddr() string {
	if t := s.t(); t != nil {
		return t.GetAddr()
	}
	return dnsx.NoDNS
}

// Measure implements [dnsx.Transport].
func (s *severbyid) Measure(mid string, n, seconds int32) *x.DNSMeasurement {
	return dnsx.Perf(s, mid, n, seconds)
}
