// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dns53

import (
	"errors"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

var errStubTransport = errors.New("dns: stub transport")

// TODO: Keep a context here so that queries can be canceled.
type errorer struct {
	id     string
	ipport string
}

var _ dnsx.Transport = (*grounded)(nil)

// NewGroundedTransport returns a DNS transport that blocks all DNS queries.
func NewErrorerTransport(id string) (t dnsx.Transport) {
	t = &grounded{
		id:     id, // typically, dnsx.Fixed
		ipport: "127.3.3.3:33",
	}
	log.I("errorer(%s) setup: %s", t.ID(), t.GetAddr())
	return
}

func (t *grounded) Query(_ string, q *dns.Msg, smm *x.DNSSummary) (*dns.Msg, error) {
	smm.Latency = 0
	smm.RData = xdns.GetInterestingRData(nil)
	smm.RCode = xdns.Rcode(nil)
	smm.RTtl = xdns.RTtl(nil)
	smm.Server = t.GetAddr()
	smm.Status = t.Status()
	smm.Msg = errStubTransport.Error()

	return nil, errStubTransport
}

func (t *grounded) ID() string {
	return t.id
}

func (t *grounded) Type() string {
	return dnsx.DNS53
}

func (t *grounded) P50() int64 {
	return 0
}

func (t *grounded) GetAddr() string {
	return t.ipport
}

func (t *grounded) Status() int {
	return x.ClientError
}

func (*grounded) Stop() error {
	return nil
}
