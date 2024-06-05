// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dns53

import (
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

// TODO: Keep a context here so that queries can be canceled.
type grounded struct {
	id     string
	ipport string
	status int
}

var _ dnsx.Transport = (*grounded)(nil)

// NewGroundedTransport returns a DNS transport that blocks all DNS queries.
func NewGroundedTransport(id string) (t dnsx.Transport) {
	t = &grounded{
		id:     id, // typically, dnsx.BlockAll
		ipport: "127.0.0.3:53",
		status: dnsx.Start,
	}
	log.I("grounded(%s) setup: %s", t.ID(), t.GetAddr())
	return
}

func (t *grounded) Query(_ string, q *dns.Msg, smm *x.DNSSummary) (ans *dns.Msg, err error) {
	ans, err = xdns.RefusedResponseFromMessage(q)
	if err != nil {
		t.status = x.BadResponse
	} else {
		t.status = x.Complete
	}
	elapsed := 0 * time.Second
	smm.Latency = elapsed.Seconds()
	smm.RData = xdns.GetInterestingRData(ans)
	smm.RCode = xdns.Rcode(ans)
	smm.RTtl = xdns.RTtl(ans)
	smm.Server = t.GetAddr()
	smm.Status = t.Status()
	if err != nil {
		smm.Msg = err.Error()
	}

	return ans, err
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
	return t.status
}
