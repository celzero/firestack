// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dns53

import (
	"time"

	x "github.com/celzero/firestack/intra/android/dnsx"
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

func (t *grounded) Query(_ string, q []byte, summary *x.DNSSummary) ([]byte, error) {
	var response []byte
	var ans *dns.Msg
	var err error

	ans, err = xdns.BlockResponseFromMessage(q)
	if err == nil {
		response, err = ans.Pack()
	}
	if err != nil {
		t.status = dnsx.BadResponse
	} else {
		t.status = dnsx.Complete
	}
	elapsed := 0 * time.Second
	summary.Latency = elapsed.Seconds()
	summary.RData = xdns.GetInterestingRData(ans)
	summary.RCode = xdns.Rcode(ans)
	summary.RTtl = xdns.RTtl(ans)
	summary.Server = t.GetAddr()
	summary.Status = t.Status()
	summary.Blocklists = ""

	return response, err
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
