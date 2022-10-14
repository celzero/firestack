// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dns53

import (
	"time"

	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

// TODO: Keep a context here so that queries can be canceled.
type grounded struct {
	dnsx.Transport
	id     string
	ipport string
	status int
}

// NewGroundedTransport returns a DNS transport that blocks all DNS queries.
func NewGroundedTransport() (t dnsx.Transport) {
	t = &grounded{
		id:     dnsx.BlockAll,
		ipport: "127.0.0.3:53",
		status: dnsx.Start,
	}
	log.Infof("grounded(%s) setup: %s", t.ID(), t.GetAddr())
	return
}

func (t *grounded) Query(_ string, q []byte, summary *dnsx.Summary) ([]byte, error) {
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
	summary.Response = response
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

func (t *grounded) GetAddr() string {
	return t.ipport
}

func (t *grounded) Status() int {
	return t.status
}
