// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dns53

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"time"

	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

const dottimeout = 7 * time.Second

// TODO: Keep a context here so that queries can be canceled.
type dot struct {
	dnsx.Transport
	id     string
	url    string
	status int
	c      *dns.Client
}

// NewTransport returns a DNS transport, ready for use.
func NewTLSTransport(id, rawurl string) (t dnsx.Transport, err error) {
	tlscfg := &tls.Config{}
	parsedurl, err := url.Parse(rawurl)
	if err != nil {
		return
	}
	if parsedurl.Scheme != "tls" {
		log.I("dot: disabling tls verification for %s", rawurl)
		tlscfg.InsecureSkipVerify = true
	}
	parsedurl.Scheme = ""
	tx := &dot{
		id:     id,
		url:    parsedurl.String(),
		status: dnsx.Start,
	}
	d := protect.MakeNsDialer(nil)
	tx.c = &dns.Client{
		Net:            "tcp-tls",
		Dialer:         d,
		Timeout:        dottimeout,
		SingleInflight: true,
		TLSConfig:      tlscfg,
	}
	log.I("dot: (%s) setup: %s", id, rawurl)
	return tx, nil
}

func (t *dot) doQuery(network string, q []byte) (response []byte, elapsed time.Duration, qerr *dnsx.QueryError) {
	if len(q) < 2 {
		qerr = dnsx.NewBadQueryError(fmt.Errorf("err len(query) %d", len(q)))
		return
	}

	response, elapsed, qerr = t.sendRequest(q)

	if qerr != nil { // only on send-request errors
		response = xdns.Servfail(q)
	}

	return
}

func (t *dot) sendRequest(q []byte) (response []byte, elapsed time.Duration, qerr *dnsx.QueryError) {
	var ans *dns.Msg
	var err error

	msg := xdns.AsMsg(q)
	if msg == nil {
		qerr = dnsx.NewBadQueryError(errQueryParse)
		return
	}

	// FIXME: conn pooling using t.c.Dial + ExchangeWithConn
	ans, elapsed, err = t.c.Exchange(msg, t.url)

	if err != nil {
		qerr = dnsx.NewTransportQueryError(err)
		return
	}
	response, err = ans.Pack()
	if err != nil {
		qerr = dnsx.NewBadResponseQueryError(err)
		return
	}
	return
}

func (t *dot) Query(network string, q []byte, summary *dnsx.Summary) (r []byte, err error) {

	response, elapsed, qerr := t.doQuery(network, q)

	status := dnsx.Complete
	if qerr != nil {
		err = qerr.Unwrap()
		status = qerr.Status()
		log.W("dot: err(%v) / size(%d)", err, len(response))
	}
	ans := xdns.AsMsg(response)
	t.status = status

	summary.Latency = elapsed.Seconds()
	summary.RData = xdns.GetInterestingRData(ans)
	summary.RCode = xdns.Rcode(ans)
	summary.RTtl = xdns.RTtl(ans)
	summary.Server = t.GetAddr()
	summary.Status = status

	return response, err
}

func (t *dot) ID() string {
	return t.id
}

func (t *dot) Type() string {
	return dnsx.DOT
}

func (t *dot) GetAddr() string {
	return t.url
}

func (t *dot) Status() int {
	return t.status
}
