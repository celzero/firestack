// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dns53

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

const dottimeout = 7 * time.Second
const dotport = "853"

// TODO: Keep a context here so that queries can be canceled.
type dot struct {
	dnsx.Transport
	id     string
	url    string
	addr   string
	status int
	c      *dns.Client
	est    core.P2QuantileEstimator
}

// NewTransport returns a DNS transport, ready for use.
func NewTLSTransport(id, rawurl string) (t dnsx.Transport, err error) {
	tlscfg := &tls.Config{}
	// rawurl is either tls:host[:port] or tls://host[:port] or host[:port]
	parsedurl, err := url.Parse(rawurl)
	if err != nil {
		return
	}
	if parsedurl.Scheme != "tls" {
		log.I("dot: disabling tls verification for %s", rawurl)
		tlscfg.InsecureSkipVerify = true
	}
	tx := &dot{
		id:     id,
		url:    rawurl,
		addr:   url2addr(rawurl),
		status: dnsx.Start,
		est:    core.NewP50Estimator(),
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
	ans, elapsed, err = t.c.Exchange(msg, t.addr)

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
	t.est.Add(summary.Latency)

	return response, err
}

func (t *dot) ID() string {
	return t.id
}

func (t *dot) Type() string {
	return dnsx.DOT
}

func (t *dot) P50() int64 {
	return t.est.Get()
}

func (t *dot) GetAddr() string {
	return t.url
}

func (t *dot) Status() int {
	return t.status
}

func url2addr(url string) string {
	// url is of type "tls://host:port" or "tls:host:port" or "host:port" or "host"
	if len(url) > 6 && url[:6] == "tls://" {
		url = url[6:]
	}
	if len(url) > 4 && url[:4] == "tls:" {
		url = url[4:]
	}
	// add port 853 if not present
	if _, _, err := net.SplitHostPort(url); err != nil {
		url = net.JoinHostPort(url, dotport)
	}
	return url
}
