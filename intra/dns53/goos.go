// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dns53

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

// TODO: Keep a context here so that queries can be canceled.
type goosr struct {
	status  int
	r       *net.Resolver
	dialer  *protect.RDial
	pid     string      // only supported proxy
	proxies ipn.Proxies // should never be nil
	est     core.P2QuantileEstimator
}

var _ dnsx.Transport = (*transport)(nil)

// NewGoosTransport returns the default Go DNS resolver
func NewGoosTransport(px ipn.Proxies, ctl protect.Controller) (t dnsx.Transport, err error) {
	// cannot be nil, see: ipn.Exit which the only proxy guaranteed to be connected to the internet;
	// ex: ipn.Base routed back within the tunnel (rethink's traffic routed back into rethink).
	if px == nil {
		return nil, dnsx.ErrNoProxyProvider
	}
	d := protect.MakeNsRDial(dnsx.Goos, ctl)
	tx := &goosr{
		status:  dnsx.Start,
		dialer:  d,
		proxies: px,
		pid:     dnsx.NetNoProxy,
		est:     core.NewP50Estimator(),
	}
	// NetNoProxy => ipn.Base
	tx.r = &net.Resolver{
		PreferGo: false,
		Dial:     tx.pxdial,
	}
	log.I("dns53: goosr: setup done")
	return tx, nil
}

// Given a raw DNS query (including the query ID), this function sends the
// query.  If the query is successful, it returns the response and a nil qerr.  Otherwise,
// it returns a SERVFAIL response and a qerr with a status value indicating the cause.
func (t *goosr) doQuery(network, pid string, q []byte) (response []byte, elapsed time.Duration, qerr *dnsx.QueryError) {
	if len(q) < 2 {
		qerr = dnsx.NewBadQueryError(fmt.Errorf("dns53: goosr: query length is %d", len(q)))
		return
	}

	response, elapsed, qerr = t.send(network, pid, q)

	if qerr != nil { // only on send-request errors
		response = xdns.Servfail(q)
	}

	return
}

func (t *goosr) pxdial(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	var px ipn.Proxy
	px, err = t.proxies.GetProxy(t.pid)
	if err != nil {
		return
	}
	log.V("dns53: goosr: pxdial: using %s proxy for %s:%s => %s", t.pid, network, px.GetAddr(), addr)
	return px.Dialer().Dial(network, addr)
}

func (t *goosr) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return t.dialer.Dial(network, addr)
}

func (t *goosr) send(network, pid string, q []byte) (response []byte, elapsed time.Duration, qerr *dnsx.QueryError) {
	var ans *dns.Msg
	var err error
	var ip netip.Addr
	var ips []netip.Addr

	start := time.Now()

	msg := xdns.AsMsg(q)
	if msg == nil {
		qerr = dnsx.NewBadQueryError(errQueryParse)
		return
	}

	host := xdns.QName(msg)
	if len(host) <= 0 || host == "." {
		qerr = dnsx.NewBadQueryError(errNoHost)
		elapsed = time.Since(start)
		response = xdns.Servfail(q)
		return
	}

	if ip, err = str2ip(host); err != nil {
		ans, err = xdns.AQuadAForQuery(msg, ip)
	} else {
		bgctx := context.Background()
		// pid == dnsx.NetNoProxy => ipn.Base => t.pid
		useproxy := len(pid) != 0 && pid != t.pid
		aquadaq := xdns.HasAQuadAQuestion(msg)

		if useproxy {
			response = xdns.Servfail(q)
			err = errUnexpectedProxy
		} else if !aquadaq { // TODO: support queries other than A/AAAA
			log.E("dns53: goosr: not A/AAAA query type for %s", host)
			response = xdns.Servfail(q)
			err = errQueryParse
		} else {
			if ips, err = t.r.LookupNetIP(bgctx, network, host); err == nil {
				ans, err = xdns.AQuadAForQuery(msg, ips...)
			}
		}
	}

	elapsed = time.Since(start)
	if err != nil {
		qerr = dnsx.NewSendFailedQueryError(err)
		return
	}

	response, err = ans.Pack()
	if err != nil {
		qerr = dnsx.NewBadResponseQueryError(err)
		return
	}

	return
}

func (t *goosr) Query(network string, q []byte, smm *dnsx.Summary) (r []byte, err error) {
	proto, pid := xdns.Net2ProxyID(network)
	response, elapsed, qerr := t.doQuery(proto, pid, q)

	status := dnsx.Complete
	if qerr != nil {
		err = qerr.Unwrap()
		status = qerr.Status()
		log.W("dns53: goosr: err(%v) / size(%d)", err, len(response))
	}
	ans := xdns.AsMsg(response)
	t.status = status

	smm.Latency = elapsed.Seconds()
	smm.RData = xdns.GetInterestingRData(ans)
	smm.RCode = xdns.Rcode(ans)
	smm.RTtl = xdns.RTtl(ans)
	smm.Server = t.GetAddr()
	smm.Status = status
	t.est.Add(smm.Latency)

	log.V("dns53: goosr: len(res): %d, data: %s, via: %s, err? %v", len(response), smm.RData, smm.RelayServer, err)

	return response, err
}

func (t *goosr) ID() string {
	return dnsx.Goos
}

func (t *goosr) Type() string {
	return dnsx.DNS53
}

func (t *goosr) P50() int64 {
	return t.est.Get()
}

func (t *goosr) GetAddr() string {
	return "127.0.0.52:53" // dummy
}

func (t *goosr) Status() int {
	return t.status
}
