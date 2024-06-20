// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dns53

import (
	"context"
	"net"
	"net/netip"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

type goosr struct {
	status int
	r      *net.Resolver
	rcgo   *net.Resolver
	// dialer *protect.RDial
	px  ipn.Proxy // the only supported proxy is ipn.Exit
	est core.P2QuantileEstimator
}

var _ dnsx.Transport = (*transport)(nil)

// NewGoosTransport returns the default Go DNS resolver
func NewGoosTransport(pxs ipn.Proxies, ctl protect.Controller) (t *goosr, err error) {
	// cannot be nil, see: ipn.Exit which the only proxy guaranteed to be connected to the internet;
	// ex: ipn.Base routed back within the tunnel (rethink's traffic routed back into rethink)
	// but it doesn't work for goos because the traffic to localhost:53 is routed back in as if
	// the destination is vpn's own "fake" dns (typically, at 10.111.222.3)
	if pxs == nil {
		return nil, dnsx.ErrNoProxyProvider
	}
	// d := protect.MakeNsRDial(dnsx.Goos, ctl)
	px, err := pxs.ProxyFor(ipn.Exit)
	if err != nil {
		log.E("dns53: goosr: no exit proxy: %v", err)
		return nil, err
	}
	tx := &goosr{
		status: x.Start,
		// dialer: d,
		px:  px,
		est: core.NewP50Estimator(),
	}
	tx.r = &net.Resolver{
		PreferGo: true,
		Dial:     tx.pxdial, // dials in to ipn.Exit, always
	}
	tx.rcgo = &net.Resolver{
		PreferGo: false,
		Dial:     tx.pxdial, // dials in to ipn.Exit, always
	}
	log.I("dns53: goosr: setup done")
	return tx, nil
}

func (t *goosr) pxdial(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	// addr must be ip:port
	log.V("dns53: goosr: pxdial: using %s proxy for %s:%s => %s", ipn.Exit, network, t.px.GetAddr(), addr)
	return t.px.Dialer().Dial(network, addr)
}

func (t *goosr) send(msg *dns.Msg) (ans *dns.Msg, elapsed time.Duration, qerr *dnsx.QueryError) {
	var err error
	var ip netip.Addr
	var ips []netip.Addr
	if msg == nil {
		qerr = dnsx.NewBadQueryError(errQueryParse)
		return
	}

	start := time.Now()

	host := xdns.QName(msg)
	// zero length host must return NS records for the root zone
	if len(host) <= 0 || host == "." {
		qerr = dnsx.NewBadQueryError(errNoHost)
		elapsed = time.Since(start)
		ans = xdns.Servfail(msg)
		return
	}

	if ip, err = str2ip(host); err == nil {
		log.V("dns53: goosr: no-op; host %s is ipaddr", host)
		ans, err = xdns.AQuadAForQuery(msg, ip)
	} else {
		bgctx := context.Background()
		aquadaq := xdns.HasAQuadAQuestion(msg)

		if !aquadaq { // TODO: support queries other than A/AAAA
			log.E("dns53: goosr: not A/AAAA query type for %s", host)
			ans = xdns.Servfail(msg)
			err = errQueryParse
		} else {
			// cgo first (uses dnsx.System iff not in Loopback), Resolver.LookupNetIP (uses dnsx.Default)
			if ips, err = t.r.LookupNetIP(bgctx, "ip", host); err == nil && xdns.HasAnyAnswer(msg) {
				log.D("dns53: goosr: go resolver for %s => %s", host, ips)
				ans, err = xdns.AQuadAForQuery(msg, ips...)
			} else if ips, err = t.rcgo.LookupNetIP(bgctx, "ip", host); err == nil {
				log.D("dns53: goosr: cgo resolver for %s => %s", host, ips)
				ans, err = xdns.AQuadAForQuery(msg, ips...)
			}
		}
	}

	elapsed = time.Since(start)
	if err != nil {
		qerr = dnsx.NewSendFailedQueryError(err)
		return
	}

	return
}

func (t *goosr) Query(_ string, q *dns.Msg, smm *x.DNSSummary) (r *dns.Msg, err error) {
	r, elapsed, qerr := t.send(q)
	if qerr != nil { // only on send-request errors
		r = xdns.Servfail(q)
	}

	status := dnsx.Complete
	if qerr != nil {
		err = qerr.Unwrap()
		status = qerr.Status()
		log.W("dns53: goosr: err(%v) / size(%d)", qerr, xdns.Len(r))
	}
	t.status = status

	smm.Latency = elapsed.Seconds()
	smm.RData = xdns.GetInterestingRData(r)
	smm.RCode = xdns.Rcode(r)
	smm.RTtl = xdns.RTtl(r)
	smm.Server = t.GetAddr()
	smm.Status = status
	if err != nil {
		smm.Msg = err.Error()
	}
	t.est.Add(smm.Latency)

	log.V("dns53: goosr: len(res): %d, data: %s, via: %s, err? %v", xdns.Len(r), smm.RData, smm.RelayServer, err)

	return r, err
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
	return protect.Localhost + ":53" // dummy
}

func (t *goosr) Status() int {
	return t.status
}
