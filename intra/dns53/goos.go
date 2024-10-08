// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dns53

import (
	"context"
	"errors"
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
	ctx  context.Context
	done context.CancelFunc
	r    *net.Resolver
	rcgo *net.Resolver
	// dialer *protect.RDial
	px ipn.Proxy // the only supported proxy is ipn.Exit

	status *core.Volatile[int]
}

var _ dnsx.Transport = (*goosr)(nil)

// NewGoosTransport returns the default Go DNS resolver
func NewGoosTransport(pctx context.Context, pxs ipn.Proxies, ctl protect.Controller) (t *goosr, err error) {
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
	ctx, cancel := context.WithCancel(pctx)
	tx := &goosr{
		ctx:    ctx,
		done:   cancel,
		status: core.NewVolatile(x.Start),
		// dialer: d,
		px: px,
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
	log.VV("dns53: goosr: pxdial: using %s proxy for %s:%s => %s", ipn.Exit, network, t.px.GetAddr(), addr)
	return t.px.Dialer().Dial(network, addr)
}

func (t *goosr) send(msg *dns.Msg) (ans *dns.Msg, elapsed time.Duration, qerr *dnsx.QueryError) {
	var err error
	var ip netip.Addr
	if msg == nil {
		qerr = dnsx.NewBadQueryError(errQueryParse)
		return
	}

	start := time.Now()

	host := xdns.QName(msg)
	// TODO: zero length host must return NS records for the root zone
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
			proto := "ip4"
			if xdns.HasAAAAQuestion(msg) {
				proto = "ip6"
			}
			if ips, errc := t.rcgo.LookupNetIP(bgctx, proto, host); errc == nil {
				log.D("dns53: goosr: cgo resolver for %s => %s", host, ips)
				ans, err = xdns.AQuadAForQuery(msg, ips...)
			} else if ips, errl := t.r.LookupNetIP(bgctx, proto, host); errl == nil && xdns.HasAnyAnswer(msg) {
				log.D("dns53: goosr: go resolver (why? %v) for %s => %s", errl, host, ips)
				ans, err = xdns.AQuadAForQuery(msg, ips...)
			} else {
				err = errors.Join(errl, errc)
			}
			// TODO: if len(ips) <= 0 synthesize a NXDOMAIN?
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
	t.status.Store(status)

	smm.Latency = elapsed.Seconds()
	smm.RData = xdns.GetInterestingRData(r)
	smm.RCode = xdns.Rcode(r)
	smm.RTtl = xdns.RTtl(r)
	smm.Server = t.GetAddr()
	smm.Status = status
	if err != nil {
		smm.Msg = err.Error()
	}

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
	return 1 // always fast
}

func (t *goosr) GetAddr() string {
	return protect.Localhost + ":53" // dummy
}

func (t *goosr) Status() int {
	return t.status.Load()
}

func (t *goosr) Stop() error {
	t.done()
	return nil
}
