// Copyright (c) 2022 RethinkDNS and its authors.
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
	"strings"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"

	_ "go4.org/unsafe/assume-no-moving-gc"
)

const (
	Port       = "53"        // default DNS port
	PortU16    = uint16(53)  // default DNS port as uint16
	DotPort    = "853"       // default DNS over TLS port
	DotPortU16 = uint16(853) // default DNS over TLS port as uint16
	timeout    = 5 * time.Second
	dottimeout = 8 * time.Second
)

var errQueryParse = errors.New("dns53: err parse query")

// TODO: Keep a context here so that queries can be canceled.
type transport struct {
	ctx      context.Context
	done     context.CancelFunc
	id       string
	addrport string // hostname, ip:port, protect.UidSelf:53, protect.System:53
	port     uint16
	client   *dns.Client
	pool     *core.MultConnPool[uintptr]
	proxies  ipn.Proxies // should never be nil
	relay    ipn.Proxy   // may be nil
	est      core.P2QuantileEstimator

	lastaddr *core.Volatile[string] // last resolved addr
	status   *core.Volatile[int]    // status of the transport
}

var _ dnsx.Transport = (*transport)(nil)

// NewTransportFromHostname returns a DNS53 transport serving from hostname, ready for use.
func NewTransportFromHostname(ctx context.Context, id, hostOrHostport string, ipcsv string, px ipn.Proxies) (t *transport, err error) {
	// ipcsv may contain port, eg: 10.1.1.3:53
	do, err := settings.NewDNSOptionsFromHostname(hostOrHostport, ipcsv)
	if err != nil {
		return
	}
	return newTransport(ctx, id, do, px)
}

// NewTransport returns a DNS53 transport serving from ip & port, ready for use.
func NewTransport(ctx context.Context, id, ip, port string, px ipn.Proxies) (t *transport, err error) {
	ipport := net.JoinHostPort(ip, port)
	do, err := settings.NewDNSOptions(ipport)
	if err != nil {
		return
	}

	return newTransport(ctx, id, do, px)
}

func newTransport(pctx context.Context, id string, do *settings.DNSOptions, px ipn.Proxies) (*transport, error) {
	// cannot be nil, see: ipn.Exit which the only proxy guaranteed to be connected to the internet;
	// ex: ipn.Base routed back within the tunnel (rethink's traffic routed back into rethink).
	if px == nil {
		return nil, dnsx.ErrNoProxyProvider
	}
	ctx, done := context.WithCancel(pctx)
	relay, _ := px.ProxyFor(id)
	tx := &transport{
		ctx:      ctx,
		done:     done,
		id:       id,
		addrport: do.AddrPort(), // may be hostname:port or ip:port
		port:     do.Port(),
		status:   core.NewVolatile(dnsx.Start),
		lastaddr: core.NewZeroVolatile[string](),
		pool:     core.NewMultConnPool[uintptr](ctx),
		proxies:  px,    // never nil; see above
		relay:    relay, // may be nil
		est:      core.NewP50Estimator(ctx),
	}
	ipcsv := do.ResolvedAddrs()
	hasips := len(ipcsv) > 0
	ips := strings.Split(ipcsv, ",")               // may be nil or empty or ip:port
	ok := dnsx.RegisterAddrs(id, tx.addrport, ips) // addrport may be protect.UidSelf or protect.System
	log.I("dns53: (%s) pre-resolved %s to %s; ok? %t", id, tx.addrport, ipcsv, ok)
	tx.client = &dns.Client{
		Net:     "udp",   // default transport type
		Timeout: timeout, // default timeout
		// instead using custom dialer rdial
		// Dialer:  d,
		// TODO: set it to MTU? or no more than 512 bytes?
		// ref: github.com/miekg/dns/blob/b3dfea071/server.go#L207
		// UDPSize: dns.DefaultMsgSize,
	}
	log.I("dns53: (%s) setup: %s; pre-ips? %t; relay? %t", id, tx.addrport, hasips, relay != nil)
	return tx, nil
}

// NewTransportFrom returns a DNS53 transport serving from ipp, ready for use.
func NewTransportFrom(ctx context.Context, id string, ipp netip.AddrPort, px ipn.Proxies) (t dnsx.Transport, err error) {
	do, err := settings.NewDNSOptionsFromNetIp(ipp)
	if err != nil {
		return
	}

	return newTransport(ctx, id, do, px)
}

func (t *transport) pxdial(network, pid string) (*dns.Conn, uintptr, error) {
	var px ipn.Proxy
	if t.relay != nil { // relay takes precedence
		px = t.relay
	} else if t.proxies != nil { // use proxy, if specified
		var err error
		if px, err = t.proxies.ProxyFor(pid); err != nil {
			return nil, core.Nobody, err
		}
	}
	if px == nil {
		return nil, core.Nobody, dnsx.ErrNoProxyProvider
	}

	who := px.Handle()
	if c := t.fromPool(who); c != nil {
		return c, who, nil
	}

	log.V("dns53: pxdial: (%s) using %s relay/proxy %s at %s",
		t.id, network, px.ID(), px.GetAddr())

	pxconn, err := px.Dialer().Dial(network, t.addrport)
	if err != nil {
		clos(pxconn)
		return nil, core.Nobody, err
	} else if pxconn == nil {
		log.E("dns53: pxdial: (%s) no %s conn for relay/proxy %s at %s",
			t.id, network, px.ID(), px.GetAddr())
		err = errNoNet
		return nil, core.Nobody, err
	}
	return &dns.Conn{Conn: pxconn}, who, nil
}

// toPool takes ownership of c.
func (t *transport) toPool(id uintptr, c *dns.Conn) {
	if !usepool || id == core.Nobody {
		clos(c)
		return
	}
	ok := t.pool.Put(id, c)
	logwif(!ok)("dns53: pool: (%s) put for %v; ok? %t", t.id, id, ok)
}

// fromPool returns a conn from the pool, if available.
func (t *transport) fromPool(id uintptr) (c *dns.Conn) {
	if !usepool || id == core.Nobody {
		return
	}

	pooled := t.pool.Get(id)
	if pooled == nil || core.IsNil(pooled) {
		return
	}
	var ok bool
	if c, ok = pooled.(*dns.Conn); !ok { // unlikely
		return &dns.Conn{Conn: pooled}
	}
	log.V("dns53: pool: (%s) got conn from %v", t.id, id)
	return
}

func (t *transport) connect(network, pid string) (conn *dns.Conn, who uintptr, err error) {
	useudp := network == dnsx.NetTypeUDP
	userelay := t.relay != nil
	useproxy := len(pid) != 0 // pid == dnsx.NetNoProxy => ipn.Block

	// if udp is unreachable, try tcp: github.com/celzero/rethink-app/issues/839
	// note that some proxies do not support udp (eg pipws, piph2)
	if userelay || useproxy {
		conn, who, err = t.pxdial(network, pid)
		if err != nil && useudp {
			clos(conn)
			network = dnsx.NetTypeTCP
			conn, who, err = t.pxdial(network, pid)
		}
	} else {
		err = dnsx.ErrNoProxyProvider
	}
	return
}

// ref: github.com/celzero/midway/blob/77ede02c/midway/server.go#L179
func (t *transport) send(network, pid string, q *dns.Msg) (ans *dns.Msg, elapsed time.Duration, qerr *dnsx.QueryError) {
	var err error
	if q == nil || !xdns.HasAnyQuestion(q) {
		qerr = dnsx.NewBadQueryError(errQueryParse)
		return
	}
	qname := xdns.QName(q)
	useudp := network == dnsx.NetTypeUDP
	userelay := t.relay != nil
	useproxy := len(pid) != 0 // pid == dnsx.NetNoProxy => ipn.Base

	conn, who, err := t.connect(network, pid)

	logev(err)("dns53: send: (%s / %s) to %s for %s using udp? %t / px? %t / relay? %t; err? %v",
		network, t.id, t.addrport, qname, useudp, useproxy, userelay, err)

	if err != nil {
		qerr = dnsx.NewSendFailedQueryError(err)
		return
	} // else: send query

	lastaddr := remoteAddrIfAny(conn) // may return empty string
	ans, elapsed, err = t.client.ExchangeWithConnContext(t.ctx, q, conn)

	if err != nil {
		clos(conn)
		ok := dialers.Disconfirm2(t.addrport, lastaddr)
		log.V("dns53: sendRequest: (%s) for %s; err: %v; disconfirm? %t %s => %s",
			t.id, qname, err, ok, t.addrport, lastaddr)
		qerr = dnsx.NewSendFailedQueryError(err)
	} else if ans == nil {
		t.toPool(who, conn) // or close
		qerr = dnsx.NewBadResponseQueryError(errNoAns)
	} else {
		t.toPool(who, conn) // or close
		dialers.Confirm2(t.addrport, lastaddr)
	}

	t.lastaddr.Store(lastaddr)

	return
}

func (t *transport) chooseProxy(pids []string) string {
	foundProxy := false
	pid := dnsx.NetNoProxy
	if len(pids) > 0 {
		pid = pids[0]
	}
	for _, ipp := range t.IPPorts() {
		if px, err := t.proxies.ProxyTo(ipp, core.UNKNOWN_UID_STR, pids); err == nil {
			pid = px.ID()
			foundProxy = true
			log.VV("dns53: proxy: choose: (%s) proxy(%s) for %s@%s; among %v",
				t.id, pid, t.addrport, ipp, pids)
		}
	}
	if !foundProxy {
		log.W("dns53: proxy: choose: (%s) no proxy for %s; choosing %s among %v",
			t.id, t.addrport, pid, pids)
	}
	return pid
}

func (t *transport) Query(network string, q *dns.Msg, smm *x.DNSSummary) (ans *dns.Msg, err error) {
	proto, pids := xdns.Net2ProxyID(network)
	pid := t.chooseProxy(pids)

	ans, elapsed, qerr := t.send(proto, pid, q)
	if qerr != nil { // only on send-request errors
		ans = xdns.Servfail(q)
	}

	status := dnsx.Complete
	if qerr != nil {
		err = qerr.Unwrap()
		status = qerr.Status()
		log.W("dns53: (%s) err(%v) / size(%d)", t.id, err, xdns.Len(ans))
	}
	t.status.Store(status)

	smm.Latency = elapsed.Seconds()
	smm.RData = xdns.GetInterestingRData(ans)
	smm.RCode = xdns.Rcode(ans)
	smm.RTtl = xdns.RTtl(ans)
	smm.Server = t.GetAddr()
	if t.relay != nil {
		smm.RelayServer = x.SummaryProxyLabel + t.relay.ID()
	} else if !dnsx.IsLocalProxy(pid) {
		smm.RelayServer = x.SummaryProxyLabel + pid
	}
	if err != nil {
		smm.Msg = err.Error()
	}
	smm.Status = status
	t.est.Add(smm.Latency)

	log.V("dns53: (%s) len(res): %d, data: %s, via: %s, err? %v",
		t.id, xdns.Len(ans), smm.RData, smm.RelayServer, err)

	return ans, err
}

func (t *transport) ID() string {
	return t.id
}

func (t *transport) Type() string {
	return dnsx.DNS53
}

func (t *transport) P50() int64 {
	return t.est.Get()
}

func (t *transport) GetAddr() string {
	addr := t.lastaddr.Load()
	if len(addr) == 0 {
		// may be protect.UidSelf (for bootstrap/default) or protect.System
		addr = t.addrport
	}

	prefix := dnsx.PrefixFor(t.id)
	if len(prefix) > 0 {
		addr = prefix + addr
	}

	return addr
}

func (t *transport) IPPorts() (ipps []netip.AddrPort) {
	for _, ip := range dialers.For(t.addrport) {
		ipps = append(ipps, netip.AddrPortFrom(ip, t.port))
	}
	return
}

func (t *transport) Status() int {
	return t.status.Load()
}

func (t *transport) Stop() error {
	t.done()
	return nil
}

func remoteAddrIfAny(conn *dns.Conn) string {
	if conn == nil || conn.Conn == nil {
		return ""
	} else if addr := conn.RemoteAddr(); addr == nil {
		return ""
	} else {
		return addr.String()
	}
}

func logev(err error) log.LogFn {
	if err != nil {
		return log.E
	}
	return log.V
}
