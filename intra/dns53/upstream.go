// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dns53

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

const (
	Port           = "53"
	DotPort        = "853"
	timeout        = 5 * time.Second
	dottimeout     = 8 * time.Second
	usemeikgclient = true
)

var errQueryParse = errors.New("dns53: err parse query")

// TODO: Keep a context here so that queries can be canceled.
type transport struct {
	id      string
	ipport  string
	status  int
	mcudp   *dns.Client
	mctcp   *dns.Client
	proxies ipn.Proxies // may be nil; esp for id == dnsx.System
	relay   ipn.Proxy   // may be nil
	est     core.P2QuantileEstimator
}

var _ dnsx.Transport = (*transport)(nil)

// NewTransport returns a DNS transport, ready for use.
func NewTransport(id, ip, port string, px ipn.Proxies) (t dnsx.Transport, err error) {
	do, err := settings.NewDNSOptions(ip, port)
	if err != nil {
		return
	}

	return newTransport(id, do, px)
}

func newTransport(id string, do *settings.DNSOptions, px ipn.Proxies) (dnsx.Transport, error) {
	relay, _ := px.GetProxy(id)
	tx := &transport{
		id:      id,
		ipport:  do.IPPort,
		status:  dnsx.Start,
		proxies: px,
		relay:   relay,
		est:     core.NewP50Estimator(),
	}
	// todo: with controller
	d := protect.MakeNsDialer(id, nil)
	if usemeikgclient {
		tx.mcudp = &dns.Client{
			Net:            "udp",
			Dialer:         d,
			Timeout:        timeout,
			SingleInflight: true,
			// TODO: set it to MTU?
			// UDPSize:        dns.DefaultMsgSize,
		}
		tx.mctcp = &dns.Client{
			Net:            "tcp",
			Dialer:         d,
			Timeout:        timeout,
			SingleInflight: true,
		}
	}
	log.I("dns53: (%s) setup: %s; relay? %t", id, do.IPPort, relay != nil)
	return tx, nil
}

// NewTransport returns a DNS transport, ready for use.
func NewTransportFrom(id string, ipp netip.AddrPort, px ipn.Proxies) (t dnsx.Transport, err error) {
	do, err := settings.NewDNSOptionsFromNetIp(ipp)
	if err != nil {
		return
	}

	return newTransport(id, do, px)
}

// Given a raw DNS query (including the query ID), this function sends the
// query.  If the query is successful, it returns the response and a nil qerr.  Otherwise,
// it returns a SERVFAIL response and a qerr with a status value indicating the cause.
func (t *transport) doQuery(network, pid string, q []byte) (response []byte, elapsed time.Duration, qerr *dnsx.QueryError) {
	if len(q) < 2 {
		qerr = dnsx.NewBadQueryError(fmt.Errorf("dns53: query length is %d", len(q)))
		return
	}

	if usemeikgclient {
		response, elapsed, qerr = t.sendRequest2(network, pid, q)
	} else {
		response, elapsed, qerr = t.sendRequest(network, pid, q)
	}

	if qerr != nil { // only on send-request errors
		response = xdns.Servfail(q)
	}

	return
}

func (t *transport) pxdial(network, pid string) (conn *dns.Conn, err error) {
	var px ipn.Proxy
	if t.relay != nil { // relay takes precedence
		px = t.relay
	} else if t.proxies != nil { // use proxy, if specified
		px, err = t.proxies.GetProxy(pid)
	} else {
		err = dnsx.ErrNoProxyProvider
	}
	if err != nil {
		return
	}
	log.V("dns53: pxdial: (%s) using %s relay/proxy %s at %s", t.id, network, px.ID(), px.GetAddr())
	pxconn, err := px.Dialer().Dial(network, t.ipport)
	if err != nil {
		return
	}
	conn = &dns.Conn{Conn: pxconn}
	return
}

func (t *transport) dial(network string) (*dns.Conn, error) {
	if network == dnsx.NetTypeUDP {
		return t.mcudp.Dial(t.ipport)
	} else {
		return t.mctcp.Dial(t.ipport)
	}
}

func (t *transport) sendRequest2(network, pid string, q []byte) (response []byte, elapsed time.Duration, qerr *dnsx.QueryError) {
	var ans *dns.Msg
	var err error
	msg := xdns.AsMsg(q)
	if msg == nil {
		qerr = dnsx.NewBadQueryError(errQueryParse)
		return
	}

	var conn *dns.Conn
	useudp := network == dnsx.NetTypeUDP
	userelay := t.relay != nil
	useproxy := len(pid) != 0 && pid != dnsx.NetNoProxy

	// if udp is unreachable, try tcp: github.com/celzero/rethink-app/issues/839
	// note that some proxies do not support udp (eg pipws, piph2)
	if userelay || useproxy {
		conn, err = t.pxdial(network, pid)
		if err != nil && useudp {
			network = dnsx.NetTypeTCP
			conn, err = t.pxdial(network, pid)
		}
	} else {
		conn, err = t.dial(network)
		if err != nil && useudp {
			network = dnsx.NetTypeTCP
			conn, err = t.dial(network)
		}
	}
	if err == nil {
		// TODO: conn pooling w/ ExchangeWithConn
		if network == dnsx.NetTypeTCP {
			ans, elapsed, err = t.mctcp.ExchangeWithConn(msg, conn)
		} else {
			ans, elapsed, err = t.mcudp.ExchangeWithConn(msg, conn)
		}
		conn.Close()
	}

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

func (t *transport) sendRequest(network, pid string, q []byte) (response []byte, elapsed time.Duration, qerr *dnsx.QueryError) {
	var conn net.Conn
	var dialError error
	start := time.Now()

	defer func() {
		if qerr != nil {
			log.I("dns53: query fail: %v %v %v", qerr, qerr.Error(), qerr.Unwrap())
		}
		if conn != nil {
			conn.Close()
		}
	}()

	conn, dialError = net.Dial(network, t.ipport)
	if dialError != nil {
		elapsed = time.Since(start)
		qerr = dnsx.NewSendFailedQueryError(dialError)
		return
	}

	if network == dnsx.NetTypeTCP {
		// for tcp, prefix the len(q) in the first two bytes
		if q, dialError = xdns.PrefixWithSize(q); dialError != nil {
			elapsed = time.Since(start)
			qerr = dnsx.NewSendFailedQueryError(dialError)
			return
		}
	}

	conn.SetDeadline(time.Now().Add(timeout)) // extend deadline
	_, err := conn.Write(q)
	if err != nil {
		elapsed = time.Since(start)
		qerr = dnsx.NewSendFailedQueryError(err)
		return
	}

	conn.SetDeadline(time.Now().Add(timeout)) // extend deadline
	// TODO: use miekg/dns udp/tcp stub resolver impl instead
	// ref: github.com/celzero/midway/blob/77ede02c/midway/server.go#L179
	// udp size is expected no more than 512 bytes?
	// ref: github.com/miekg/dns/blob/b3dfea071/server.go#L207

	if network == dnsx.NetTypeTCP {
		// TODO: replace xdns.ReadPrefixed impl
		// for tcp, read the len(response) which is sent in the first 2 bytes
		// see: github.com/miekg/dns/blob/b3dfea071/server.go#L662
		b := make([]byte, 2)
		n, err := conn.Read(b)
		if err != nil || n < 2 {
			elapsed = time.Since(start)
			qerr = dnsx.NewBadResponseQueryError(err)
			return
		}
		l := binary.BigEndian.Uint16(b)
		if int(l) < xdns.MinDNSPacketSize {
			elapsed = time.Since(start)
			qerr = dnsx.NewBadResponseQueryError(fmt.Errorf("tcp: too small a response %d", l))
			return
		}

		b = make([]byte, l)
		for {
			conn.SetDeadline(time.Now().Add(timeout)) // extend deadline
			_, err = conn.Read(b)
			if err != nil {
				elapsed = time.Since(start)
				qerr = dnsx.NewTransportQueryError(fmt.Errorf("failed read %d/%d", len(response), l))
				return
			}
			response = append(response, b...)
			rem := int(l) - len(response)
			if rem <= 0 {
				break
			}
			b = b[:rem]
		}
	} else {
		b := make([]byte, xdns.MaxDNSUDPSafePacketSize)
		conn.SetDeadline(time.Now().Add(timeout)) // extend deadline
		n, err := conn.Read(b)
		elapsed = time.Since(start)
		if err != nil {
			qerr = dnsx.NewBadResponseQueryError(err)
			return
		}
		if n < xdns.MinDNSPacketSize {
			qerr = dnsx.NewBadResponseQueryError(fmt.Errorf("udp: too small a response %d", n))
		}
		response = b[:n]
	}

	return
}

func (t *transport) Query(network string, q []byte, summary *dnsx.Summary) (r []byte, err error) {

	proto, pid := xdns.Net2ProxyID(network)
	response, elapsed, qerr := t.doQuery(proto, pid, q)

	status := dnsx.Complete
	if qerr != nil {
		err = qerr.Unwrap()
		status = qerr.Status()
		log.W("dns53: err(%v) / size(%d)", err, len(response))
	}
	ans := xdns.AsMsg(response)
	t.status = status

	summary.Latency = elapsed.Seconds()
	summary.RData = xdns.GetInterestingRData(ans)
	summary.RCode = xdns.Rcode(ans)
	summary.RTtl = xdns.RTtl(ans)
	summary.Server = t.GetAddr()
	if t.relay != nil {
		summary.RelayServer = dnsx.SummaryProxyLabel + t.relay.ID()
	} else if len(pid) > 0 && pid != dnsx.NetNoProxy {
		summary.RelayServer = dnsx.SummaryProxyLabel + pid
	}
	summary.Status = status
	t.est.Add(summary.Latency)

	return response, err
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
	return t.ipport
}

func (t *transport) Status() int {
	return t.status
}
