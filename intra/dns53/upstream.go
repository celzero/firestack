// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dns53

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/xdns"
)

const timeout = 10 * time.Second

// TODO: Keep a context here so that queries can be canceled.
type transport struct {
	dnsx.Transport
	id     string
	ipport string
	status int
}

// NewTransport returns a DNS transport, ready for use.
func NewTransport(id, ip, port string) (t dnsx.Transport, err error) {
	do, err := settings.NewDNSOptions(ip, port)
	if err != nil {
		return
	}
	t = &transport{
		id:     id,
		ipport: do.IPPort,
		status: dnsx.Start,
	}
	log.I("dns53(%s) setup: %s", id, do.IPPort)
	return
}

// NewTransport returns a DNS transport, ready for use.
func NewTransportFrom(id string, ipp netip.AddrPort) (t dnsx.Transport, err error) {
	do, err := settings.NewDNSOptionsFromNetIp(ipp)
	if err != nil {
		return
	}
	t = &transport{
		id:     id,
		ipport: do.IPPort,
		status: dnsx.Start,
	}
	log.I("dns53(%s) setup: %s", id, do.IPPort)
	return
}

// Given a raw DNS query (including the query ID), this function sends the
// query.  If the query is successful, it returns the response and a nil qerr.  Otherwise,
// it returns a SERVFAIL response and a qerr with a status value indicating the cause.
func (t *transport) doQuery(network string, q []byte) (response []byte, blocklists string, elapsed time.Duration, qerr *dnsx.QueryError) {
	if len(q) < 2 {
		qerr = dnsx.NewBadQueryError(fmt.Errorf("query length is %d", len(q)))
		return
	}
	response, blocklists, elapsed, qerr = t.sendRequest(network, q)

	if qerr != nil { // only on send-request errors
		response = xdns.Servfail(q)
	}

	return
}

func (t *transport) sendRequest(network string, q []byte) (response []byte, blocklists string, elapsed time.Duration, qerr *dnsx.QueryError) {
	var conn net.Conn
	var dialError error
	start := time.Now()

	defer func() {
		if qerr != nil {
			log.I("dnsproxy query fail: %v %v %v", qerr, qerr.Error(), qerr.Unwrap())
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

	response, blocklists, elapsed, qerr := t.doQuery(network, q)

	status := dnsx.Complete
	if qerr != nil {
		err = qerr.Unwrap()
		status = qerr.Status()
		log.W("dns53 err(%v) / size(%d)", err, len(response))
	}
	ans := xdns.AsMsg(response)
	t.status = status
	summary.Latency = elapsed.Seconds()
	summary.RData = xdns.GetInterestingRData(ans)
	summary.RCode = xdns.Rcode(ans)
	summary.RTtl = xdns.RTtl(ans)
	summary.Server = t.GetAddr()
	summary.Status = status
	summary.Blocklists = blocklists

	return response, err
}

func (t *transport) ID() string {
	return t.id
}

func (t *transport) Type() string {
	return dnsx.DNS53
}

func (t *transport) GetAddr() string {
	return t.ipport
}

func (t *transport) Status() int {
	return t.status
}
