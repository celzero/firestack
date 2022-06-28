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
	"io"
	"math"
	"net"
	"net/http"
	"time"

	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/xdns"
	"golang.org/x/net/dns/dnsmessage"
)

const timeout = 10 * time.Second

// Transport represents a DNS query transport.  This interface is exported by gobind,
// so it has to be very simple.
type Transport interface {
	// Given a DNS query (including ID), returns a DNS response with matching
	// ID, or an error if no response was received.  The error may be accompanied
	// by a SERVFAIL response if appropriate.
	Query(network string, q []byte) ([]byte, error)
	// Return the server URL used to initialize this transport.
	GetAddr() string
	// SetBraveDNS sets bravedns variable
	SetBraveDNS(dnsx.BraveDNS)
	// SetNatPt sets NAT PT variable
	SetNatPt(ipn.NatPt)
}

// TODO: Keep a context here so that queries can be canceled.
type transport struct {
	Transport
	ipport   string
	listener Listener
	natpt    ipn.NatPt
	bravedns dnsx.BraveDNS
}

// NewTransport returns a DNS transport, ready for use.
func NewTransport(ip, port string, listener Listener) (t Transport, err error) {
	do, err := settings.NewDNSOptions(ip, port)
	if err != nil {
		return
	}
	t = &transport{
		ipport:   do.IPPort,
		listener: listener,
		bravedns: nil,
	}
	log.Infof("dns53 setup: %s", do.IPPort)
	return
}

// Given a raw DNS query (including the query ID), this function sends the
// query.  If the query is successful, it returns the response and a nil qerr.  Otherwise,
// it returns a SERVFAIL response and a qerr with a status value indicating the cause.
func (t *transport) doQuery(network string, q []byte) (response []byte, blocklists string, elapsed time.Duration, qerr *queryError) {
	if len(q) < 2 {
		qerr = &queryError{BadQuery, fmt.Errorf("query length is %d", len(q))}
		return
	}

	start := time.Now()
	if err := t.prepareOnDeviceBlock(); err == nil {
		response, blocklists, err = t.applyBlocklists(q)
		if err == nil { // blocklist applied only when err is nil
			elapsed = time.Since(start)
			return
		}
		// skipping block because err
		log.Debugf("skip local block for %s with err %s", blocklists, err)
	} else {
		log.Debugf("forward query: no local block")
	}

	response, blocklists, elapsed, qerr = t.sendRequest(network, q)

	if qerr != nil { // only on send-request errors
		response = tryServfail(q)
	}

	return
}

func (t *transport) sendRequest(network string, q []byte) (response []byte, blocklists string, elapsed time.Duration, qerr *queryError) {
	var conn net.Conn
	var dialError error
	start := time.Now()

	defer func() {
		if qerr != nil {
			log.Infof("dnsproxy query fail: %v %v %v", qerr, qerr.Error(), qerr.Unwrap())
		}
		if conn != nil {
			conn.Close()
		}
	}()

	conn, dialError = net.Dial(network, t.ipport)
	if dialError != nil {
		elapsed = time.Since(start)
		qerr = &queryError{SendFailed, dialError}
		return
	}

	conn.SetDeadline(time.Now().Add(timeout)) // extend deadline
	_, err := conn.Write(q)
	if err != nil {
		elapsed = time.Since(start)
		qerr = &queryError{SendFailed, err}
		return
	}

	conn.SetDeadline(time.Now().Add(timeout)) // extend deadline
	// TODO: use miekg/dns udp/tcp stub resolver impl instead
	// ref: github.com/celzero/midway/blob/77ede02c/midway/server.go#L179
	// udp size is expected no more than 512 bytes?
	// ref: github.com/miekg/dns/blob/b3dfea071/server.go#L207
	b := make([]byte, 2048) // some sufficiently large buffer
	// for tcp reads, we need to read the length of the response first which
	// is sent in the first 2 bytes.
	// see: github.com/miekg/dns/blob/b3dfea071/server.go#L662
	n, err := conn.Read(b)
	elapsed = time.Since(start)
	if err != nil {
		qerr = &queryError{BadResponse, err}
		return
	}

	response = b[:n]
	if len(response) >= 2 {
		var r []byte
		blocklists, r = t.resolveBlock(q, response)
		if len(blocklists) > 0 && r != nil {
			response = r // overwrite response when blocked
		}
	} else {
		qerr = &queryError{BadResponse, fmt.Errorf("response length is %d", len(response))}
	}

	return
}

// Implements ipn.DnsExchange
func (t *transport) Exchange(q []byte) (r []byte, err error) {
	// TODO: set network as original query
	r, _, _, err = t.doQuery("udp", q)
	return
}

func (t *transport) Query(network string, q []byte) ([]byte, error) {
	var token Token
	if t.listener != nil {
		token = t.listener.OnDNSProxyQuery(t.GetAddr())
	}

	response, blocklists, elapsed, qerr := t.doQuery(network, q)
	if len(blocklists) <= 0 && qerr == nil && t.natpt != nil {
		response = t.natpt.D64(t.GetAddr(), response, t)
	}

	var err error
	status := Complete
	proxyStatus := http.StatusOK // ?
	if qerr != nil {
		log.Warnf("dns53 err(%w) / size(%d)", qerr, len(response))
		err = qerr
		status = qerr.status
		proxyStatus = 0

		var perr *proxyError
		if errors.As(qerr.err, &perr) {
			proxyStatus = perr.status
		}
	}

	if t.listener != nil {
		t.listener.OnDNSProxyResponse(token, &Summary{
			Latency:     elapsed.Seconds(),
			Query:       q,
			Response:    response,
			Server:      t.GetAddr(),
			Status:      status,
			ProxyStatus: proxyStatus,
			Blocklists:  blocklists,
		})
	}
	return response, err
}

func (t *transport) GetAddr() string {
	return t.ipport
}

func (t *transport) SetBraveDNS(b dnsx.BraveDNS) {
	t.bravedns = b
}

func (t *transport) SetNatPt(pt ipn.NatPt) {
	t.natpt = pt
	// TODO: pt.AddResolver(t.url, t.Query)
}

func (t *transport) prepareOnDeviceBlock() error {
	b := t.bravedns
	u := t.GetAddr()

	if b == nil || len(u) <= 0 {
		return errors.New("t.addr or dnsx.bravedns nil")
	}

	if !b.OnDeviceBlock() {
		return errors.New("on-device block not set")
	}

	return nil
}

func (t *transport) applyBlocklists(q []byte) (response []byte, blocklists string, err error) {
	bravedns := t.bravedns
	if bravedns == nil {
		err = errors.New("bravedns is nil")
		return
	}
	blocklists, err = bravedns.BlockRequest(q)
	if err != nil {
		return
	}
	if len(blocklists) <= 0 {
		err = errors.New("no blocklist applies")
		return
	}

	ans, err := xdns.BlockResponseFromMessage(q)
	if err != nil {
		return
	}

	response, err = ans.Pack()
	return
}

func (t *transport) resolveBlock(q []byte, ans []byte) (blocklistNames string, blockedResponse []byte) {
	bravedns := t.bravedns
	if bravedns == nil {
		return
	}

	var err error
	if !bravedns.OnDeviceBlock() {
		return
	}

	if blocklistNames, err = bravedns.BlockResponse(ans); err != nil {
		log.Debugf("response not blocked %v", err)
		return
	}

	if len(blocklistNames) <= 0 {
		log.Debugf("query not blocked blocklist empty")
		return
	}

	msg, err := xdns.BlockResponseFromMessage(q)
	if err != nil {
		log.Warnf("could not pack blocked dns ans %v", err)
		return
	}

	blockedResponse, _ = msg.Pack()
	return
}

// Perform a query using the transport, and send the response to the writer.
func forwardQuery(t Transport, q []byte, c io.Writer) error {
	resp, qerr := t.Query("tcp", q)
	if resp == nil && qerr != nil {
		return qerr
	}

	rlen := len(resp)
	if rlen > math.MaxUint16 {
		return fmt.Errorf("oversize response: %d", rlen)
	}

	// Use a combined write to ensure atomicity.  Otherwise, writes from two
	// responses could be interleaved.
	rlbuf := make([]byte, rlen+2)
	binary.BigEndian.PutUint16(rlbuf, uint16(rlen))
	copy(rlbuf[2:], resp)

	n, err := c.Write(rlbuf)
	if err != nil {
		return err
	}

	if int(n) != len(rlbuf) {
		return fmt.Errorf("res write incomplete: %d < %d", n, len(rlbuf))
	}
	return qerr
}

// Perform a query using the transport, send the response to the writer,
// and close the writer if there was an error.
func forwardQueryAndCheck(t Transport, q []byte, c io.WriteCloser) {
	if err := forwardQuery(t, q, c); err != nil {
		log.Warnf("Query forwarding failed: %v", err)
		c.Close()
	}
}

// Accept a DNS-over-TCP socket from a stub resolver, and connect the socket
// to this DNSTransport.
func Accept(t Transport, c io.ReadWriteCloser) {
	qlbuf := make([]byte, 2)
	for {
		n, err := c.Read(qlbuf)
		if n == 0 {
			log.Debugf("tcp query socket clean shutdown")
			break
		}
		if err != nil {
			log.Warnf("error reading from tcp query socket: %v", err)
			break
		}
		if n < 2 {
			log.Warnf("incomplete query length")
			break
		}
		qlen := binary.BigEndian.Uint16(qlbuf)
		q := make([]byte, qlen)
		n, err = c.Read(q)
		if err != nil {
			log.Warnf("error reading query: %v", err)
			break
		}
		if n != int(qlen) {
			log.Warnf("incomplete query: %d < %d", n, qlen)
			break
		}
		go forwardQueryAndCheck(t, q, c)
	}
	// TODO: Cancel outstanding queries at this point.
	c.Close()
}

// FIXME: Move this to xdns pkg, see: BlockResponseFromMessage
// Servfail returns a SERVFAIL response to the query q.
func Servfail(q []byte) ([]byte, error) {
	var msg dnsmessage.Message
	if err := msg.Unpack(q); err != nil {
		return nil, err
	}
	msg.Response = true
	msg.RecursionAvailable = true
	msg.RCode = dnsmessage.RCodeServerFailure
	msg.Additionals = nil // Strip EDNS
	return msg.Pack()
}

func tryServfail(q []byte) []byte {
	response, err := Servfail(q)
	if err != nil {
		log.Warnf("Error constructing servfail: %v", err)
	}
	return response
}
