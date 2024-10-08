// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//    SPDX-License-Identifier: MIT
//
//    Copyright (c) HashiCorp, Inc.

package dns53

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

var (
	errNoProtos     = errors.New("enable at least one of IPv4 and IPv6 querying")
	errBindFail     = errors.New("failed to bind to udp port")
	errNoMdnsQuery  = errors.New("no mdns query")
	errNoMdnsAnswer = errors.New("no mdns answer")
)

type dnssd struct {
	ctx    context.Context
	done   context.CancelFunc
	id     string // ID of this transport
	ipport string // IP:Port queries are sent to (v4)
	use4   bool   // Use IPv4
	use6   bool   // Use IPv6
	status int    // Status of this transport
	est    core.P2QuantileEstimator
}

var _ dnsx.Transport = (*dnssd)(nil)

// NewMDNSTransport returns a DNS transport that sends all DNS queries to mDNS endpoint.
func NewMDNSTransport(pctx context.Context, protos string) *dnssd {
	ctx, done := context.WithCancel(pctx)
	t := &dnssd{
		ctx:    ctx,
		done:   done,
		id:     dnsx.Local,
		use4:   use4(protos),
		use6:   use6(protos),
		ipport: xdns.MDNSAddr4.String(), // ip6: ff02::fb:5353
		status: dnsx.Start,
		est:    core.NewP50Estimator(ctx),
	}
	log.I("mdns: setup: %s", protos)
	return t
}

func use4(l3 string) bool {
	switch l3 {
	case settings.IP4, settings.IP46:
		return true
	default:
		return false
	}
}

func use6(l3 string) bool {
	switch l3 {
	case settings.IP6, settings.IP46:
		return true
	default:
		return false
	}
}

func (t *dnssd) oneshotQuery(msg *dns.Msg) (*dns.Msg, *dnsx.QueryError) {
	service, tld := xdns.ExtractMDNSDomain(msg)
	// always buffered; otherwise c.listen may block on writes into ansch / resch.
	// go.dev/play/p/gzwnGAFlTDV
	resch := make(chan *dnssdanswer, 32)
	qctx := &qcontext{
		msg:   msg,
		svc:   service,
		tld:   tld,
		ansch: resch,
		// sec 5 rfc6762 for oneshot queries
		timeout: time.Second * 3,
		// sec 5.4 rfc6762 multicast flooding
		unicastonly: true,
	}

	var c *client
	var err error
	qname := fmt.Sprintf("%s.%s", service, tld)
	log.D("mdns: oquery: %s", qname)

	if c, err = t.newClient(true); err != nil {
		log.E("mdns: oquery: underlying transport: %s", err)
		return nil, dnsx.NewTransportQueryError(err)
	}
	defer core.Close(c)
	if qerr := c.query(qctx); qerr != nil {
		log.E("mdns: oquery(%s): %v", qname, qerr)
		return nil, qerr
	}
	log.D("mdns: oquery: awaiting response %s", qname)
	// return the first response from channel qctx.ansch (same as resch)
	for res := range resch {
		if res != nil && res.ans != nil {
			log.I("mdns: oquery: q(%s) ans(%s) 4(%s) 6(%s)", qname, res.name, res.ip4, res.ip6)
			// todo: multiple answers?
			return res.ans, nil
		} else {
			log.D("mdns: oquery: q(%s); ans missing for %v", qname, res)
		}
	}
	log.I("mdns: oquery: no response for %s", qname)
	return nil, dnsx.NewNoResponseQueryError(errNoMdnsAnswer)
}

func (t *dnssd) Query(_ string, q *dns.Msg, smm *x.DNSSummary) (ans *dns.Msg, err error) {
	smm.ID = t.ID()
	smm.Type = t.Type()
	smm.Server = t.GetAddr()

	defer func() {
		log.D("mdns: err: %v; summary: %s", err, smm.Str())
	}()

	start := time.Now()

	if q == nil || !xdns.HasAnyQuestion(q) {
		smm.Status = dnsx.BadQuery
		t.status = dnsx.BadQuery
		return
	}

	ans, qerr := t.oneshotQuery(q)
	if qerr != nil {
		err = qerr.Unwrap()
		t.status = qerr.Status()
	} else {
		t.status = dnsx.Complete
	}

	elapsed := time.Since(start)
	smm.Latency = elapsed.Seconds()
	smm.RData = xdns.GetInterestingRData(ans)
	smm.RCode = xdns.Rcode(ans)
	smm.RTtl = xdns.RTtl(ans)
	smm.Status = t.Status()
	if err != nil {
		smm.Msg = err.Error()
	}
	t.est.Add(smm.Latency)

	return ans, err
}

func (t *dnssd) ID() string {
	return t.id
}

func (t *dnssd) Type() string {
	return dnsx.DNS53
}

func (t *dnssd) P50() int64 {
	return t.est.Get()
}

func (t *dnssd) GetAddr() string {
	return t.ipport
}

func (t *dnssd) Status() int {
	return t.status
}

func (t *dnssd) Stop() error {
	t.done()
	return nil
}

// from: github.com/hashicorp/mdns/blob/5b0ab6d61/client.go

// dnssdanswer is returned after dnssd / mdns query
type dnssdanswer struct {
	ans      *dns.Msg
	name     string
	target   string
	ip4      net.IP
	ip6      net.IP
	port     int
	txt      []string
	captured bool
}

// hasip checks if we have all the ip recs we need
func (s *dnssdanswer) hasip() bool {
	return (s.ip4 != nil || s.ip6 != nil)
}

// hassvc checks if we have all the srv recs we need
func (s *dnssdanswer) hassvc() bool {
	return s.port != 0 && len(s.txt) > 0
}

// qcontext customizes how a mdns lookup is performed
type qcontext struct {
	svc         string              // Service to query for, ex: _foobar._tcp, normalized to lower case
	tld         string              // If blank, assumes "local"
	msg         *dns.Msg            // If not nil, use this message instead of building one
	timeout     time.Duration       // Lookup timeout
	ansch       chan<- *dnssdanswer // answers acc, must be non-blocking (buffered)
	unicastonly bool                // Unicast response desired, as per 5.4 in RFC
}

// Client provides a query interface that can be used to
// search for service providers using mDNS
type client struct {
	use4 bool
	use6 bool

	unicast4   *net.UDPConn
	unicast6   *net.UDPConn
	multicast4 *net.UDPConn
	multicast6 *net.UDPConn

	tracker map[string]*dnssdanswer
	msgCh   chan *dns.Msg // never closed

	oneshot bool

	once sync.Once

	// mutable fields

	closed atomic.Bool // 0: open, 1: closed
}

func (c *client) str() string {
	return fmt.Sprintf("use4/6? %t/%t; oneshot? %t; tracked %d; closed %t", c.use4, c.use6, c.oneshot, len(c.tracker), c.closed.Load())
}

// newClient creates a new mdns unicast and multicast client
func (t *dnssd) newClient(oneshot bool) (*client, error) {
	if !t.use4 && !t.use6 {
		return nil, errNoProtos
	}

	var uconn4 *net.UDPConn // bind to higher port for unicast
	var uconn6 *net.UDPConn
	var mconn4 *net.UDPConn // bind to port 5353 for multicast
	var mconn6 *net.UDPConn
	var err error

	if t.use4 {
		uconn4, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			log.E("mdns: new-client: unicast4 bind fail: %v", err)
		}
		if !oneshot {
			mconn4, err = net.ListenMulticastUDP("udp4", nil, xdns.MDNSAddr4)
			if err != nil {
				log.E("mdns: new-client: multicast4 bind fail: %v", err)
			}
		}
	}

	if t.use6 {
		uconn6, err = net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero, Port: 0})
		if err != nil {
			log.E("mdns: new-client: unicast6 bind fail: %v", err)
		}
		if !oneshot {
			mconn6, err = net.ListenMulticastUDP("udp6", nil, xdns.MDNSAddr6)
			if err != nil {
				log.E("mdns: new-client: multicast6 bind fail: %v", err)
			}
		}
	}

	has4 := t.use4 && uconn4 != nil && (oneshot || mconn4 != nil)
	has6 := t.use6 && uconn6 != nil && (oneshot || mconn6 != nil)
	if !has4 && !has6 {
		log.E("mdns: new-client: oneshot? %t with no4? %t / no6? %t", oneshot, has4, has6)
		return nil, errBindFail
	}

	c := &client{
		use4:       t.use4,
		use6:       t.use6,
		multicast4: mconn4, // nil if oneshot
		multicast6: mconn6, // nil if oneshot
		unicast4:   uconn4,
		unicast6:   uconn6,
		tracker:    make(map[string]*dnssdanswer),
		msgCh:      make(chan *dns.Msg, 32),
		oneshot:    oneshot,
	}
	return c, nil
}

// Close cleanups the client
func (c *client) Close() error {
	if c.closed.Load() {
		return nil // already closed
	}
	c.once.Do(func() {
		c.closed.Store(true)
		log.I("mdns: closing client %v", c.str())

		core.CloseUDP(c.unicast4)
		core.CloseUDP(c.unicast6)
		core.CloseUDP(c.multicast4)
		core.CloseUDP(c.multicast6)
	})

	return nil
}

// query is used to perform a lookup and stream results
func (c *client) query(qctx *qcontext) *dnsx.QueryError {
	if !xdns.HasAnyQuestion(qctx.msg) {
		return dnsx.NewBadQueryError(errNoMdnsQuery)
	}

	if c.use4 {
		go c.recv(c.unicast4)
		go c.recv(c.multicast4)
	}
	if c.use6 {
		go c.recv(c.unicast6)
		go c.recv(c.multicast6)
	}

	q := qctx.msg
	q.RecursionDesired = false
	// RFC 6762, section 18.12.
	//
	// In the Question Section of a Multicast DNS query, the top bit of the qclass
	// field is used to indicate that unicast responses are preferred for this
	// particular question.  (See Section 5.4.)
	if !c.oneshot && qctx.unicastonly && len(q.Question) > 0 {
		q.Question[0].Qclass |= 1 << 15
	}
	if err := c.send(q); err != nil {
		log.E("mdns: query: send query(%s) fail: err(%v)", qctx.svc, err)
		return err
	}

	core.Go("mdns.listen", func() { c.listen(qctx) })

	log.D("mdns: query: waiting for ans to %s", qctx.svc)
	return nil
}

// listen listens for answers to the MDNS query, and sends them to qctx.ansch,
// and stops listening after qctx.timeout or the client is closed.
// Must be called from a goroutine.
func (c *client) listen(qctx *qcontext) {
	timesup := time.After(qctx.timeout)
	qname := fmt.Sprintf("%s.%s.", qctx.svc, qctx.tld)
	total := 0
	defer close(qctx.ansch)
loop:
	for {
		select {
		case msg, ok := <-c.msgCh:
			if !ok {
				// stackoverflow.com/a/13666733
				log.W("mdns: listen: msg channel for %s closed", qname)
				break loop
			}
			var disco *dnssdanswer
			xxlans := append(msg.Answer, msg.Extra...)
			for _, ans := range xxlans {
				ansname, aerr := xdns.AName(ans)
				// expect answers only for the service name client queried for
				if (aerr != nil) || (c.oneshot && !strings.Contains(ansname, qctx.svc)) {
					log.V("mdns: listen: ignoring %s ans for %s svc; err? %v", ansname, qctx.svc, aerr)
					continue
				}
				log.D("mdns: listen: processing %s ans for %s", ansname, qname)
				switch rr := ans.(type) {
				case *dns.PTR:
					// create new entry for this
					disco = c.track(rr.Ptr)
				case *dns.SRV:
					// check for a target mismatch
					if rr.Target != rr.Hdr.Name {
						c.alias(rr.Hdr.Name, rr.Target)
					}
					disco = c.track(rr.Hdr.Name)
					disco.target = rr.Target
					disco.port = int(rr.Port)
				case *dns.TXT:
					disco = c.track(rr.Hdr.Name)
					disco.txt = rr.Txt
					// todo: r.ans = ans ?
				case *dns.A:
					disco = c.track(rr.Hdr.Name)
					// todo: append to ip4?
					disco.ip4 = rr.A
					disco.ans = msg
				case *dns.AAAA:
					disco = c.track(rr.Hdr.Name)
					// todo: append to ip6?
					disco.ip6 = rr.AAAA
					disco.ans = msg
				default:
					who := qname
					if disco != nil {
						who += " -> (disco name) " + disco.name
					}
					log.I("mdns: listen: ignoring ans %s to %s", rr, who)
				}
			}

			if disco == nil { // no valid answers
				log.D("mdns: listen: no valid answers for %s; len? %d", qname, len(xxlans))
				continue
			} else if (c.oneshot && disco.hasip()) || // oneshot + received v4 / v6 ips
				(!c.oneshot && disco.hasip() && disco.hassvc()) { // v4 / v6 ips and srv
				if !disco.captured {
					disco.captured = true
					log.D("mdns: listen: q: %s; sent ans %s", qname, disco)
					qctx.ansch <- disco
					c.untrack(disco.name)
					total++
				} else { // discard duplicates
					log.D("mdns: listen: q: %s; duplicate ans %s", qname, disco)
					continue
				}
			} else if !c.oneshot { // fire off a node specific query
				m := new(dns.Msg)
				m.SetQuestion(disco.name, dns.TypePTR)
				m.RecursionDesired = false
				if err := c.send(m); err != nil {
					log.E("mdns: listen: failed to ptr query %s: %v", disco.name, err)
				} else {
					log.D("mdns: listen: sent ptr query for %s", disco.name)
				}
			} else {
				log.D("mdns: listen: waiting for ip / port for %s", disco.name)
			}
		case <-timesup:
			log.W("mdns: listen: timeout for %s", qname)
			break loop
		}
	}
	log.D("mdns: listen: done; got answers %d for %s", total, qname)
}

// send writes q to approp unicast mdns address
func (c *client) send(q *dns.Msg) *dnsx.QueryError {
	if buf, err := q.Pack(); err != nil {
		log.W("mdns: send: failed to pack query: %v", err)
		return dnsx.NewBadQueryError(err)
	} else {
		qname := xdns.QName(q)
		if c.unicast4 != nil {
			extend(c.unicast4, timeout)
			if _, err = c.unicast4.WriteToUDP(buf, xdns.MDNSAddr4); err != nil {
				return dnsx.NewSendFailedQueryError(err)
			}
			log.D("mdns: send: sent query4 %s", qname)
		}
		if c.unicast6 != nil {
			extend(c.unicast6, timeout)
			if _, err = c.unicast6.WriteToUDP(buf, xdns.MDNSAddr6); err != nil {
				return dnsx.NewSendFailedQueryError(err)
			}
			log.D("mdns: send: sent query6 %s", qname)
		}
	}
	return nil
}

// recv forwards bytes to msgCh read from conn until error or shutdown.
// Must be called from a goroutine.
func (c *client) recv(conn *net.UDPConn) {
	if conn == nil {
		return
	}

	defer core.Recover(core.DontExit, "mdns.recv")

	bptr := core.Alloc()
	buf := *bptr
	buf = buf[:cap(buf)]
	// buf must be recycled from a deferred fn since exec continues
	// on panics and deferred fns are guaranteed to run.
	defer func() {
		*bptr = buf
		core.Recycle(bptr)
	}()

	raddr := conn.RemoteAddr()
	for !c.closed.Load() {
		extend(conn, timeout)
		n, err := conn.Read(buf)

		if c.closed.Load() {
			log.W("mdns: recv: from(%v); closed; bytes(%d), err(%v)", raddr, n, err)
			return
		}

		if err != nil {
			log.E("mdns: recv: read failed: %v", err)
			continue
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil {
			log.E("mdns: recv: unpack failed: %v", err)
			continue
		}

		timesup := time.After(timeout)
		// ideally, the writer would close the channel, but in this
		// case there are potentially 4 writers (2 unicast, 2 multicast)
		// also see: go.dev/play/p/gzwnGAFlTDV
		select {
		case c.msgCh <- msg:
			log.V("mdns: recv: from(%v); sent; bytes(%d)", raddr, n)
		case <-timesup:
			log.V("mdns: recv: from(%v); timeout ch; bytes(%d)", raddr, n)
			return
		}
	}
}

// untrack removes a name from the tracker;
// name is NOT normalized. untrack is not thread safe.
func (c *client) untrack(name string) {
	log.V("mdns: tracker: rmv %s", name)
	delete(c.tracker, name)
}

// track marks a name as being tracked by this client;
// name is NOT normalized. track is not thread safe.
func (c *client) track(name string) *dnssdanswer {
	if tse, ok := c.tracker[name]; ok {
		log.VV("mdns: tracker: exists %s with %v", name, tse)
		return tse
	}
	se := &dnssdanswer{
		name: name,
	}
	c.tracker[name] = se
	log.V("mdns: tracker: start %s with %v", name, se)
	return se
}

// alias sets up mapping between two tracked entries;
// src and dst are NOT normalized. alias is not thread safe.
func (c *client) alias(src, dst string) {
	if se, ok := c.tracker[dst]; ok {
		log.VV("mdns: tracker: discard %v for %s; aliased to %s", se, dst, src)
	}
	se := c.track(src)
	log.V("mdns: tracker: alias %s <-> %s with %v", src, dst, se)
	c.tracker[dst] = se
}

func extend(c net.Conn, t time.Duration) {
	if c != nil && core.IsNotNil(c) {
		_ = c.SetDeadline(time.Now().Add(t))
	}
}
