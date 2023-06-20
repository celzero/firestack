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
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

var (
	errNoProtos = errors.New("Must enable at least one of IPv4 and IPv6 querying")
	errBindFail = errors.New("failed to bind to udp port")
)

type dnssd struct {
	id     string
	ipport string
	use4   bool
	use6   bool
	status int
}

// NewMDNSTransport returns a DNS transport that sends all DNS queries to mDNS endpoint.
func NewMDNSTransport(protos string) (t dnsx.Transport) {
	t = &dnssd{
		id:     dnsx.Local,
		use4:   use4(protos),
		use6:   use6(protos),
		ipport: "224.0.0.251:5353", // ip6: ff02::fb:5353
		status: dnsx.Start,
	}
	log.I("mdns(%s) setup: %s", protos)
	return
}

func use4(l3 string) bool {
	switch l3 {
	case settings.IP4:
		return true
	case settings.IP46:
		return true
	default:
		return false
	}
}

func use6(l3 string) bool {
	switch l3 {
	case settings.IP6:
		return true
	case settings.IP46:
		return true
	default:
		return false
	}
}

func (t *dnssd) oneshotQuery(msg *dns.Msg) (*dns.Msg, *dnsx.QueryError) {
	service, tld := xdns.ExtractMDNSDomain(msg)
	resch := make(chan *dnssdanswer)
	qctx := &qcontext{
		svc:   service,
		tld:   tld,
		ansch: resch,
		// sec 5 rfc6762 for oneshot queries
		timeout: time.Second * 3,
		// sec 5.4 rfc6762 multicast flooding
		unicastonly: true,
	}
	log.D("mdns query: %s.%s", qctx.svc, qctx.tld)

	if c, err := newUnderlyingTransport(true, t.use4, t.use6); err != nil {
		log.E("mdns: underlying transport: %s", err)
		return nil, dnsx.NewTransportQueryError(err)
	} else {
		defer c.Close()
		if qerr := c.query(qctx); err != nil {
			return nil, qerr
		} else {
			log.D("mdns: awaiting response %s.%s", qctx.svc, qctx.tld)
			// return the first response
			for res := range resch {
				if res.ans != nil {
					log.I("mdns: ans(%s) 4(%s) 6(%s)", res.name, res.ip4, res.ip6)
					return res.ans, nil
				}
			}
		}
		return nil, dnsx.NewNoResponseQueryError(nil)
	}
}

func (t *dnssd) Query(_ string, q []byte, summary *dnsx.Summary) (r []byte, err error) {
	summary.ID = t.ID()
	summary.Type = t.Type()
	summary.Server = t.GetAddr()

	start := time.Now()

	msg := &dns.Msg{}
	if err = msg.Unpack(q); err != nil {
		summary.Status = dnsx.BadQuery
		t.status = dnsx.BadQuery
		return
	}

	ans, qerr := t.oneshotQuery(msg)
	if qerr != nil {
		err = qerr.Unwrap()
		t.status = qerr.Status()
	} else {
		t.status = dnsx.Complete
	}

	elapsed := time.Since(start)
	summary.Latency = elapsed.Seconds()
	summary.RData = xdns.GetInterestingRData(ans)
	summary.RCode = xdns.Rcode(ans)
	summary.RTtl = xdns.RTtl(ans)
	summary.Status = t.Status()
	summary.Blocklists = ""

	if qerr != nil {
		return
	}

	return ans.Pack()
}

func (t *dnssd) ID() string {
	return t.id
}

func (t *dnssd) Type() string {
	return dnsx.DNS53
}

func (t *dnssd) GetAddr() string {
	return t.ipport
}

func (t *dnssd) Status() int {
	return t.status
}

// from: github.com/hashicorp/mdns/blob/5b0ab6d61/client.go

// dnssdanswer is returned after we query for a service
type dnssdanswer struct {
	ans      *dns.Msg
	name     string
	target   string
	ip4      *net.IP
	ip6      *net.IP
	port     int
	txt      []string
	captured bool
}

// done is used to check if we have all the info we need
func (s *dnssdanswer) hasip() bool {
	return (s.ip4 != nil || s.ip6 != nil)
}

func (s *dnssdanswer) hassvc() bool {
	return s.port != 0 && len(s.txt) > 0
}

// qcontext is used to customize how a Lookup is performed
type qcontext struct {
	svc         string              // Service to query for, ex: _foobar._tcp
	tld         string              // If blank, assumes "local"
	msg         *dns.Msg            // If not nil, use this message instead of building one
	timeout     time.Duration       // Lookup timeout, default 1 second
	ansch       chan<- *dnssdanswer // Entries Channel
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
	msgCh   chan *dns.Msg

	oneshot bool

	closed   int32
	closedCh chan struct{}
}

// NewClient creates a new mdns Client that can be used to query
// for records
func newUnderlyingTransport(oneshot, v4, v6 bool) (*client, error) {
	if !v4 && !v6 {
		return nil, errNoProtos
	}

	var uconn4 *net.UDPConn // bind to higher port for unicast
	var uconn6 *net.UDPConn
	var mconn4 *net.UDPConn // bind to port 5353 for multicast
	var mconn6 *net.UDPConn
	var err error

	if v4 {
		uconn4, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			log.E("mdns: failed to bind to unicast4 port: %v", err)
		}
		if !oneshot {
			mconn4, err = net.ListenMulticastUDP("udp4", nil, xdns.MDNSAddr4)
			if err != nil {
				log.E("mdns: failed to bind to multicast4 port: %v", err)
			}
		}
	}

	if v6 {
		uconn6, err = net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero, Port: 0})
		if err != nil {
			log.E("mdns: failed to bind to unicast6 port: %v", err)
		}
		if !oneshot {
			mconn6, err = net.ListenMulticastUDP("udp6", nil, xdns.MDNSAddr6)
			if err != nil {
				log.E("mdns: failed to bind to multicast6 port: %v", err)
			}
		}
	}

	has4 := v4 && uconn4 != nil && (oneshot || mconn4 != nil)
	has6 := v6 && uconn6 != nil && (oneshot || mconn6 != nil)
	if !has4 && !has6 {
		log.E("mdns: oneshot? %t with no4? %t / no6? %t", oneshot, has4, has6)
		return nil, errBindFail
	}

	c := &client{
		use4:       v4,
		use6:       v6,
		multicast4: mconn4, // nil if oneshot
		multicast6: mconn6, // nil if oneshot
		unicast4:   uconn4,
		unicast6:   uconn6,
		tracker:    make(map[string]*dnssdanswer),
		msgCh:      make(chan *dns.Msg, 32),
		closedCh:   make(chan struct{}),
		oneshot:    oneshot,
	}
	return c, nil
}

// Close is used to cleanup the client
func (c *client) Close() error {
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		return nil // already closed
	}

	log.I("mdns: closing client %v", *c)

	c.closedCh <- struct{}{}
	defer close(c.closedCh)
	defer close(c.msgCh)

	closeudp(c.unicast4)
	closeudp(c.unicast6)
	closeudp(c.multicast4)
	closeudp(c.multicast6)

	return nil
}

func closeudp(c *net.UDPConn) error {
	if c != nil {
		return c.Close()
	}
	return nil
}

// query is used to perform a lookup and stream results
func (c *client) query(qctx *qcontext) *dnsx.QueryError {
	if c.use4 {
		go c.recv(c.unicast4)
		go c.recv(c.multicast4)
	}
	if !c.oneshot && c.use6 {
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
	if !c.oneshot && qctx.unicastonly {
		q.Question[0].Qclass |= 1 << 15
	}

	if err := c.send(q); err != nil {
		return err
	}

	timeup := time.After(qctx.timeout)
	defer close(qctx.ansch)
loop:
	for {
		select {
		case msg := <-c.msgCh:
			var r *dnssdanswer
			for _, ans := range append(msg.Answer, msg.Extra...) {
				// expect answers only for the service name client queried for
				if c.oneshot && !strings.Contains(ans.Header().Name, qctx.svc) {
					continue
				}
				switch rr := ans.(type) {
				case *dns.PTR:
					// Create new entry for this
					r = c.track(rr.Ptr)
				case *dns.SRV:
					// Check for a target mismatch
					if rr.Target != rr.Hdr.Name {
						c.alias(rr.Hdr.Name, rr.Target)
					}
					r = c.track(rr.Hdr.Name)
					r.target = rr.Target
					r.port = int(rr.Port)
				case *dns.TXT:
					r = c.track(rr.Hdr.Name)
					r.txt = rr.Txt
					// todo: r.ans = ans ?
				case *dns.A:
					r = c.track(rr.Hdr.Name)
					r.ip4 = &rr.A
					r.ans = msg
				case *dns.AAAA:
					r = c.track(rr.Hdr.Name)
					r.ip6 = &rr.AAAA
					r.ans = msg
				}
			}

			if r == nil { // no valid answers
				continue
			} else if c.oneshot && r.hasip() || // recieved v4 / v6 ips
				!c.oneshot && r.hasip() && r.hassvc() { // v4 / v6 ips and srv
				if !r.captured {
					r.captured = true
					log.D("mdns: sent ans for %s", r.name)
					qctx.ansch <- r
				} else { // discard duplicates
					log.D("mdns: duplicate ans for %s", r.name)
					continue
				}
			} else if !c.oneshot { // fire off a node specific query
				m := new(dns.Msg)
				m.SetQuestion(r.name, dns.TypePTR)
				m.RecursionDesired = false
				if err := c.send(m); err != nil {
					log.E("mdns: failed to ptr query %s: %v", r.name, err)
				}
			}
		case <-timeup:
			break loop
		}
	}
	return nil
}

func (c *client) send(q *dns.Msg) *dnsx.QueryError {
	if buf, err := q.Pack(); err != nil {
		return dnsx.NewBadQueryError(err)
	} else {
		if c.unicast4 != nil {
			if _, err = c.unicast4.WriteToUDP(buf, xdns.MDNSAddr4); err != nil {
				return dnsx.NewSendFailedQueryError(err)
			}
		}
		if c.unicast6 != nil {
			if _, err = c.unicast6.WriteToUDP(buf, xdns.MDNSAddr6); err != nil {
				return dnsx.NewSendFailedQueryError(err)
			}
		}
	}
	return nil
}

// recv is used to receive until we get a shutdown
func (c *client) recv(conn *net.UDPConn) {
	if conn == nil {
		return
	}

	buf := core.Alloc()
	defer core.Recycle(buf)

	for atomic.LoadInt32(&c.closed) == 0 {
		n, err := conn.Read(buf)

		if atomic.LoadInt32(&c.closed) == 1 {
			return
		}

		if err != nil {
			log.E("mdns: failed to read packet: %v", err)
			continue
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil {
			log.E("mdns: failed to unpack packet: %v", err)
			continue
		}
		select {
		case c.msgCh <- msg:
		case <-c.closedCh:
			return
		}
	}
}

// track is used to mark a name as being tracked by this client
func (c *client) track(name string) (se *dnssdanswer) {
	if se, ok := c.tracker[name]; ok {
		return se
	}
	se = &dnssdanswer{
		name: name,
	}
	c.tracker[name] = se
	return
}

// alias is used to setup an alias between two tracked entries
func (c *client) alias(src, dst string) {
	c.tracker[dst] = c.track(src)
}
