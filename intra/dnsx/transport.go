// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/k-sone/critbitgo"
	"github.com/miekg/dns"
)

const (
	// DNS transport types
	DOH      = "DNS-over-HTTPS"
	DNSCrypt = "DNSCrypt"
	DNS53    = "DNS"

	// special singleton DNS transports (IDs)
	System    = "System"    // network/os provided dns
	Default   = "Default"   // default (fallback) dns
	BlockFree = "BlockFree" // no blocks
	BlockAll  = "BlockAll"  // all blocks
	ALG       = "alg"       // dns application-level gateway
)

const (
	NetTypeUDP = "udp"
	NetTypeTCP = "tcp"
)

var (
	errNoSuchTransport     = errors.New("missing transport")
	errBlockFreeTransport  = errors.New("block free transport")
	errNoRdns              = errors.New("no rdns")
	errRdnsLocalIncorrect  = errors.New("rdns local is not remote")
	errRdnsRemoteIncorrect = errors.New("rdns remote is not local")
)

// Transport represents a DNS query transport.  This interface is exported by gobind,
// so it has to be very simple.
type Transport interface {
	// uniquely identifies this transport
	ID() string
	// one of DNS53, DOH, DNSCrypt, System
	Type() string
	// Given a DNS query (including ID), returns a DNS response with matching
	// ID, or an error if no response was received.  The error may be accompanied
	// by a SERVFAIL response if appropriate.
	Query(network string, q []byte, summary *Summary) ([]byte, error)
	// Return the server host address used to initialize this transport.
	GetAddr() string
	// State of the transport after previous query (see: queryerror.go)
	Status() int
}

type Conn interface {
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	Close() error
}

type Resolver interface {
	RdnsResolver
	Add(t Transport) bool
	Remove(id string) bool
	AddSystemDNS(t Transport) bool
	RemoveSystemDNS() int
	Gateway() Gateway
	IsDnsAddr(network, ipport string) bool
	Forward(q []byte) ([]byte, error)
	Serve(conn Conn)
}

type resolver struct {
	sync.RWMutex
	Resolver
	tunmode      *settings.TunMode
	tcpaddrs     []*net.TCPAddr
	udpaddrs     []*net.UDPAddr
	systemdns    []Transport
	transports   map[string]Transport
	pool         map[string]*oneTransport
	localdomains *critbitgo.Trie
	rdnsl        BraveDNS
	rdnsr        BraveDNS
	natpt        ipn.DNS64
	listener     Listener
}

func NewResolver(fakeaddrs string, tunmode *settings.TunMode, defaultdns Transport, l Listener, pt ipn.DNS64) Resolver {
	r := &resolver{
		listener:     l,
		natpt:        pt,
		transports:   make(map[string]Transport),
		tunmode:      tunmode,
		localdomains: UndelegatedDomainsTrie(),
	}
	r.Add(defaultdns)
	r.Add(NewDNSGateway(defaultdns))
	r.loadaddrs(fakeaddrs)
	return r
}

type oneTransport struct {
	ipn.Resolver
	t Transport
}

func (r *resolver) Gateway() Gateway {
	if gw, ok := r.transports[ALG]; ok {
		return gw.(Gateway)
	}
	return nil
}

// Implements ipn.Exchange
func (one *oneTransport) Exchange(q []byte) (r []byte, err error) {
	ans1, err1 := one.t.Query(NetTypeUDP, q, &Summary{})
	if err1 != nil {
		return ans1, err1
	}
	// if the transport type is anything else but dns53, then the
	// ans isn't expected to be truncated. So, nothing left to do.
	if one.t.Type() != DNS53 {
		return ans1, err1
	}

	msg1 := &dns.Msg{}
	err1 = msg1.Unpack(ans1)
	if err != nil {
		return ans1, err1
	}
	if !msg1.Truncated {
		return ans1, err1
	}

	// else if: returned response is truncated dns ans, retry over tcp
	return one.t.Query(NetTypeTCP, q, &Summary{})
}

// Implements RdnsResolver
func (r *resolver) SetRethinkDNSLocal(b BraveDNS) error {
	if b == nil {
		r.rdnsl = nil
	} else if b.OnDeviceBlock() {
		r.rdnsl = b
	} else {
		return errRdnsLocalIncorrect
	}
	return nil
}

func (r *resolver) SetRethinkDNSRemote(b BraveDNS) error {
	if b == nil {
		r.rdnsl = nil
	} else if !b.OnDeviceBlock() {
		r.rdnsl = b
	} else {
		return errRdnsRemoteIncorrect
	}
	return nil
}

func (r *resolver) GetRethinkDNSLocal() BraveDNS {
	return r.rdnsl
}

func (r *resolver) GetRethinkDNSRemote() BraveDNS {
	return r.rdnsr
}

func (r *resolver) AddSystemDNS(t Transport) bool {
	defer r.addSystemDnsIfAbsent(t)
	r.Lock()
	r.systemdns = append(r.systemdns, t)
	r.Unlock()
	return true
}

func (r *resolver) RemoveSystemDNS() int {
	defer r.Remove(System)
	r.Lock()
	d := len(r.systemdns)
	r.systemdns = nil
	r.Unlock()

	return d
}

// Implements Resolver
func (r *resolver) Add(t Transport) (ok bool) {
	r.Lock()
	defer r.Unlock()
	r.transports[t.ID()] = t
	r.pool[t.ID()] = &oneTransport{t: t}
	// if resetting default transport, update underlying transport for alg
	if gw := r.Gateway(); t.ID() == Default && gw != nil {
		gw.WithTransport(t)
	}
	return true
}

func (r *resolver) addSystemDnsIfAbsent(t Transport) (ok bool) {
	r.Lock()
	defer r.Unlock()
	if _, ok = r.transports[t.ID()]; !ok {
		// r.Add before r.registerSystemDns64, since r.pool must be populated
		ok1 := r.Add(t)
		go r.registerSystemDns64(t)
		return ok1
	}
	return false
}

func (r *resolver) registerSystemDns64(t Transport) (ok bool) {
	return r.natpt.AddResolver(ipn.UnderlayResolver, r.pool[t.ID()])
}

func (r *resolver) Remove(id string) (ok bool) {
	r.Lock()
	defer r.Unlock()
	_, ok1 := r.transports[id]
	_, ok2 := r.pool[id]
	if ok1 {
		delete(r.transports, id)
	}
	if ok2 {
		delete(r.pool, id)
	}
	return ok1 || ok2
}

func (r *resolver) IsDnsAddr(network, ipport string) bool {
	if len(ipport) <= 0 {
		return false
	}
	return r.isDns(network, ipport)
}

func (r *resolver) Forward(q []byte) ([]byte, error) {
	starttime := time.Now()
	summary := &Summary{
		Query:  q,
		Status: Start,
	}
	// always call up to the listener
	defer func() {
		go r.listener.OnResponse(summary)
	}()

	msg, err := unpack(q)
	if err != nil {
		log.Warnf("not a dns packet %v", err)
		summary.Latency = time.Since(starttime).Seconds()
		summary.Status = BadQuery
		return nil, err
	}

	// figure out transport to use
	qname := qname(msg)
	id := r.requiresSystem(qname)
	if len(id) <= 0 {
		id = r.listener.OnQuery(qname)
	} else {
		log.Infof("transport (udp): using system-dns %s for %s", id, qname)
	}
	// retrieve transport
	r.RLock()
	var t Transport
	t, ok := r.transports[id]
	onet := r.pool[id]
	r.RUnlock()
	if !ok {
		summary.Latency = time.Since(starttime).Seconds()
		summary.Status = TransportError
		return nil, errNoSuchTransport
	}

	// block query if needed (skipped for alg/block-free)
	res1, blocklists, err := r.block(t, msg)
	if err == nil {
		b, e := res1.Pack()
		summary.Latency = time.Since(starttime).Seconds()
		summary.Status = Complete
		summary.Blocklists = blocklists
		summary.Response = b
		return b, e
	}

	// query the transport
	summary.Type = t.Type()
	summary.ID = t.ID()
	res2, err := t.Query(NetTypeUDP, q, summary)

	if err != nil {
		// summary latency, ips, response, status already set by transport t
		return res2, err
	}
	ans1, err := unpack(res2)
	if err != nil {
		summary.Status = BadResponse
		return res2, err
	}

	// block response if needed
	ans2, blocklistnames := r.blockRes(t, msg, ans1, summary.Blocklists)
	// overwrite response when blocked
	if len(blocklistnames) > 0 && ans2 != nil {
		// summary latency, response, status, ips already set by transport t
		summary.Blocklists = blocklistnames
		ans1 = ans2
	}

	// override resp with dns64 if needed
	if onet != nil {
		d64 := r.natpt.D64(t.ID(), res2, onet)
		if len(d64) >= xdns.MinDNSPacketSize {
			return d64, nil
		}
	} else {
		log.Warnf("dns64: missing onetransport for %s", t.ID())
	}

	return ans1.Pack()
}

func (r *resolver) Serve(x Conn) {
	if c, ok := x.(io.ReadWriteCloser); ok {
		r.accept(c)
	}
}

// Perform a query using the transport, and send the response to the writer.
func (r *resolver) forwardQuery(q []byte, c io.Writer) error {
	starttime := time.Now()
	summary := &Summary{
		Query:  q,
		Status: Start,
	}
	// always call up to the listener
	defer func() {
		go r.listener.OnResponse(summary)
	}()

	msg, err := unpack(q)
	if err != nil {
		log.Warnf("not a dns packet %v", err)
		summary.Latency = time.Since(starttime).Seconds()
		summary.Status = BadQuery
		return err
	}

	// figure out transport to use
	qname := qname(msg)
	id := r.requiresSystem(qname)
	if len(id) <= 0 {
		id = r.listener.OnQuery(qname)
	} else {
		log.Infof("transport (tcp): using system-dns %s for %s", id, qname)
	}
	// retrieve transport
	r.RLock()
	var t Transport
	t, ok := r.transports[id]
	onet := r.pool[id]
	r.RUnlock()
	if !ok {
		summary.Latency = time.Since(starttime).Seconds()
		summary.Status = TransportError
		return errNoSuchTransport
	}

	// block query if needed (skipped for alg/block-free)
	res1, blocklists, err := r.block(t, msg)
	if err == nil {
		b, e := res1.Pack()
		summary.Latency = time.Since(starttime).Seconds()
		summary.Status = Complete
		summary.Blocklists = blocklists
		summary.Response = b
		writeto(c, b, len(b))
		return e
	}

	// query the transport
	summary.Type = t.Type()
	summary.ID = t.ID()
	res2, err := t.Query(NetTypeTCP, q, summary)

	if err != nil {
		// summary latency, ips, response, status already set by transport t
		return err
	}
	ans1, qerr := unpack(res2)
	if qerr != nil {
		summary.Status = BadResponse
		return qerr
	}

	ans2, blocklistnames := r.blockRes(t, msg, ans1, summary.Blocklists)
	// overwrite response when blocked
	if len(blocklistnames) > 0 {
		// summary latency, response, status, ips already set by transport t
		summary.Blocklists = blocklistnames
		ans1 = ans2
	}

	resp, qerr := ans1.Pack()
	if qerr != nil {
		summary.Status = BadResponse
		return qerr
	}
	rlen := len(resp)
	if rlen > xdns.MaxDNSPacketSize {
		summary.Status = BadResponse
		return fmt.Errorf("oversize response: %d", rlen)
	}

	// override resp with dns64 if needed
	if onet != nil {
		d64 := r.natpt.D64(t.ID(), res2, onet)
		rlen = len(resp)
		if rlen > xdns.MinDNSPacketSize {
			resp = d64
		}
	} else {
		log.Warnf("dns64: missing onetransport for %s", t.ID())
	}

	n, err := writeto(c, resp, rlen)
	if err != nil {
		summary.Status = InternalError
		return err
	}
	if n != rlen {
		summary.Status = InternalError
		return fmt.Errorf("incomplete response write: %d < %d", n, rlen)
	}
	return qerr
}

// Perform a query using the transport, send the response to the writer,
// and close the writer if there was an error.
func (r *resolver) forwardQueryAndCheck(q []byte, c io.WriteCloser) {
	if err := r.forwardQuery(q, c); err != nil {
		log.Warnf("Query forwarding failed: %v", err)
		c.Close()
	}
}

// Accept a DNS-over-TCP socket from a stub resolver, and connect the socket
// to this DNSTransport.
func (r *resolver) accept(c io.ReadWriteCloser) {
	defer c.Close()

	qlbuf := make([]byte, 2)
	for {
		n, err := c.Read(qlbuf)
		if n == 0 {
			log.Debugf("TCP query socket clean shutdown")
			break
		}
		if err != nil {
			log.Warnf("Error reading from TCP query socket: %v", err)
			break
		}
		// TODO: inform the listener?
		if n < 2 {
			log.Warnf("Incomplete query length")
			break
		}
		qlen := binary.BigEndian.Uint16(qlbuf)
		q := make([]byte, qlen)
		n, err = c.Read(q)
		if err != nil {
			log.Warnf("Error reading query: %v", err)
			break
		}
		if n != int(qlen) {
			log.Warnf("Incomplete query: %d < %d", n, qlen)
			break
		}
		go r.forwardQueryAndCheck(q, c)
	}
	// TODO: Cancel outstanding queries.
}

func unpack(q []byte) (*dns.Msg, error) {
	msg := &dns.Msg{}
	err := msg.Unpack(q)
	return msg, err
}

func qname(msg *dns.Msg) string {
	n := xdns.QName(msg)
	n, _ = xdns.NormalizeQName(n)
	return n
}

func (r *resolver) loadaddrs(csvaddr string) {
	r.fakeTcpAddr(csvaddr)
	r.fakeUdpAddr(csvaddr)
}

func writeto(w io.Writer, b []byte, l int) (int, error) {
	rlbuf := make([]byte, l+2)
	binary.BigEndian.PutUint16(rlbuf, uint16(l))
	copy(rlbuf[2:], b)
	// Use a combined write to ensure atomicity.
	// Otherwise, writes from two responses could be interleaved.
	return w.Write(rlbuf)
}
