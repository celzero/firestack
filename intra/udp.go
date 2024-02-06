// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     Copyright 2019 The Outline Authors
//
//     Licensed under the Apache License, Version 2.0 (the "License");
//     you may not use this file except in compliance with the License.
//     You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
//     Unless required by applicable law or agreed to in writing, software
//     distributed under the License is distributed on an "AS IS" BASIS,
//     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//     See the License for the specific language governing permissions and
//     limitations under the License.

// Derived from go-tun2socks's "direct" handler under the Apache 2.0 license.

package intra

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/netstack"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
)

const (
	// arbitrary threshold of temporary errs before udp socket is closed
	maxconnerr = 3
)

const (
	UDPOK = iota
	UDPEND
)

var (
	errUdpRead       = errors.New("udp: remote read fail")
	errUdpFirewalled = errors.New("udp: firewalled")
	errUdpSetupConn  = errors.New("udp: could not create conn")
	errUdpEnd        = errors.New("udp: end")
)

type tracker struct {
	*SocketSummary
	dst      any          // net.Conn or net.PacketConn; may be nil
	errcount int16        // conn splice err count
	ip       *net.UDPAddr // masked addr
}

func makeTracker(cid, pid, uid string) *tracker {
	smm := udpSummary(cid, pid, uid)
	return &tracker{smm, nil, 0, nil}
}

func (t *tracker) done(err error) {
	if t.SocketSummary != nil {
		t.SocketSummary.done(err)
	}
}

func (t *tracker) connected() bool {
	return t.dst != nil
}

func (t *tracker) ok() bool {
	return t.errcount <= maxconnerr
}

// UDPHandler adds DOH support to the base UDPConnHandler interface.
type UDPHandler interface {
	netstack.GUDPConnHandler
}

type udpHandler struct {
	UDPHandler
	sync.RWMutex

	resolver    dnsx.Resolver
	timeout     time.Duration
	udpConns    map[core.UDPConn]*tracker // src -> tracker(cid, dst)
	conntracker map[string]core.UDPConn   // cid -> src
	config      *net.ListenConfig
	dialer      *net.Dialer
	tunMode     *settings.TunMode
	listener    SocketListener
	prox        ipn.Proxies
	fwtracker   *core.ExpMap
	status      int
}

// NewUDPHandler makes a UDP handler with Intra-style DNS redirection:
// All packets are routed directly to their destination.
// `timeout` controls the effective NAT mapping lifetime.
// `config` is used to bind new external UDP ports.
// `listener` receives a summary about each UDP binding when it expires.
func NewUDPHandler(resolver dnsx.Resolver, prox ipn.Proxies, tunMode *settings.TunMode, ctl protect.Controller, listener SocketListener) UDPHandler {
	// RFC 4787 REQ-5 requires a timeout no shorter than 5 minutes; but most
	// routers do not keep udp mappings for that long (usually just for 30s)
	udptimeout, _ := time.ParseDuration("2m")
	c := protect.MakeNsListenConfig("udphl", ctl)
	d := protect.MakeNsDialer("udph", ctl)
	h := &udpHandler{
		timeout:     udptimeout,
		udpConns:    make(map[core.UDPConn]*tracker, 8),
		resolver:    resolver,
		tunMode:     tunMode,
		config:      c,
		dialer:      d,
		listener:    listener,
		prox:        prox,
		fwtracker:   core.NewExpiringMap(),
		conntracker: make(map[string]core.UDPConn),
		status:      UDPOK,
	}

	log.I("udp: new handler created")
	return h
}

func nc2str(conn core.UDPConn, c net.Conn, nat *tracker) string {
	laddr := c.LocalAddr()
	raddr := c.RemoteAddr()
	nsladdr := conn.LocalAddr()
	nsraddr := conn.RemoteAddr()
	return fmt.Sprintf("nc(l:%v [%v] <- r:%v [%v / n:%v])", laddr, nsladdr, nsraddr, raddr, nat.ip)
}

func pc2str(conn core.UDPConn, c net.PacketConn, nat *tracker) string {
	laddr := c.LocalAddr()
	nsladdr := conn.LocalAddr()
	nsraddr := conn.RemoteAddr()
	return fmt.Sprintf("pc(l:%v [%v] <- r:%v [ / n:%v])", laddr, nsladdr, nsraddr, nat.ip)
}

// fetchUDPInput reads from nat.dst to masqurade-write it to core.UDPConn
func (h *udpHandler) fetchUDPInput(conn core.UDPConn, nat *tracker) {
	defer func() {
		h.Close(conn)
	}()

	if ok := conn.Ready(); !ok {
		return
	}

	bptr := core.Alloc()
	buf := *bptr
	buf = buf[:cap(buf)]
	defer func() {
		*bptr = buf
		core.Recycle(bptr)
	}()

	var err error
	for {
		if h.status == UDPEND {
			log.D("udp: ingress: end", h.status)
			nat.done(errUdpEnd)
			return
		}
		if !nat.ok() {
			log.D("udp: ingress: too many errors (%v); latest(%v), closing", nat.errcount, err)
			nat.done(err) // err may be nil
			return
		}

		var n int
		var logaddr string
		var addr net.Addr
		// FIXME: ReadFrom seems to block for 50mins+ at times:
		// Cancel the goroutine in such cases and close the conns
		switch c := nat.dst.(type) { // assume nat.connected() == true
		// net.UDPConn is both net.Conn and net.PacketConn; check net.Conn
		// first, as it denotes a connected socket which netstack also uses
		case net.Conn:
			logaddr = nc2str(conn, c, nat)
			log.D("udp: ingress: read (c) remote for %s", logaddr)

			c.SetDeadline(time.Now().Add(h.timeout)) // extend deadline
			// c is already dialed-in to some addr in udpHandler.Connect
			n, err = c.Read(buf[:])
		case net.PacketConn: // unused
			logaddr = pc2str(conn, c, nat)
			log.D("udp: ingress: read (pc) remote for %s", logaddr)

			c.SetDeadline(time.Now().Add(h.timeout)) // extend deadline
			// reads a packet from t.conn copying it to buf
			n, addr, err = c.ReadFrom(buf[:])
		default:
			err = errUdpRead
		}

		// is err recoverable? github.com/miekg/dns/blob/f8a185d39/server.go#L521
		if neterr, ok := err.(net.Error); ok && neterr.Temporary() && !neterr.Timeout() {
			nat.errcount += 1
			log.I("udp: ingress: %s temp err#%d(%v)", logaddr, nat.errcount, err)
			continue
		} else if err != nil {
			log.I("udp: ingress: %s err(%v)", logaddr, err)
			nat.done(err)
			return
		}

		var udpaddr *net.UDPAddr
		if addr != nil {
			udpaddr, _ = addr.(*net.UDPAddr)
		} else if nat.ip != nil {
			// overwrite source-addr as set in t.ip
			udpaddr = nat.ip
		}

		log.D("udp: ingress: data(%d) from remote(pc?%v/masq:%v) | addrs: %s", n, addr, udpaddr, logaddr)

		if udpaddr == nil {
			log.W("udp: ingress: unexpected! %s is not a udpaddr [%s]", addr, logaddr)
			n, err = conn.Write(buf) // writes buf to conn (tun)
		} else {
			n, err = conn.WriteFrom(buf[:n], udpaddr) // writes buf to conn (tun) with udpaddr as src
		}
		if err != nil {
			log.W("udp: ingress: failed write to tun (%s) from %s; err %v; %dsecs", logaddr, udpaddr, err, nat.Duration)
			// for half-open: nat.errcount += 1 and continue
			// otherwise: return and close conn
			nat.done(err)
			return
		} else {
			nat.Rx += int64(n) // rcvd (download) so far
			nat.elapsed()      // time since last write
		}
	}
}

func (h *udpHandler) dnsOverride(conn core.UDPConn, addr *net.UDPAddr, query []byte) bool {
	// dst is nil if dns is to be overriden; see: h.Connect
	if !h.isDns(addr) {
		return false
	}
	// conn was only used for this DNS query, so it's unlikely to be used again.
	defer h.Close(conn)

	resp, err := h.resolver.Forward(query)
	if resp != nil {
		_, err = conn.WriteFrom(resp, addr)
	}
	if err != nil {
		log.W("udp: dns: query failed %v", err)
	}
	return true // handled
}

func (h *udpHandler) isDns(addr *net.UDPAddr) bool {
	// addr with zone information removed; see: netip.ParseAddrPort which h.resolver relies on
	// addr2 := &net.UDPAddr{IP: addr.IP, Port: addr.Port}
	return h.resolver.IsDnsAddr(addr.String())
}

func (h *udpHandler) onFlow(localudp core.UDPConn, target *net.UDPAddr, realips, domains, probableDomains, blocklists string) *Mark {
	// BlockModeNone returns false, BlockModeSink returns true
	if h.tunMode.BlockMode == settings.BlockModeSink {
		return optionsBlock
	}
	// todo: block-mode none should call into listener.Flow to determine upstream proxy
	if h.tunMode.BlockMode == settings.BlockModeNone {
		return optionsBase
	}

	source := localudp.LocalAddr()
	src := source.String()
	dst := target.String()
	if len(realips) <= 0 || len(domains) <= 0 {
		log.V("udp: onFlow: no realips(%s) or domains(%s + %s), for src=%s dst=%s", realips, domains, probableDomains, src, dst)
	}

	// Implict: BlockModeFilter or BlockModeFilterProc
	uid := -1
	if h.tunMode.BlockMode == settings.BlockModeFilterProc {
		srcaddr, err := udpAddrFrom(source)
		if err != nil {
			log.W("udp: onFlow: failed parsing src addr %s; err %v", src, err)
			return optionsBlock
		}

		procEntry := settings.FindProcNetEntry("udp", srcaddr.IP, srcaddr.Port, target.IP, target.Port)
		if procEntry != nil {
			uid = procEntry.UserID
		}
	}

	var proto int32 = 17 // udp
	res := h.listener.Flow(proto, uid, src, dst, realips, domains, probableDomains, blocklists)

	if res == nil {
		log.W("udp: onFlow: empty res from kt; optbase")
		return optionsBase
	} else if len(res.PID) <= 0 {
		log.W("udp: onFlow: no pid from kt; using base")
		res.PID = ipn.Base
	}

	return res
}

func ipportFromAddr(addr string) (ip net.IP, port int, err error) {
	var ipstr, portstr string
	ipstr, portstr, err = net.SplitHostPort(addr)
	if err != nil {
		return
	}
	ip = net.ParseIP(ipstr)
	port, err = strconv.Atoi(portstr)
	return ip, port, err
}

func udpAddrFrom(addr net.Addr) (*net.UDPAddr, error) {
	if addr == nil {
		return nil, &net.AddrError{Err: "nil addr", Addr: "<nil>"}
	}
	if r, ok := addr.(*net.UDPAddr); ok {
		return r, nil
	}
	ip, port, err := ipportFromAddr(addr.String())
	if err != nil {
		return nil, err
	}
	return &net.UDPAddr{
		IP:   ip,
		Port: port,
	}, nil
}

// OnNewConn implements netstack.GUDPConnHandler
func (h *udpHandler) OnNewConn(gconn *netstack.GUDPConn, _, dst *net.UDPAddr) {
	finish := true   // disconnect
	forward := false // connect

	if h.status == UDPEND {
		log.D("udp: connect: end")
		gconn.Connect(finish) // disconnect, no nat
		return
	}

	var conn core.UDPConn = gconn  // typecast here so h.track/h.probe work
	t, err := h.Connect(conn, dst) // t is never nil

	if err != nil { // no nat
		gconn.Connect(finish)
		if t != nil { // t is never nil; but nilaway complains
			t.done(err)
		} else {
			log.W("udp: on-new-conn: unexpected nil tracker %s -> %s; err %v", gconn.LocalAddr(), dst, err)
		}
		h.Close(conn)
		return
	}
	// err here may happen for ex when netstack has no route to dst
	if nerr := gconn.Connect(forward); nerr != nil {
		err := errors.New(nerr.String())
		log.W("udp: on-new-conn: failed to connect %s -> %s; err %v", gconn.LocalAddr(), dst, err)
		t.done(err)
		h.Close(conn)
		return
	}
}

// Connect connects the proxy server.
// Note, target may be nil in lwip (deprecated) while it may be unspecified in netstack
func (h *udpHandler) Connect(src core.UDPConn, target *net.UDPAddr) (nat *tracker, err error) {
	var px ipn.Proxy
	var pc protect.Conn
	var dst net.Conn

	realips, domains, probableDomains, blocklists := undoAlg(h.resolver, target.IP)

	// flow is alg/nat-aware, do not change target or any addrs
	res := h.onFlow(src, target, realips, domains, probableDomains, blocklists)
	nat = makeTracker(splitCidPidUid(res))
	h.track(src, nat)

	defer func() {
		if dst != nil {
			nat.dst = dst

			// the actual ip the client sees data from; unused in netstack
			nat.ip = &net.UDPAddr{
				IP:   target.IP,
				Port: target.Port,
				Zone: target.Zone,
			}
		}
	}()

	if nat.PID == ipn.Block {
		var secs uint32
		k := nat.UID + target.String()
		if len(domains) > 0 { // probableDomains are not reliable for firewalling
			k = nat.UID + domains
		}
		if secs = stall(h.fwtracker, k); secs > 0 {
			waittime := time.Duration(secs) * time.Second
			time.Sleep(waittime)
		}
		log.I("udp: %s conn firewalled from %s -> %s (dom: %s + %s/ real: %s); stall? %ds for uid %s", nat.ID, src.LocalAddr(), target, domains, probableDomains, realips, secs, nat.UID)
		return nat, errUdpFirewalled // disconnect
	}

	// requests meant for ipn.Exit are always routed to it
	// and never to whatever is set as DNS upstream.
	// Ex: If kotlin-land initiates a DNS query (with InetAddress),
	// it is routed to the tunnel's fake DNS addr, which is trapped by
	// by h.dnsOverride that forwards it to one of the dnsx Transports.
	// These dnsx Transports route the query back into the tunnel when
	// Rethink-within-Rethink routing is enabled. If this dnsx Transport
	// is forwarding queries to ANY DNS upstream on port 53 (dns53)
	// (see h.resolver.isDns), then the request again is trapped and
	// routed back to the dnsx Transport. To avoid this loop, when
	// Rethink-within-Rethink routing is enabled, kotlin-land
	// is expected to mark ipn.Base for queries to be trapped and sent
	// to user-preferred dnsx Transport, and ipn.Exit for queries to be
	// dialed as an outgoing protected connection. In practice, when
	// Rethink-within-Rethink routing is enabled and a DNS connection
	// as seen (with Flow) is owned by Rethink, then expect the conn
	// to be marked ipn.Base for queries sent to tunnel's fake DNS addr
	// and ipn.Exit for anywhere else.
	if nat.PID != ipn.Exit && h.isDns(target) {
		return nat, nil // connect, no dst
	}

	if px, err = h.prox.GetProxy(nat.PID); err != nil {
		log.W("udp: failed to get proxy for %s: %v", nat.PID, err)
		return nat, err // disconnect
	}

	var errs error
	// note: fake-dns-ips shouldn't be un-nated / un-alg'd
	for i, dstip := range makeIPs(realips, target.IP) {
		target.IP = dstip
		if pc, err = px.Dial(target.Network(), target.String()); err == nil {
			errs = nil // reset errs
			break
		} // else try the next realip
		log.W("udp: connect: #%d: %s failed to bind addr(%s); for uid %s w err(%v)", i, nat.ID, target, nat.UID, err)
		errs = err // store just the last err; complicates logging
	}

	if errs != nil {
		return nat, errs // disconnect
	}
	if pc == nil {
		log.W("udp: connect: %s failed to connect addr(%s); for uid %s", nat.ID, target, nat.UID)
		return nat, errUdpSetupConn // disconnect
	}

	var ok bool
	if dst, ok = pc.(net.Conn); !ok {
		pc.Close()
		log.E("udp: connect: %s proxy(%s) does not impl net.Conn(%s) for uid %s", nat.ID, px.ID(), target, nat.UID)
		return nat, errUdpSetupConn // disconnect
	}

	go h.fetchUDPInput(src, nat)

	log.I("udp: connect: %s (proxy? %s@%s) %v -> %v for uid %s", nat.ID, px.ID(), px.GetAddr(), dst.LocalAddr(), target, nat.UID)

	return nat, nil // connect
}

// HandleData implements netstack.GUDPConnHandler
func (h *udpHandler) HandleData(src *netstack.GUDPConn, data []byte, addr net.Addr) error {
	if h.status == UDPEND {
		log.D("udp: handle-data: end")
		return errUdpEnd
	}
	dst, err := udpAddrFrom(addr)
	if err != nil {
		log.E("udp: handle-data: failed to parse dst(%s); err(%v)", addr, err)
		return err
	}
	return h.ReceiveTo(src, data, dst)
}

func (h *udpHandler) End() error {
	h.status = UDPEND
	return nil
}

// ReceiveTo is called when data arrives from conn (tun).
func (h *udpHandler) ReceiveTo(conn core.UDPConn, data []byte, addr *net.UDPAddr) (err error) {
	nsladdr := conn.LocalAddr()
	nsraddr := conn.RemoteAddr()
	raddr := addr

	nat, _ := h.probe(conn)

	if nat == nil { // no nat
		log.W("udp: egress: no-op; closed? no nat(%v -> %v [%v])", nsladdr, raddr, nsraddr)
		return fmt.Errorf("udp: egress: nat %v -> %v [%v] does not exist", nsladdr, raddr, nsraddr)
	}
	if !nat.connected() { // no nat conn; see h.Connect
		if h.dnsOverride(conn, addr, data) { // if dns request; handle it
			log.D("udp: egress: dns-op; dstaddr(%v) <- src(l:%v r:%v)", raddr, nsladdr, nsraddr)
			return nil
		}
		return fmt.Errorf("udp: egress: conn %v -> %v [%v] does not exist", nsladdr, raddr, nsraddr)
	}

	// unused in netstack as it only supports connected udp
	// that is, udpconn.writeFrom(data, addr) isn't supported
	nat.ip = &net.UDPAddr{
		IP:   addr.IP,
		Port: addr.Port,
		Zone: addr.Zone,
	}

	nat.Tx += int64(len(data))

	switch c := nat.dst.(type) {
	// net.UDPConn is both net.Conn and net.PacketConn; check net.Conn
	// first, as it denotes a connected socket which netstack also uses
	case net.Conn:
		c.SetDeadline(time.Now().Add(h.timeout))
		// c is already dialed-in to some addr in udpHandler.Connect
		_, err = c.Write(data)
	case net.PacketConn: // unused
		c.SetDeadline(time.Now().Add(h.timeout))
		// realips, _, _, _ := undoAlg(h.resolver, addr.IP)
		// addr.IP = oneRealIp(realips, addr.IP)
		_, err = c.WriteTo(data, addr) // writes packet payload, data, to addr
	default:
		err = errUdpSetupConn
	}

	// is err recoverable?
	// ref: github.com/miekg/dns/blob/f8a185d39/server.go#L521
	if neterr, ok := err.(net.Error); ok && neterr.Temporary() {
		nat.errcount += 1
		if !nat.ok() {
			log.W("udp: egress: too many errors(%d) for conn(l:%v -> r:%v [%v]) for uid %s", nat.errcount, nsladdr, raddr, nsraddr, nat.UID)
			return err
		} else {
			log.W("udp: egress: temporary error(%v) for conn(l:%v -> r:%v [%v]) for uid %s", err, nsladdr, raddr, nsraddr, nat.UID)
			return nil
		}
	} else if err != nil {
		log.I("udp: egress: end splice (%v -> %v [%v]), forward udp for uid %s w err(%v)", conn.LocalAddr(), raddr, nsraddr, nat.UID, err)
		return err
	} else {
		nat.errcount = 0
	}

	log.I("udp: egress: conn(%v -> %v [%v]) / data(%d) for uid %s", nsladdr, raddr, nsraddr, len(data), nat.UID)
	return nil
}

func (h *udpHandler) CloseConns(cids []string) []string {
	h.RLock()
	defer h.RUnlock()

	var closed []string
	// Close all conns for the given cids
	for _, cid := range cids {
		if src, ok := h.conntracker[cid]; ok {
			go h.Close(src)
			closed = append(closed, cid)
		}
	}
	log.I("udp: closed %d/%d conns", len(closed), len(cids))
	return closed
}

func (h *udpHandler) probe(c core.UDPConn) (t *tracker, ok bool) {
	h.RLock()
	defer h.RUnlock()
	t, ok = h.udpConns[c]
	return
}

func (h *udpHandler) track(c core.UDPConn, t *tracker) {
	h.Lock()
	h.udpConns[c] = t
	h.conntracker[t.ID] = c
	h.Unlock()
}

func (h *udpHandler) untrack(c core.UDPConn) *tracker {
	h.Lock()
	defer h.Unlock()
	t := h.udpConns[c]
	delete(h.udpConns, c)
	if t != nil {
		delete(h.conntracker, t.ID)
	} else {
		log.W("udp: untrack: not found; conn(%v)", c)
	}
	return t // may be nil
}

func (h *udpHandler) Close(conn core.UDPConn) {
	if conn == nil {
		log.W("udp: close: nil conn; no-op")
		return
	}

	local := conn.LocalAddr()
	remote := conn.RemoteAddr()
	close(conn)
	t := h.untrack(conn)
	if t != nil {
		clos(t.dst)
		// TODO: Cancel any outstanding dns queries
		go h.sendNotif(t.SocketSummary)
	}

	log.D("udp: close conn [%v -> %v]; tracked? %t", local, remote, t != nil)
}

func clos(c any) {
	if c == nil {
		return
	}
	switch x := c.(type) {
	case io.Closer:
		x.Close()
	default:
		log.W("clos: type %T is not %T", c, x)
	}
}

// must always be called as a goroutine
func (h *udpHandler) sendNotif(s *SocketSummary) {
	// sleep a bit to avoid scenario where kotlin-land
	// hasn't yet had the chance to persist info about
	// this conn (cid) to meaninfully process its summary
	time.Sleep(1 * time.Second)

	l := h.listener
	ok0 := h.status != UDPEND
	ok1 := l != nil
	ok2 := len(s.ID) > 0
	if ok0 && ok1 && ok2 {
		log.V("udp: sendNotif(true): %s", s.str())
		l.OnSocketClosed(s) // s.Duration may be uninitialized (zero)
		return
	} else {
		log.V("udp: sendNotif(%t, %t, %t): no listener", ok0, ok1, ok2)
	}
}
