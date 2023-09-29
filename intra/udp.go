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
	"net"
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

var notimetrack int32 = -1

type tracker struct {
	id       string       // unique identifier for this connection
	pid      string       // proxy id
	uid      string       // uid that created this connection
	conn     any          // net.Conn and net.PacketConn
	start    time.Time    // creation time
	upload   int64        // Non-DNS upload bytes
	download int64        // Non-DNS download bytes
	errcount int16        // conn splice err count
	msg      string       // last error
	ip       *net.UDPAddr // masked addr
}

func makeTracker(cid, pid, uid string, conn any) *tracker {
	return &tracker{cid, pid, uid, conn, time.Now(), 0, 0, 0, noerr.Error(), nil}
}

func (t *tracker) elapsed() int32 {
	return int32(time.Since(t.start).Seconds())
}

// UDPHandler adds DOH support to the base UDPConnHandler interface.
type UDPHandler interface {
	netstack.GUDPConnHandler
}

type udpHandler struct {
	UDPHandler
	sync.RWMutex

	resolver  dnsx.Resolver
	timeout   time.Duration
	udpConns  map[core.UDPConn]*tracker
	config    *net.ListenConfig
	dialer    *net.Dialer
	tunMode   *settings.TunMode
	listener  SocketListener
	prox      ipn.Proxies
	fwtracker *core.ExpMap
	status    int
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
		timeout:   udptimeout,
		udpConns:  make(map[core.UDPConn]*tracker, 8),
		resolver:  resolver,
		tunMode:   tunMode,
		config:    c,
		dialer:    d,
		listener:  listener,
		prox:      prox,
		fwtracker: core.NewExpiringMap(),
		status:    UDPOK,
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

// fetchUDPInput reads from nat.conn to masqurade-write it to core.UDPConn
func (h *udpHandler) fetchUDPInput(conn core.UDPConn, nat *tracker) {
	elapsed := notimetrack
	defer func() {
		h.Close(conn, elapsed)
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
			nat.msg = errUdpEnd.Error()
			return
		}
		if nat.errcount > maxconnerr {
			log.D("udp: ingress: too many errors (%v); latest(%v), closing", nat.errcount, err)
			nat.msg = err.Error()
			return
		}

		var n int
		var logaddr string
		var addr net.Addr
		// FIXME: ReadFrom seems to block for 50mins+ at times:
		// Cancel the goroutine in such cases and close the conns
		switch c := nat.conn.(type) {
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
			nat.msg = err.Error()
			return
		}

		var udpaddr *net.UDPAddr
		if addr != nil {
			udpaddr = addr.(*net.UDPAddr)
		} else if nat.ip != nil {
			// overwrite source-addr as set in t.ip
			udpaddr = nat.ip
		}

		log.D("udp: ingress: data(%d) from remote(pc?%v/masq:%v) | addrs: %s", n, addr, udpaddr, logaddr)

		_, err = conn.WriteFrom(buf[:n], udpaddr) // writes buf to conn (tun) with udpaddr as src
		elapsed = nat.elapsed()                   // track time since last write
		nat.download += int64(n)                  // track data downloaded
		if err != nil {
			log.W("udp: ingress: failed write to tun (%s) from %s; err %v; %dsecs", logaddr, udpaddr, err, elapsed)
			// for half-open: nat.errcount += 1 and continue
			// otherwise: return and close conn
			return
		}
	}
}

func (h *udpHandler) dnsOverride(conn core.UDPConn, addr *net.UDPAddr, query []byte) bool {
	if !h.isDns(addr) {
		return false
	}
	// conn was only used for this DNS query, so it's unlikely to be used again.
	defer h.Close(conn, notimetrack)

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
	addr2 := &net.UDPAddr{IP: addr.IP, Port: addr.Port}
	return h.resolver.IsDnsAddr(dnsx.NetTypeUDP, addr2.String())
}

func (h *udpHandler) onFlow(localudp core.UDPConn, target *net.UDPAddr, realips, domains, blocklists string) *Mark {
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
		log.V("udp: onFlow: no realips(%s) or domains(%s), for src=%s dst=%s", realips, domains, src, dst)
	}

	// Implict: BlockModeFilter or BlockModeFilterProc
	uid := -1
	if h.tunMode.BlockMode == settings.BlockModeFilterProc {
		procEntry := settings.FindProcNetEntry("udp", source.IP, source.Port, target.IP, target.Port)
		if procEntry != nil {
			uid = procEntry.UserID
		}
	}

	var proto int32 = 17 // udp
	res := h.listener.Flow(proto, uid, src, dst, realips, domains, blocklists)

	if len(res.PID) <= 0 {
		log.W("udp: empty flow from kt; using base")
		res.PID = ipn.Base
	}

	return res
}

// OnNewConn implements netstack.GUDPConnHandler
func (h *udpHandler) OnNewConn(gconn *netstack.GUDPConn, _, dst *net.UDPAddr) {
	finish := true // disconnect
	decision, err := h.Connect(gconn, dst)
	pid, cid, uid := splitPidCidUid(decision)
	if err != nil {
		go h.sendNotif(cid, pid, uid, err.Error(), 0, 0, 0)
	} else {
		finish = false // connect
	}
	nerr := gconn.Connect(finish)
	if nerr != nil { // may happen for ex when netstack has no route to dst
		go h.sendNotif(cid, pid, uid, nerr.String(), 0, 0, 0)
	}
}

// Connect connects the proxy server.
// Note, target may be nil in lwip (deprecated) while it may be unspecified in netstack
func (h *udpHandler) Connect(conn core.UDPConn, target *net.UDPAddr) (res *Mark, err error) {
	if h.status == UDPEND {
		log.D("udp: connect: end")
		return nil, errUdpEnd
	}

	var px ipn.Proxy
	var pc protect.Conn

	realips, domains, blocklists := undoAlg(h.resolver, target.IP)
	ipx4 := maybeUndoNat64(h.resolver, realips, target.IP)

	// flow is alg/nat-aware, do not change target or any addrs
	res = h.onFlow(conn, target, realips, domains, blocklists)

	localaddr := conn.LocalAddr()
	pid, cid, uid := splitPidCidUid(res)

	if pid == ipn.Block {
		var secs uint32
		k := uid + target.String()
		if len(domains) > 0 {
			k = uid + domains
		}
		if secs = stall(h.fwtracker, k); secs > 0 {
			waittime := time.Duration(secs) * time.Second
			time.Sleep(waittime)
		}
		log.I("udp: conn firewalled from %s -> %s (dom: %s/ real: %s); stall? %ds", localaddr, target, domains, realips, secs)
		return res, errUdpFirewalled // disconnect
	}

	if h.isDns(target) {
		return res, nil // connect
	}

	if px, err = h.prox.GetProxy(pid); err != nil {
		log.W("udp: failed to get proxy for %s: %v", pid, err)
		return res, err // disconnect
	}

	// note: fake-dns-ips shouldn't be un-nated / un-alg'd
	// alg happens before nat64, and so, alg has no knowledge of nat-ed ips
	// ipx4 is un-nated (and same as target.IP when no nat64 is involved)
	// but ipx4 might itself be an alg ip; so check if there's a real-ip to connect to
	// ie, must send to un-nated ips; overwrite target.IP with ipx4
	target.IP = oneRealIp(realips, ipx4)

	// deprecated: github.com/golang/go/issues/25104
	if pc, err = px.Dial(target.Network(), target.String()); err != nil {
		log.E("udp: connect: failed to bind addr(%s); err(%v)", target, err)
		return res, err // disconnect
	}

	var ok bool
	var c net.Conn
	if c, ok = pc.(net.Conn); !ok {
		log.E("udp: connect: proxy(%s) does not implement net.Conn(%s)", px.ID(), target)
		return res, errUdpSetupConn // disconnect
	}

	nat := makeTracker(cid, pid, uid, c)

	// the actual ip the client sees data from
	// unused in netstack
	nat.ip = &net.UDPAddr{
		IP:   target.IP,
		Port: target.Port,
		Zone: target.Zone,
	}

	h.Lock()
	h.udpConns[conn] = nat
	h.Unlock()

	go h.fetchUDPInput(conn, nat)

	log.I("udp: connect: (proxy? %s@%s) %v -> %v", px.ID(), px.GetAddr(), c.LocalAddr(), target)

	return res, nil // connect
}

// HandleData implements netstack.GUDPConnHandler
func (h *udpHandler) HandleData(conn *netstack.GUDPConn, data []byte, addr *net.UDPAddr) error {
	if h.status == UDPEND {
		log.D("udp: handle-data: end")
		return errUdpEnd
	}
	return h.ReceiveTo(conn, data, addr)
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

	if h.dnsOverride(conn, addr, data) {
		log.D("udp: egress: dns-override for dstaddr(%v) <- src(l:%v r:%v)", raddr, nsladdr, nsraddr)
		return nil
	}

	h.RLock()
	nat, ok1 := h.udpConns[conn]
	h.RUnlock()

	if !ok1 {
		log.W("udp: egress: no nat(%v -> %v [%v])", nsladdr, raddr, nsraddr)
		return fmt.Errorf("conn %v -> %v [%v] does not exist", nsladdr, raddr, nsraddr)
	}

	// unused in netstack as it only supports connected udp
	// that is, udpconn.writeFrom(data, addr) isn't supported
	nat.ip = &net.UDPAddr{
		IP:   addr.IP,
		Port: addr.Port,
		Zone: addr.Zone,
	}

	// send data to un-nated ips; overwrite target.IP with ipx4
	// alg happens before nat64, and so, alg has no knowledge of nat-ed ips
	// ipx4 is un-nated (and equal to target.IP when no nat64 is involved)
	realips, _, _ := undoAlg(h.resolver, addr.IP)
	ipx4 := maybeUndoNat64(h.resolver, realips, addr.IP)
	// but ipx4 might itself be an alg ip; so check if there's a real-ip to connect to
	addr.IP = oneRealIp(realips, ipx4)

	nat.upload += int64(len(data))

	switch c := nat.conn.(type) {
	// net.UDPConn is both net.Conn and net.PacketConn; check net.Conn
	// first, as it denotes a connected socket which netstack also uses
	case net.Conn:
		// Update deadline.
		c.SetDeadline(time.Now().Add(h.timeout))
		// c is already dialed-in to some addr in udpHandler.Connect
		_, err = c.Write(data)
	case net.PacketConn: // unused
		// Update deadline.
		c.SetDeadline(time.Now().Add(h.timeout))
		// writes packet payload, data, to addr
		_, err = c.WriteTo(data, addr)
	default:
		err = errUdpSetupConn
	}

	// is err recoverable?
	// ref: github.com/miekg/dns/blob/f8a185d39/server.go#L521
	if neterr, ok := err.(net.Error); ok && neterr.Temporary() {
		nat.errcount += 1
		if nat.errcount > maxconnerr {
			log.W("udp: egress: too many errors(%d) for conn(l:%v -> r:%v [%v])", nat.errcount, nsladdr, raddr, nsraddr)
			return err
		} else {
			log.W("udp: egress: temporary error(%v) for conn(l:%v -> r:%v [%v])", err, nsladdr, raddr, nsraddr)
			return nil
		}
	} else if err != nil {
		log.I("udp: egress: end splice (%v -> %v [%v]), forward udp err(%v)", conn.LocalAddr(), raddr, nsraddr, err)
		return err
	} else {
		nat.errcount = 0
	}

	log.I("udp: egress: conn(%v -> %v [%v]) / data(%d)", nsladdr, raddr, nsraddr, len(data))
	return nil
}

func (h *udpHandler) Close(conn core.UDPConn, secs int32) {
	log.V("udp: closing conn [%v -> %v]", conn.LocalAddr(), conn.RemoteAddr())
	conn.Close()

	h.Lock()
	defer h.Unlock()

	if t, ok := h.udpConns[conn]; ok {
		switch c := t.conn.(type) {
		case net.PacketConn: // unused
			c.Close()
		case net.Conn:
			c.Close()
		default:
		}

		elapsed := secs
		if elapsed == notimetrack {
			elapsed = t.elapsed()
		}
		// TODO: Cancel any outstanding DoH queries.
		go h.sendNotif(t.id, t.pid, t.uid, t.msg, t.upload, t.download, elapsed)
		delete(h.udpConns, conn)
	}
}

// must always be called as a goroutine
func (h *udpHandler) sendNotif(cid, pid, uid, msg string, up, down int64, elapsed int32) {
	// sleep a bit to avoid scenario where kotlin-land
	// hasn't yet had the chance to persist info about
	// this conn (cid) to meaninfully process its summary
	time.Sleep(1 * time.Second)

	l := h.listener
	ok0 := h.status != UDPEND
	ok1 := l != nil
	ok2 := len(cid) > 0
	if ok0 && ok1 && ok2 {
		s := &SocketSummary{
			Proto:    ProtoTypeUDP,
			ID:       cid,
			PID:      pid,
			UID:      uid,
			Msg:      msg,
			Tx:       up,
			Rx:       down,
			Duration: elapsed,
		}
		log.V("udp: sendNotif(true): %s", s.str())
		l.OnSocketClosed(s)
		return
	} else {
		log.V("udp: sendNotif(%t, %t, %t): no listener", ok0, ok1, ok2)
	}
}
