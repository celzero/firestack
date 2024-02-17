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

// Assumes connected udp; see also: github.com/pion/transport/blob/03c807b/udp/conn.go

package intra

import (
	"errors"
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

// UDPHandler adds DOH support to the base UDPConnHandler interface.
type UDPHandler interface {
	netstack.GUDPConnHandler
}

type udpHandler struct {
	UDPHandler
	sync.RWMutex

	resolver    dnsx.Resolver
	conntracker core.ConnMapper // connid -> [local,remote]
	config      *net.ListenConfig
	dialer      *net.Dialer
	tunMode     *settings.TunMode
	listener    SocketListener
	prox        ipn.Proxies
	fwtracker   *core.ExpMap
	status      int
}

const (
	UDPOK = iota
	UDPEND
)

var (
	errUdpFirewalled = errors.New("udp: firewalled")
	errUdpSetupConn  = errors.New("udp: could not create conn")
	errUdpEnd        = errors.New("udp: end")
)

var (
	// RFC 4787 REQ-5 requires a timeout no shorter than 5 minutes; but most
	// routers do not keep udp mappings for that long (usually just for 30s)
	udptimeout, _ = time.ParseDuration("2m")
)

func makeTracker(cid, pid, uid string) *SocketSummary {
	return udpSummary(cid, pid, uid)
}

// NewUDPHandler makes a UDP handler with Intra-style DNS redirection:
// All packets are routed directly to their destination.
// `timeout` controls the effective NAT mapping lifetime.
// `config` is used to bind new external UDP ports.
// `listener` receives a summary about each UDP binding when it expires.
func NewUDPHandler(resolver dnsx.Resolver, prox ipn.Proxies, tunMode *settings.TunMode, ctl protect.Controller, listener SocketListener) UDPHandler {
	c := protect.MakeNsListenConfig("udphl", ctl)
	d := protect.MakeNsDialer("udph", ctl)
	h := &udpHandler{
		resolver:    resolver,
		tunMode:     tunMode,
		config:      c,
		dialer:      d,
		listener:    listener,
		prox:        prox,
		fwtracker:   core.NewExpiringMap(),
		conntracker: core.NewConnMap(),
		status:      UDPOK,
	}

	log.I("udp: new handler created")
	return h
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

// Proxy implements netstack.GUDPConnHandler
func (h *udpHandler) Proxy(gconn *netstack.GUDPConn, src, dst *net.UDPAddr) {
	const fin = true  // disconnect
	const ack = false // connect

	if h.status == UDPEND {
		log.D("udp: connect: end")
		gconn.Connect(fin) // disconnect, no nat
		return
	}

	var local core.UDPConn = gconn            // typecast here so h.track/h.probe work
	remote, smm, err := h.Connect(local, dst) // dst may be nil; smm is never nil

	if err != nil || remote == nil {
		gconn.Connect(fin)
		clos(local, remote)
		if smm != nil { // smm is never nil; but nilaway complains
			smm.done(err)
			go h.sendNotif(smm)
		} else {
			log.W("udp: on-new-conn: unexpected nil tracker %s -> %s; err %v", gconn.LocalAddr(), dst, err)
		}
		return
	}

	// err here may happen for ex when netstack has no route to dst
	if err := gconn.Connect(ack); err != nil {
		log.W("udp: on-new-conn: %s failed to connect %s -> %s; err %v", smm.ID, gconn.LocalAddr(), dst, err)
		clos(local, remote)
		smm.done(err)
		go h.sendNotif(smm)
		return
	} else {
		go func() {
			remote.SetDeadline(time.Now().Add(udptimeout))
			// TODO: SetDeadline extension needed for reads in forward() / io.Copy?
			forward(local, remote, h.conntracker, smm)
			h.sendNotif(smm)
		}()
	} // else: connection refused / failed
}

// Connect connects the proxy server.
// Note, target may be nil in lwip (deprecated) while it is always specified in netstack
func (h *udpHandler) Connect(src core.UDPConn, target *net.UDPAddr) (dst net.Conn, smm *SocketSummary, err error) {
	var px ipn.Proxy
	var pc protect.Conn

	realips, domains, probableDomains, blocklists := undoAlg(h.resolver, target.IP)

	// flow is alg/nat-aware, do not change target or any addrs
	res := h.onFlow(src, target, realips, domains, probableDomains, blocklists)
	smm = makeTracker(splitCidPidUid(res))

	if res.PID == ipn.Block {
		var secs uint32
		k := res.UID + target.String()
		if len(domains) > 0 { // probableDomains are not reliable for firewalling
			k = res.UID + domains
		}
		if secs = stall(h.fwtracker, k); secs > 0 {
			waittime := time.Duration(secs) * time.Second
			time.Sleep(waittime)
		}
		log.I("udp: %s conn firewalled from %s -> %s (dom: %s + %s/ real: %s); stall? %ds for uid %s", res.CID, src.LocalAddr(), target, domains, probableDomains, realips, secs, res.UID)
		return nil, smm, errUdpFirewalled // disconnect
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
	if res.PID != ipn.Exit {
		if dnsOverride(h.resolver, dnsx.NetTypeUDP, src, target) {
			// SocketSummary is not sent to listener; dnsx.Summary is
			return nil, smm, nil // connect, no dst
		} // else: not a dns query
	} // else: proxy src to dst

	if px, err = h.prox.GetProxy(res.PID); err != nil {
		log.W("udp: %s failed to get proxy for %s: %v", res.CID, res.PID, err)
		return nil, smm, err // disconnect
	}

	var errs error
	// note: fake-dns-ips shouldn't be un-nated / un-alg'd
	for i, dstip := range makeIPs(realips, target.IP) {
		target.IP = dstip
		if pc, err = px.Dial(target.Network(), target.String()); err == nil {
			errs = nil // reset errs
			break
		} // else try the next realip
		log.W("udp: connect: #%d: %s failed to bind addr(%s); for uid %s w err(%v)", i, res.CID, target, res.UID, err)
		errs = err // store just the last err; complicates logging
	}

	if errs != nil {
		return nil, smm, errs // disconnect
	}
	if pc == nil {
		log.W("udp: connect: %s failed to connect addr(%s); for uid %s", res.CID, target, res.UID)
		return nil, smm, errUdpSetupConn // disconnect
	}

	var ok bool
	if dst, ok = pc.(net.Conn); !ok {
		_ = pc.Close()
		log.E("udp: connect: %s proxy(%s) does not impl net.Conn(%s) for uid %s", res.CID, px.ID(), target, res.UID)
		return nil, smm, errUdpSetupConn // disconnect
	}

	log.I("udp: %s (proxy? %s@%s) %v -> %v for uid %s", res.CID, px.ID(), px.GetAddr(), dst.LocalAddr(), target, res.UID)

	return dst, smm, nil // connect
}

func (h *udpHandler) End() error {
	h.status = UDPEND
	h.CloseConns(nil)
	return nil
}

// CloseConns implements netstack.GUDPConnHandler
func (h *udpHandler) CloseConns(cids []string) (closed []string) {
	return closeconns(h.conntracker, cids)
}

func clos(c ...net.Conn) {
	for _, x := range c {
		if x != nil {
			x.Close()
		}
	}
}

// must always be called as a goroutine
func (h *udpHandler) sendNotif(s *SocketSummary) {
	if s == nil { // unlikely
		log.W("udp: sendNotif: nil summary; no-op")
		return
	}
	// sleep a bit to avoid scenario where kotlin-land
	// hasn't yet had the chance to persist info about
	// this conn (cid) to meaninfully process its summary
	time.Sleep(1 * time.Second)

	l := h.listener
	ok0 := h.status != UDPEND
	ok1 := l != nil
	ok2 := len(s.ID) > 0
	log.V("udp: end? %t sendNotif(%t,%t): %s", ok0, ok1, ok2, s.str())
	if ok1 && ok2 {
		l.OnSocketClosed(s) // s.Duration may be uninitialized (zero)
		return
	}
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
