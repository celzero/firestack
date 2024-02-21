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
	"net/netip"
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
	tunMode     *settings.TunMode
	listener    SocketListener
	prox        ipn.Proxies
	fwtracker   *core.ExpMap
	status      int
}

// rwext wraps net.Conn and extends deadline by
// udptimeout on read and write.
type rwext struct {
	core.UDPConn
}

const (
	UDPOK = iota
	UDPEND
)

var (
	errUdpFirewalled = errors.New("udp: firewalled")
	errUdpSetupConn  = errors.New("udp: could not create conn")
)

var (
	// RFC 4787 REQ-5 requires a timeout no shorter than 5 minutes; but most
	// routers do not keep udp mappings for that long (usually just for 30s)
	udptimeout, _ = time.ParseDuration("2m")
)

func (rw *rwext) Read(b []byte) (n int, err error) {
	rw.UDPConn.SetDeadline(time.Now().Add(udptimeout))
	return rw.UDPConn.Read(b)
}

func (rw *rwext) Write(b []byte) (n int, err error) {
	rw.UDPConn.SetDeadline(time.Now().Add(udptimeout))
	return rw.UDPConn.Write(b)
}

func makeTracker(cid, pid, uid string) *SocketSummary {
	return udpSummary(cid, pid, uid)
}

// NewUDPHandler makes a UDP handler with Intra-style DNS redirection:
// All packets are routed directly to their destination.
// `timeout` controls the effective NAT mapping lifetime.
// `config` is used to bind new external UDP ports.
// `listener` receives a summary about each UDP binding when it expires.
func NewUDPHandler(resolver dnsx.Resolver, prox ipn.Proxies, tunMode *settings.TunMode, ctl protect.Controller, listener SocketListener) UDPHandler {
	h := &udpHandler{
		resolver:    resolver,
		tunMode:     tunMode,
		listener:    listener,
		prox:        prox,
		fwtracker:   core.NewExpiringMap(),
		conntracker: core.NewConnMap(),
		status:      UDPOK,
	}

	log.I("udp: new handler created")
	return h
}

func (h *udpHandler) onFlow(localaddr, target netip.AddrPort, realips, domains, probableDomains, blocklists string) *Mark {
	// BlockModeNone returns false, BlockModeSink returns true
	if h.tunMode.BlockMode == settings.BlockModeSink {
		return optionsBlock
	}
	// todo: block-mode none should call into listener.Flow to determine upstream proxy
	if h.tunMode.BlockMode == settings.BlockModeNone {
		return optionsBase
	}

	src := localaddr.String()
	dst := "" // unconnected udp sockets may not have a valid target
	if target.IsValid() {
		dst = target.String()
	}
	if len(realips) <= 0 || len(domains) <= 0 {
		log.V("udp: onFlow: no realips(%s) or domains(%s + %s), for src=%s dst=%s", realips, domains, probableDomains, localaddr, dst)
	}

	// Implict: BlockModeFilter or BlockModeFilterProc
	uid := -1
	if h.tunMode.BlockMode == settings.BlockModeFilterProc {
		procEntry := settings.FindProcNetEntry("udp", localaddr, target)
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

// ProxyMux implements netstack.GUDPConnHandler
func (h *udpHandler) ProxyMux(gconn *netstack.GUDPConn, src netip.AddrPort) (ok bool) {
	log.I("udp: mux for %s", src)
	// only ipn.Exit and ipn.Base support udp mux / packet conns
	const fin = true  // disconnect
	const ack = false // connect
	var invalidaddr = netip.AddrPort{}

	if h.status == UDPEND {
		log.D("udp: connect: end")
		gconn.Connect(fin) // disconnect, no nat
		return             // not ok
	}

	// connect (register endpoint) right away, since new packets needn't be
	// handled / assumed as a new conn (endpoint) by netstack
	gerr := gconn.Connect(ack)

	l := h.listener
	local, smm, err := h.Connect(gconn, src, invalidaddr) // local may be nil; smm is never nil

	if err != nil || gerr != nil || local == nil {
		clos(gconn, local)
		if smm != nil { // smm is never nil; but nilaway complains
			smm.done(err)
			go sendNotif(l, smm)
		} else {
			log.W("udp: proxy: unexpected %s -> [unconnected]; netstack err: %v; dst err: %v", src, gerr, err)
		}
		return // not ok
	}
	mxr := newMuxer(local)
	go func() {
		for {
			dxconn, err := mxr.vend()
			if err != nil {
				log.I("udp: proxy: %s vend for %s done; err? %v", smm.ID, src, err)
				break
			}
			if dst, err := ipp(dxconn.RemoteAddr()); err != nil || dst.Addr().IsUnspecified() || !dst.IsValid() {
				log.W("udp: proxy: %s bad dst ipport %s -> %s; err: %v", smm.ID, src, dst, err)
				clos(dxconn)
			} else {
				log.I("udp: proxy: %s mux for %s -> %s", smm.ID, src, dst)
				h.proxy(dxconn, src, dst)
			}
		}
		log.I("udp: proxy: %s mux for %s done", smm.ID, mxr.stats)
	}()
	return true // ok
}

// Proxy implements netstack.GUDPConnHandler
func (h *udpHandler) Proxy(gconn *netstack.GUDPConn, src, dst netip.AddrPort) (ok bool) {
	return h.proxy(gconn, src, dst)
}

func (h *udpHandler) proxy(gconn net.Conn, src, dst netip.AddrPort) (ok bool) {
	// const fin = true  // disconnect
	const ack = false // connect
	if h.status == UDPEND {
		log.D("udp: connect: end")
		clos(gconn) // disconnect, no nat
		return      // not ok
	}

	// if gconn is a netstack.GUDPConn, then it is not connected.
	// connect right away, since we assume a duplex-stream from here on
	// see: h.Connect -> dnsOverride
	var gerr error
	if gc, ok := gconn.(*netstack.GUDPConn); ok {
		gerr = gc.Connect(ack)
	} // not a *netstack.GUDPConn, may be *demuxconn

	l := h.listener
	remote, smm, err := h.Connect(gconn, src, dst) // remote may be nil; smm is never nil

	if err != nil || gerr != nil {
		clos(gconn, remote)
		if smm != nil { // smm is never nil; but nilaway complains
			smm.done(err)
			go sendNotif(l, smm)
		} else {
			log.W("udp: proxy: unexpected %s -> %s; netstack err: %v; dst err: %v", src, dst, gerr, err)
		}
		return // not ok
	} else if remote == nil { // dnsOverride?
		return true // ok
	}
	go func() {
		cm := h.conntracker
		defer func() {
			if r := recover(); r != nil {
				log.W("udp: forward: %s -> %s panic %v", src, dst, r)
			}
		}()

		forward(gconn, &rwext{remote}, cm, l, smm)
	}()
	return true // ok
}

// Connect connects the proxy server.
// Note, target may be nil in lwip (deprecated) while it is always specified in netstack
func (h *udpHandler) Connect(gconn net.Conn, src, target netip.AddrPort) (dst core.UDPConn, smm *SocketSummary, err error) {
	var px ipn.Proxy
	var pc protect.Conn

	realips, domains, probableDomains, blocklists := undoAlg(h.resolver, target.Addr())

	// flow is alg/nat-aware, do not change target or any addrs
	res := h.onFlow(src, target, realips, domains, probableDomains, blocklists)
	smm = makeTracker(splitCidPidUid(res))

	if res.PID == ipn.Block {
		var secs uint32
		k := res.UID + target.String() // UID may be unknown and target may be invalid addr
		if len(domains) > 0 {          // probableDomains are not reliable for firewalling
			k = res.UID + domains
		}
		if secs = stall(h.fwtracker, k); secs > 0 {
			waittime := time.Duration(secs) * time.Second
			time.Sleep(waittime)
		}
		log.I("udp: %s conn firewalled from %s -> %s (dom: %s + %s/ real: %s); stall? %ds for uid %s", res.CID, src, target, domains, probableDomains, realips, secs, res.UID)
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
		if dnsOverride(h.resolver, dnsx.NetTypeUDP, gconn, target) {
			// SocketSummary is not sent to listener; dnsx.Summary is
			return nil, smm, nil // connect, no dst
		} // else: not a dns query
	} // else: proxy src to dst

	if px, err = h.prox.GetProxy(res.PID); err != nil {
		log.W("udp: %s failed to get proxy for %s: %v", res.CID, res.PID, err)
		return nil, smm, err // disconnect
	}

	var errs error

	// unconnected udp socket?
	if target.Addr().IsUnspecified() || !target.IsValid() {
		log.I("udp: unconnected udp at (%s) for uid %s via %s", src, res.UID, px.ID())
		pc, errs = px.Announce("udp", src.String())
	} else {
		// note: fake-dns-ips shouldn't be un-nated / un-alg'd
		for i, dstipp := range makeIPPorts(realips, target, 0) {
			if pc, err = px.Dial("udp", dstipp.String()); err == nil {
				errs = nil // reset errs
				break
			} // else try the next realip
			log.W("udp: connect: #%d: %s failed; addr(%s); for uid %s w err(%v)", i, res.CID, dstipp, res.UID, err)
			errs = err // store just the last err; complicates logging
		}
	}

	if errs != nil {
		return nil, smm, errs // disconnect
	}
	if pc == nil {
		log.W("udp: connect: %s failed to connect addr(%s); for uid %s", res.CID, target, res.UID)
		return nil, smm, errUdpSetupConn // disconnect
	}

	var ok bool
	if dst, ok = pc.(core.UDPConn); !ok { // todo: typecast to core.UDPConn?
		_ = pc.Close()
		log.E("udp: connect: %s proxy(%s) does not impl core.UDPConn(%s) for uid %s", res.CID, px.ID(), target, res.UID)
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
