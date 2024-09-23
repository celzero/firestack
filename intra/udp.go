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
	"github.com/celzero/firestack/intra/settings"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/netstack"
	"github.com/celzero/firestack/intra/protect"
)

type udpHandler struct {
	*baseHandler
	conntracker core.ConnMapper     // connid -> [local,remote]
	mux         *muxTable           // EIM/EIF table
	prox        ipn.Proxies         // proxy provider for egress
	fwtracker   *core.ExpMap        // uid+dst(domainOrIP) -> blockSecs
	smmch       chan *SocketSummary // socket summary channel
	done        chan struct{}       // always unbuffered

	once sync.Once

	// fields below are mutable

	status *core.Volatile[int] // status of the handler
}

const (
	UDPOK = iota
	UDPEND
)

var (
	errNoIPsForDomain  = errors.New("dns: no ips")
	errIcmpFirewalled  = errors.New("icmp: firewalled")
	errUdpFirewalled   = errors.New("udp: firewalled")
	errUdpInFirewalled = errors.New("udp: ingress firewalled")
	errUdpSetupConn    = errors.New("udp: could not create conn")
	errProxyMismatch   = errors.New("udp: proxy mismatch")
	errUidMismatch     = errors.New("udp: uid mismatch")
	errUdpUnconnected  = errors.New("udp: cannot connect")
	errUdpEnd          = errors.New("udp: stopped")
	errIcmpEnd         = errors.New("icmp: stopped")
)

var (
	// RFC 4787 REQ-5 requires a timeout no shorter than 5 minutes; but most
	// routers do not keep udp mappings for that long (usually just for 30s)
	udptimeout, _ = time.ParseDuration("2m")
)

var _ netstack.GUDPConnHandler = (*udpHandler)(nil)

// rwext wraps MinConn and extends deadline by
// udptimeout on read and write.
type rwext struct {
	net.Conn
}

func (rw *rwext) Read(b []byte) (n int, err error) {
	extend(rw.Conn, udptimeout)
	return rw.Conn.Read(b)
}

func (rw *rwext) Write(b []byte) (n int, err error) {
	extend(rw.Conn, udptimeout)
	return rw.Conn.Write(b)
}

// NewUDPHandler makes a UDP handler with Intra-style DNS redirection:
// All packets are routed directly to their destination.
// `timeout` controls the effective NAT mapping lifetime.
// `config` is used to bind new external UDP ports.
// `listener` receives a summary about each UDP binding when it expires.
func NewUDPHandler(resolver dnsx.Resolver, prox ipn.Proxies, tunMode *settings.TunMode, ctl protect.Controller, listener SocketListener) netstack.GUDPConnHandler {
	if listener == nil || core.IsNil(listener) {
		log.W("udp: using noop listener")
		listener = nooplistener
	}
	h := &udpHandler{
		baseHandler: &baseHandler{
			resolver: resolver,
			tunMode:  tunMode,
			listener: listener,
		},
		prox:        prox,
		fwtracker:   core.NewExpiringMap(),
		conntracker: core.NewConnMap(),
		mux:         newMuxTable(),
		status:      core.NewVolatile(UDPOK),
		smmch:       make(chan *SocketSummary, smmchSize),
		done:        make(chan struct{}),
	}

	go sendSummary(h.smmch, h.done, listener)

	log.I("udp: new handler created")
	return h
}

func (h *udpHandler) ReverseProxy(gconn *netstack.GUDPConn, in net.Conn, to, from netip.AddrPort) (ok bool) {
	uid := UNKNOWN_UID
	nn := ntoa("udp")
	// TODO: default fm as optionsBase or optionsBlock
	// inflow does not go through nat/alg/dns/proxy
	fm, ok := core.Grx("udp.inflow", func() *Mark {
		return h.listener.Inflow(nn, int32(uid), to.String(), from.String())
	}, onFlowTimeout)
	if !ok || fm == nil {
		log.E("udp: reverse: inflow timeout %v <= %v", to, from)
		return false
	}
	cid := fm.CID
	pid := fm.PID
	smm := udpSummary(cid, pid, fm.UID, from.Addr())
	if pid == ipn.Block {
		log.I("udp: %s reverse: block %s -> %s", cid, from, to)
		clos(gconn, in)
		queueSummary(h.smmch, h.done, smm.done(errUdpInFirewalled))
		return true
	}

	if err := gconn.Establish(); err != nil { // gconn.Establish() failed
		log.W("udp: %s reverse: %s gconn.Est, err %s => %s", cid, to, from, err)
		queueSummary(h.smmch, h.done, smm.done(errUdpInFirewalled))
		return false
	}

	h.conntracker.Track(cid, gconn, in)
	core.Go("udp.reverse:"+cid, func() {
		defer h.conntracker.Untrack(cid)
		forward(gconn, &rwext{in}, h.smmch, h.done, smm)
	})
	return true
}

// ProxyMux implements netstack.GUDPConnHandler
func (h *udpHandler) ProxyMux(gconn *netstack.GUDPConn, src, dst netip.AddrPort, dmx netstack.DemuxerFn) (ok bool) {
	defer core.Recover(core.Exit11, "udp.ProxyMux")
	return h.proxy(gconn, src, dst, dmx)
}

// Error implements netstack.GUDPConnHandler.
// Must be called from a goroutine.
func (h *udpHandler) Error(gconn *netstack.GUDPConn, src, target netip.AddrPort, err error) {
	log.W("udp: proxy: %v ->  %v; err %v", src, target, err)
	if !src.IsValid() || !target.IsValid() {
		return
	}
	res, _, _, _ := h.onFlow("udp", src, target)
	cid, pid, uid := splitCidPidUid(res)
	smm := udpSummary(cid, pid, uid, target.Addr())

	if pid == ipn.Block {
		err = errUdpFirewalled
	}
	queueSummary(h.smmch, h.done, smm.done(err))
}

// Proxy implements netstack.GUDPConnHandler; thread-safe.
// Must be called from a goroutine.
func (h *udpHandler) Proxy(gconn *netstack.GUDPConn, src, dst netip.AddrPort) (ok bool) {
	defer core.Recover(core.Exit11, "udp.Proxy")
	return h.proxy(gconn, src, dst, nil)
}

// proxy connects src to dst over a proxy; thread-safe.
func (h *udpHandler) proxy(gconn *netstack.GUDPConn, src, dst netip.AddrPort, dmx netstack.DemuxerFn) (ok bool) {
	mux := dmx != nil
	remote, smm, err := h.Connect(gconn, src, dst, dmx) // remote may be nil; smm is never nil

	if err != nil {
		core.Close(gconn, remote)
		queueSummary(h.smmch, h.done, smm.done(err)) // smm may be nil
		log.D("udp: proxy: mux? %t, firewalled? %s => %s; err: %v", mux, src, dst, err)
		// dst addrs no longer tracked in h.Connect: h.conntracker.Untrack(ct.CID)
		return // not ok
	} else if remote == nil { // dnsOverride?
		// no summary for dns queries
		// dns-conns not tracked in h.Connect: conntracker.Untrack() not req
		return true // ok
	}

	var cid string
	if smm != nil { // smm is never nil
		cid = smm.ID
	}

	h.conntracker.Track(cid, gconn, remote)
	core.Go("udp.forward: "+cid, func() {
		defer h.conntracker.Untrack(cid)
		forward(gconn, &rwext{remote}, h.smmch, h.done, smm)
	})
	return true // ok
}

// Connect connects the proxy server; thread-safe.
func (h *udpHandler) Connect(gconn *netstack.GUDPConn, src, target netip.AddrPort, dmx netstack.DemuxerFn) (pc net.Conn, smm *SocketSummary, err error) {
	mux := dmx != nil

	if !target.IsValid() { // must call h.Bind
		err = errUdpUnconnected
	} else { // connect gconn right away, since we assume a duplex-stream from here on
		// see: h.Connect -> dnsOverride
		err = gconn.Establish()
	} // err handled after onFlow, so that the listener knows about this gconn/flow

	// flow is alg/nat-aware, do not change target or any addrs
	res, undidAlg, realips, domains := h.onFlow("udp", src, target)
	cid, pid, uid := splitCidPidUid(res)
	smm = udpSummary(cid, pid, uid, target.Addr())

	if h.status.Load() == UDPEND {
		log.D("udp: connect: %s %v => %v, end", cid, src, target)
		return nil, smm, errUdpEnd // disconnect, no nat
	}

	if pid == ipn.Block {
		if undidAlg && len(realips) <= 0 && len(domains) > 0 {
			err = errNoIPsForDomain
		} else {
			err = errUdpFirewalled
		}
		var k string
		if len(domains) > 0 {
			k = uid + domains
		} else {
			k = uid + target.String() // UID may be unknown
		}
		var secs uint32
		if secs = stall(h.fwtracker, k); secs > 0 {
			waittime := time.Duration(secs) * time.Second
			time.Sleep(waittime)
		}
		log.I("udp: connect: %s conn firewalled from %s => %s (dom: %s / real: %s); stall? %ds for uid %s",
			cid, src, target, domains, realips, secs, uid)
		return nil, smm, err // disconnect
	}

	if err != nil { // gconn.Establish() failed
		log.W("udp: connect: %s gconn.Est, mux? %t, err %s => %s", src, target, mux, err)
		return nil, smm, err // disconnect
	}

	// requests meant for ipn.Exit are always routed untouched to target
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
	if pid == ipn.Base {
		if dnsOverride(h.resolver, dnsx.NetTypeUDP, gconn, target) {
			// SocketSummary is not sent to listener; x.DNSSummary is
			return nil, smm, nil // connect, no dst
		} // else: not a dns query or target is not a dns addr
	} // else: proxy src to dst

	var px ipn.Proxy
	if px, err = h.prox.ProxyFor(pid); err != nil || px == nil {
		log.W("udp: connect: %s failed to get proxy for %s: %v", cid, pid, err)
		return nil, smm, err // disconnect
	}

	var errs error
	var selectedTarget netip.AddrPort
	// note: fake-dns-ips shouldn't be un-nated / un-alg'd
	for i, dstipp := range makeIPPorts(realips, target, 0) {
		selectedTarget = dstipp
		if mux { // mux is not supported by all proxies (few like Exit, Base, WG support it)
			pc, err = h.mux.associate(cid, pid, uid, src, selectedTarget, px.Dialer().Announce, vendor(dmx))
		} else {
			pc, err = px.Dialer().Dial("udp", selectedTarget.String())
		}
		if err == nil {
			errs = nil // reset errs
			break
		} // else try the next realip

		errs = err // store just the last err; complicates logging
		end := time.Since(smm.start)
		log.W("udp: connect: #%d: %s failed; mux? %t, addr(%s); for uid %s (%dms) w err(%v)",
			i, cid, mux, dstipp, uid, end.Milliseconds(), err)
		if end > retrytimeout {
			break
		}
	}

	// pc.RemoteAddr may be that of the proxy, not the actual dst
	// ex: pc.RemoteAddr is 127.0.0.1 for Orbot
	smm.Target = selectedTarget.Addr().String()

	if errs != nil {
		return nil, smm, errs // disconnect
	} else if pc == nil || core.IsNil(pc) {
		log.W("udp: connect: %s no egress conn/mux? %t for addr(%s/%s), uid %s",
			cid, mux, target, selectedTarget, uid)
		return nil, smm, errUdpSetupConn // disconnect
	}

	var laddr net.Addr
	switch x := pc.(type) {
	case core.UDPConn: // connected
		laddr = x.LocalAddr()
	case net.Conn: // muxed
		laddr = x.LocalAddr()
	default:
		core.Close(pc)
		log.E("udp: connect: %s proxy(%s) does not impl core.UDPConn(%s/%s); mux? %t, uid %s",
			cid, px.ID(), target, selectedTarget, mux, uid)
		return nil, smm, errUdpSetupConn // disconnect
	}

	log.I("udp: connect: %s (proxy? %s@%s) %v -> %s/%s; mux? %t, uid %s",
		cid, px.ID(), px.GetAddr(), laddr, target, selectedTarget, mux, uid)

	return pc, smm, nil // connect
}

// End implements netstack.GUDPConnHandler
func (h *udpHandler) End() error {
	h.once.Do(func() {
		h.CloseConns(nil)
		h.status.Store(UDPEND)
		close(h.done)
		close(h.smmch)
		log.I("udp: handler end %x %x", h.done, h.smmch)
	})
	return nil
}

// OpenConns implements netstack.GUDPConnHandler
func (h *udpHandler) OpenConns() int32 {
	// account for two conntracker entries (local, remote)
	// per outbound connection
	return int32(h.conntracker.Len() / 2)
}

// CloseConns implements netstack.GUDPConnHandler
func (h *udpHandler) CloseConns(cids []string) (closed []string) {
	return closeconns(h.conntracker, cids)
}
