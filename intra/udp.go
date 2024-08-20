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
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/netstat"
	"github.com/celzero/firestack/intra/settings"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/netstack"
	"github.com/celzero/firestack/intra/protect"
)

type udpHandler struct {
	resolver    dnsx.Resolver   // dns resolver to forward queries to
	conntracker core.ConnMapper // connid -> [local,remote]
	mux         *muxTable       // EIM/EIF table
	tunMode     *settings.TunMode
	listener    SocketListener      // listener for socket summaries
	prox        ipn.Proxies         // proxy provider for egress
	fwtracker   *core.ExpMap        // uid+dst(domainOrIP) -> blockSecs
	smmch       chan *SocketSummary // socket summary channel
	done        chan struct{}       // always unbuffered

	once sync.Once

	// fields below are mutable

	status *core.Volatile[int] // status of the handler
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
	errIcmpFirewalled = errors.New("icmp: firewalled")
	errUdpFirewalled  = errors.New("udp: firewalled")
	errUdpSetupConn   = errors.New("udp: could not create conn")
	errUdpEnd         = errors.New("udp: stopped")
)

var (
	// RFC 4787 REQ-5 requires a timeout no shorter than 5 minutes; but most
	// routers do not keep udp mappings for that long (usually just for 30s)
	udptimeout, _ = time.ParseDuration("2m")
)

var _ netstack.GUDPConnHandler = (*udpHandler)(nil)

func (rw *rwext) Read(b []byte) (n int, err error) {
	extend(rw.UDPConn, udptimeout)
	return rw.UDPConn.Read(b)
}

func (rw *rwext) Write(b []byte) (n int, err error) {
	extend(rw.UDPConn, udptimeout)
	return rw.UDPConn.Write(b)
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
		resolver:    resolver,
		tunMode:     tunMode,
		listener:    listener,
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

// onFlow calls listener.Flow to determine egress rules and routes; thread-safe.
func (h *udpHandler) onFlow(localaddr, target netip.AddrPort, realips, domains, probableDomains, blocklists string) *Mark {
	blockmode := h.tunMode.BlockMode.Load()
	// BlockModeNone returns false, BlockModeSink returns true
	if blockmode == settings.BlockModeSink {
		return optionsBlock
	}
	// todo: block-mode none should call into listener.Flow to determine upstream proxy
	if blockmode == settings.BlockModeNone {
		return optionsBase
	}

	src := localaddr.String()
	dst := "" // unconnected udp sockets may not have a valid target
	if target.IsValid() {
		dst = target.String()
	}
	if len(realips) <= 0 || len(domains) <= 0 {
		log.VV("udp: onFlow: no realips(%s) or domains(%s + %s), for src=%s dst=%s", realips, domains, probableDomains, localaddr, dst)
	}

	// Implicit: BlockModeFilter or BlockModeFilterProc
	uid := -1
	if blockmode == settings.BlockModeFilterProc {
		procEntry := netstat.FindProcNetEntry("udp", localaddr, target)
		if procEntry != nil {
			uid = procEntry.UserID
		}
	}

	var proto int32 = 17 // udp
	res, flok := core.Gr("udp.flow", func() *Mark {
		return h.listener.Flow(proto, int32(uid), src, dst, realips, domains, probableDomains, blocklists)
	}, onFlowTimeout)

	if res == nil || !flok { // zeroListener returns nil
		log.W("udp: onFlow: empty res or on flow timeout %t; block!", flok)
		return optionsBlock
	} else if len(res.PID) <= 0 {
		log.W("udp: onFlow: no pid from kt; exit!")
		res.PID = ipn.Exit
	}

	return res
}

// ProxyMux implements netstack.GUDPConnHandler
func (h *udpHandler) ProxyMux(gconn *netstack.GUDPConn, src, dst netip.AddrPort) (ok bool) {
	defer core.Recover(core.Exit11, "udp.ProxyMux")
	return h.proxy(gconn, src, dst, true)
}

// Error implements netstack.GUDPConnHandler.
// Must be called from a goroutine.
func (h *udpHandler) Error(gconn *netstack.GUDPConn, src, dst netip.AddrPort, err error) {
	ok := h.proxy(gconn, src, dst, false)
	log.I("udp: proxy: %v ->  %v; err %v; recovered? %t", src, dst, err, ok)
}

// Proxy implements netstack.GUDPConnHandler; thread-safe.
// Must be called from a goroutine.
func (h *udpHandler) Proxy(gconn *netstack.GUDPConn, src, dst netip.AddrPort) (ok bool) {
	defer core.Recover(core.Exit11, "udp.Proxy")
	return h.proxy(gconn, src, dst, false)
}

// proxy connects src to dst over a proxy; thread-safe.
func (h *udpHandler) proxy(gconn *netstack.GUDPConn, src, dst netip.AddrPort, mux bool) (ok bool) {

	remote, smm, ct, err := h.Connect(gconn, src, dst, mux) // remote may be nil; smm is never nil

	if err != nil {
		clos(gconn, remote)
		queueSummary(h.smmch, h.done, smm.done(err)) // smm may be nil
		log.W("udp: proxy: mux? %t, unexpected %s -> %s; err: %v", mux, src, dst, err)
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

	h.conntracker.Track(ct, gconn, remote)
	core.Go("udp.forward: "+cid, func() {
		defer h.conntracker.Untrack(ct.CID)
		forward(gconn, &rwext{remote}, h.smmch, h.done, smm)
	})
	return true // ok
}

// Connect connects the proxy server; thread-safe.
func (h *udpHandler) Connect(gconn *netstack.GUDPConn, src, target netip.AddrPort, mux bool) (dst core.UDPConn, smm *SocketSummary, ct core.ConnTuple, err error) {
	var px ipn.Proxy = nil
	var pc io.Closer = nil

	// connect gconn right away, since we assume a duplex-stream from here on
	// see: h.Connect -> dnsOverride
	if err = gconn.Establish(); err != nil {
		log.W("udp: %s gconn connect, mux? %t, err %s => %s", src, target, mux, err)
	} // err handled after onFlow, so that the listener knows about this gconn/flow

	realips, domains, probableDomains, blocklists := undoAlg(h.resolver, target.Addr())

	// flow is alg/nat-aware, do not change target or any addrs
	res := h.onFlow(src, target, realips, domains, probableDomains, blocklists)
	cid, pid, uid := splitCidPidUid(res)
	smm = udpSummary(cid, pid, uid, target.Addr())
	ct = core.ConnTuple{CID: cid, UID: uid}

	if h.status.Load() == UDPEND {
		log.D("udp: connect: end")
		return nil, smm, ct, errUdpEnd // disconnect, no nat
	}

	if pid == ipn.Block {
		var secs uint32
		k := uid + target.String() // UID may be unknown and target may be invalid addr
		if len(domains) > 0 {      // probableDomains are not reliable for firewalling
			k = uid + domains
		}
		if secs = stall(h.fwtracker, k); secs > 0 {
			waittime := time.Duration(secs) * time.Second
			time.Sleep(waittime)
		}
		log.I("udp: %s conn firewalled from %s => %s (dom: %s + %s/ real: %s); stall? %ds for uid %s",
			cid, src, target, domains, probableDomains, realips, secs, uid)
		return nil, smm, ct, errUdpFirewalled // disconnect
	}

	if err != nil { // gconn.Establish() failed
		return nil, smm, ct, err // disconnect
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
	if pid != ipn.Exit {
		if dnsOverride(h.resolver, dnsx.NetTypeUDP, gconn, target) {
			// SocketSummary is not sent to listener; x.DNSSummary is
			return nil, smm, ct, nil // connect, no dst
		} // else: not a dns query
	} // else: proxy src to dst

	if px, err = h.prox.ProxyFor(pid); err != nil || px == nil {
		log.W("udp: %s failed to get proxy for %s: %v", cid, pid, err)
		return nil, smm, ct, err // disconnect
	}

	var errs error
	var selectedTarget netip.AddrPort
	// note: fake-dns-ips shouldn't be un-nated / un-alg'd
	for i, dstipp := range makeIPPorts(realips, target, 0) {
		selectedTarget = dstipp
		// h.conntracker.TrackDest(ct, selectedTarget) // will be untracked by forward
		if mux { // pc is net.PacketConn (which confirms to core.UDPConn)
			var mxr *muxer
			// mux not supported by all proxies (few like Exit, Base, WG support it)
			if mxr, err = h.mux.associate(src, px.Dialer().Announce); err == nil {
				pc, err = mxr.vend(net.UDPAddrFromAddrPort(selectedTarget))
			}
		} else { // pc is net.Conn (which confirms to core.UDPConn)
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
		return nil, smm, ct, errs // disconnect
	} else if pc == nil || core.IsNil(pc) {
		log.W("udp: connect: %s no egress conn/mux? %t for addr(%s/%s), uid %s",
			cid, mux, target, selectedTarget, uid)
		return nil, smm, ct, errUdpSetupConn // disconnect
	}

	var ok bool
	if dst, ok = pc.(core.UDPConn); !ok {
		core.Close(pc)
		log.E("udp: connect: %s proxy(%s) does not impl core.UDPConn(%s/%s); mux? %t, uid %s",
			cid, px.ID(), target, selectedTarget, mux, uid)
		return nil, smm, ct, errUdpSetupConn // disconnect
	}

	log.I("udp: %s (proxy? %s@%s) %v -> %s/%s; mux? %t, uid %s",
		cid, px.ID(), px.GetAddr(), dst.LocalAddr(), target, selectedTarget, mux, uid)

	return dst, smm, ct, nil // connect
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

// CloseConns implements netstack.GUDPConnHandler
func (h *udpHandler) CloseConns(cids []string) (closed []string) {
	return closeconns(h.conntracker, cids)
}
