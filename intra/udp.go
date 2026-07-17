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
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/netstack"
)

type udpHandler struct {
	*baseHandler
	mux *muxTable // EIM/EIF table
}

var (
	errNoIPsForDomain  = errors.New("dns: no ips")
	errIcmpFirewalled  = errors.New("icmp: firewalled")
	errUdpFirewalled   = errors.New("udp: firewalled")
	errUdpInFirewalled = errors.New("udp: ingress firewalled")
	errTcpInFirewalled = errors.New("tcp: ingress firewalled")
	errUdpSetupConn    = errors.New("udp: could not create conn")
	errUdpIncomingDrop = errors.New("udp: at capacity; packet in dropped")
	errUdpUnconnected  = errors.New("udp: cannot connect")
	errUdpNoTarget     = errors.New("udp: no target addr")
	errTcpNoTarget     = errors.New("tcp: no target addr")
)

const (
	// RFC 4787 REQ-5 requires a timeout no shorter than 5 minutes; but most
	// routers do not keep udp mappings for that long (usually just for 30s)
	udptimeout = 2 * 60 // seconds
	// TODO: 2h 40m?
	tcptimeout = 0 // no timeout
)

var _ netstack.GUDPConnHandler = (*udpHandler)(nil)

// NewUDPHandler makes a UDP handler with Intra-style DNS redirection:
// All packets are routed directly to their destination.
// `timeout` controls the effective NAT mapping lifetime.
// `config` is used to bind new external UDP ports.
// `listener` receives a summary about each UDP binding when it expires.
func NewUDPHandler(pctx context.Context, resolver dnsx.Resolver, prox ipn.ProxyProvider, listener FlowListener) netstack.GUDPConnHandler {
	if listener == nil || core.IsNil(listener) {
		log.W("udp: using noop listener")
		listener = nooplistener
	}
	h := &udpHandler{
		baseHandler: newBaseHandler(pctx, dnsx.NetTypeUDP, resolver, prox, listener),
		mux:         newMuxTable(),
	}

	core.Gx("udp.ps", h.processSummaries)

	log.I("udp: new handler created")
	return h
}

func (h *udpHandler) ReverseProxy(gconn *netstack.GUDPConn, in net.Conn, to, from netip.AddrPort) (ok bool) {
	fm := h.onInflow(to, from)
	cid, uid, _, pids := h.judge(fm)
	smm := udpSummary(cid, uid, to.Addr(), from.Addr())

	if log.Verbose {
		log.V("udp: %s [%s]: reverse: %s => %s; pids: %v", cid, uid, from, to, pids)
	}

	if isAnyBlockPid(pids) {
		log.I("udp: %s [%s]: reverse: block %s => %s", cid, uid, from, to)
		clos(gconn, in) // blocked
		h.queueSummary(smm.done(errUdpInFirewalled))
		return true // ok
	} // else: pid should only be ipn.Ingress

	if err := gconn.Establish(); err != nil { // gconn.Establish() failed
		err = log.EE("udp: %s [%s]: reverse: %s gconn.Est, err %s => %s: %v", cid, uid, to, from, err)
		clos(gconn, in) // teardown
		h.queueSummary(smm.done(err))
		return false // not ok
	}

	core.Go("udp.reverse:"+cid, func() {
		h.forward(gconn, rwext{in, udptimeout}, smm)
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
	log.W("udp: error: %v => %v; err %v", src, target, err)
	if !src.IsValid() || !target.IsValid() {
		clos(gconn)
		return
	}
	res, undidAlg, realips, domains := h.onFlow(src, target)
	h.maybeReplaceDest(res, &target)
	cid, uid, fid, pids := h.judge(res)
	smm := udpSummary(cid, uid, src.Addr(), target.Addr())

	if isAnyBlockPid(pids) {
		smm.PID = ipn.Block
		if undidAlg && len(realips) <= 0 && len(domains) > 0 {
			err = core.JoinErr(errNoIPsForDomain, err)
		} else {
			err = core.JoinErr(errUdpFirewalled, err)
		}
		core.Go("udp.stall."+fid, func() {
			defer h.queueSummary(smm.done(err))
			secs := h.stall(fid)
			log.I("udp: error: %s [%s] firewalled from %s => %s (dom: %s / real: %s) for %s; stall? %ds",
				cid, uid, src, target, domains, realips, uid, secs)
		})
		clos(gconn) // close immediately while stall delays queuing summary
		return
	}

	clos(gconn)
	h.queueSummary(smm.done(err))
}

// Proxy implements netstack.GUDPConnHandler; thread-safe.
// Must be called from a goroutine.
func (h *udpHandler) Proxy(gconn *netstack.GUDPConn, src, dst netip.AddrPort) (ok bool) {
	defer core.Recover(core.Exit11, "udp.Proxy")
	return h.proxy(gconn, src, dst, nil)
}

// proxy connects src to dst over a proxy; thread-safe.
func (h *udpHandler) proxy(gconn *netstack.GUDPConn, src, dst netip.AddrPort, dmx netstack.DemuxerFn) (ok bool) {
	// remote, smm, err may all be nil
	remote, smm, err := h.Connect(gconn, src, dst, dmx)

	if err != nil {
		clos(gconn, remote) // teardown
		// smm may be nil; in which case this is a no-op
		h.queueSummary(smm.done(err)) // no-op if smm is nil
		return false                  // not ok
	} else if remote == nil || smm == nil { // dnsOverride or ipn.Block
		h.queueSummary(smm.done(err)) // no-op if smm is nil
		// do not close gconn here; it is either
		// connected (overridden) or disconnected (blocked) already
		// no summary for dns queries; for blocked connection,
		// summary is queued in Connect()
		return true // ok
	}

	h.loopAssoc(smm)

	cid := smm.ID
	core.Go("udp.forward."+cid, func() {
		defer h.loopUnassoc(smm)
		h.flowing(smm)
		h.forward(gconn, rwext{remote, udptimeout}, smm)
	})
	return true // ok
}

// Connect connects the proxy server; thread-safe.
func (h *udpHandler) Connect(gconn *netstack.GUDPConn, src, target netip.AddrPort, dmx netstack.DemuxerFn) (pc net.Conn, smm *FlowSummary, err error) {
	mux := dmx != nil // also disabled for loopback mode, for now

	// flow is alg/nat-aware, do not change target or any addrs
	res, undidAlg, realips, domains := h.onFlow(src, target)

	h.maybeReplaceDest(res, &target)

	// when target is local nat64 ip6 address, it cannot be really dialed in to
	// as it only exists within the tunnel to facilitate 6to4 translation; that is
	// the client uid connects over ip6 to the tunnel, but tunnel de-nats the target
	// and instead connects over ip4 outside the tunnel, which will go through if
	// ip4 is available on the underlying network (whereas within the tunnel the uid
	// would "think" it is using an ip6 enabled network). That is, when proxying client
	// sources from [fd66:f83a:c650::1]:4956 to target [64:ff9b:1:fffe::22a0:6f91]:80,
	// it is correct to only dial [34.160.111.145:80] (that is, 22a0:6f91 as ip4) and
	// not dial both the nat64 target ([64:ff9b:1:fffe::22a0:6f91]:80) and the de-natted
	// target ([34.160.111.145:80]); indeed, the former wouldn't dial anywhere as it
	// doesn't exist outside of firestack's tunnel).
	targetIsLocalNat64 := h.resolver.IsNat64(dnsx.Local464Resolver, target.Addr())

	filtered, _, fallingback := filterFamilyForDialingWithFailSafe(realips)
	actualTargets := makeIPPorts(filtered, target, !undidAlg && !targetIsLocalNat64, 0)
	cid, uid, fid, pids := h.judge(res, domains, target.String())

	if len(actualTargets) <= 0 { // unlikely
		actualTargets = []netip.AddrPort{target}
	}
	smm = udpSummary(cid, uid, src.Addr(), actualTargets[0].Addr())

	if h.status.Load() == HDLEND {
		err = log.EE("udp: connect: %s [%s] %v => %v, end", cid, uid, src, target)
		return nil, smm, err // disconnect, no nat
	}

	if !target.IsValid() { // must call h.Bind?
		log.E("udp: connect: %s [%s] %s => %s; invalid dst", cid, uid, src, target)
		return nil, smm, errUdpUnconnected
	}

	if isAnyBlockPid(pids) {
		smm.PID = ipn.Block
		if undidAlg && len(realips) <= 0 && len(domains) > 0 {
			err = errNoIPsForDomain
		} else {
			err = errUdpFirewalled
		}
		core.Go("udp.stall."+fid, func() {
			defer clos(gconn)
			defer h.queueSummary(smm.done(err))
			secs := h.stall(fid)
			log.I("udp: %s [%s] firewalled from %s => %s (dom: %s / real: %s) for %s; stall? %ds",
				cid, uid, src, target, domains, realips, uid, secs)
		})
		return nil, smm, nil // disconnect override, no dst
	}

	// connect gconn right away, since we assume a duplex-stream from here on
	if err = gconn.Establish(); err != nil {
		log.W("udp: connect: %s [%s] gconn.Est, mux? %t, %s => %s err: %v",
			cid, uid, mux, src, target, err)
		return nil, smm, err // disconnect
	}

	// requests meant for ipn.Exit are always routed untouched to target
	// and never to whatever is set as DNS upstream.
	// Ex: If kotlin-land initiates a DNS query (with InetAddress),
	// it is routed to the tunnel's fake DNS addr, which is trapped by
	// by h.dnsOverride that forwards it to one of the dnsx Transports.
	// These dnsx Transports route the query back into the tunnel when
	// Rethink-within-Rethink (settings.LoopingBack) routing is enabled.
	// If this dnsx Transport is inturn forwarding queries to ANY DNS upstream
	// on port 53 (dns53) (see h.resolver.isDns), then the request is trapped
	// again & routed back to the dnsx Transport. To avoid this loop, when
	// Rethink-within-Rethink routing is enabled (settings.LoopingBack),
	// kotlin-land is expected to mark ipn.Base for queries to be trapped
	// and sent to user-preferred dnsx Transport, and ipn.Exit for queries
	// to be dialed as an outgoing protected connection. In practice, when
	// Rethink-within-Rethink routing is enabled and a DNS connection
	// as seen (with Flow) is owned by Rethink, then expect the conn
	// to be marked ipn.Base for queries sent to tunnel's fake DNS addr
	// and ipn.Exit for anywhere else.
	if isAnyBasePid(pids) && h.isDNS(target) {
		if h.dnsOverride(gconn, uid, smm) {
			// socket/session closed by the overriding dns resolver
			return nil, nil, nil // connect override, no dst
		} // else: not a dns query or target is not a dns addr
	} // else: proxy src to dst

	var pxid string
	var px ipn.Proxy
	var errs error
	var selectedTarget netip.AddrPort

	portfwd := settings.PortForward.Load()
	canportfwd := portfwd
	if mux {
		if muxpid := h.mux.pid(src); len(muxpid) > 0 && containsPid(pids, muxpid) {
			if log.Debug {
				log.D("udp: connect: %s [%s] mux: %s => %s using muxed-pid %s; all pids %s",
					cid, uid, src, target, muxpid, pids)
			}
			pids = []string{muxpid}
		} // else: mxr will dial this conn with a different pid
	}

	if log.Verbose {
		log.V("udp: connect: %s [%s] proxying %s => %s [%v]; pids: %s, mux? %t / fwd? %t / localnat64? %t",
			cid, uid, src, target, actualTargets, pids, mux, canportfwd, targetIsLocalNat64)
	}

	// note: fake-dns-ips shouldn't be un-nated / un-alg'd
	for i, dstipp := range actualTargets {
		rttstart := time.Now()

		px, err = h.prox.ProxyTo(cid, dstipp, "udp", uid, pids)

		// TODO: wait to break circular route after going through all actualTargets?
		if errors.Is(err, ipn.ErrCircularRoute) {
			log.I("udp: dial: loop: break1 #%d: %s circular route; dst(%s) for %s; exiting...", i, cid, dstipp, uid)
			// do not invoke ProxyTo (as it also pins dst to ipn.Exit)
			// we only want to break "circular loop" just this one time.
			px, err = h.prox.ProxyFor(ipn.Exit)
		}

		selectedTarget = dstipp

		if err != nil || px == nil {
			log.W("udp: connect: #%d: %s [%s] failed to get proxy from %s: %v", i, cid, uid, pxid, err)
			errs = err // disconnect if loop terminates
			continue
		}

		smm.PID = pidstr(px) // last chosen proxy may yet emayrror out
		smm.RPID = ipn.ViaID(px)
		smm.Target = selectedTarget.Addr().String() // may be invalid

		if h.loopDetected(smm) {
			log.I("udp: dial: loop: break2 #%d %s: %s => %v via %s for %s; exiting...", i, cid, src, selectedTarget, smm.PID, uid)
			px, err = h.prox.ProxyTo(cid+"/loop", dstipp, "udp", uid, onlyExitPid)
			smm.PID = ipn.Exit // last chosen proxy may yet emayrror out
			smm.RPID = ""
		}

		if px == nil || err != nil { // unlikely
			log.E("udp: connect: #%d: %s [%s] failed to get proxy from %s: %v", i, cid, uid, smm.PID, err)
			errs = err
			continue
		}

		pxid = smm.PID
		canportfwd = portfwd && ipn.Remote(pxid)

		if mux { // mux is not supported by all proxies (few like Exit, Base, WG support it)
			pc, err = h.mux.associate(cid, pxid, uid, src, selectedTarget, px.Dialer().Announce, vendor(dmx), canportfwd)
		} else {
			if log.Verbose {
				log.VV("udp: connect: #%d: attempt: %s [%s] proxy(%s) to dst(%s); mux? %t / fwd? %t",
					i, cid, uid, pxid, selectedTarget, mux, canportfwd)
			}

			if canportfwd {
				boundSrc := makeAnyAddrPort(src)
				pc, err = px.Dialer().DialBind("udp", boundSrc.String(), selectedTarget.String())
			} else {
				pc, err = px.Dialer().Dial("udp", selectedTarget.String())
			}
		}
		if err == nil {
			errs = nil // reset errs
			break
		} // else try the next realip

		errs = err // store just the last err; complicates logging
		end := time.Since(smm.start)
		smm.Rtt = time.Since(rttstart).Milliseconds()
		log.W("udp: connect: #%d: %s [%s] failed; mux? %t / fwd? %t, addr(%s) / fallback? %t; (rtt:%dms, dur:%s) w err(%v)",
			i, cid, uid, mux, canportfwd, dstipp, fallingback, smm.Rtt, core.FmtPeriod(end), err)
		if end > retryTimeout {
			break
		}
	}

	if !selectedTarget.IsValid() {
		log.E("udp: connect: %s [%s] no target addr for %s from %v",
			cid, uid, target, actualTargets)
		return nil, smm, errUdpNoTarget
	}

	// pc.RemoteAddr may be that of the proxy, not the actual dst
	// ex: pc.RemoteAddr is 127.0.0.1 for Orbot
	smm.Target = selectedTarget.Addr().String()

	if errs != nil {
		return nil, smm, errs // disconnect
	} else if px == nil || pc == nil || core.IsNil(pc) {
		log.W("udp: connect: %s [%s] no proxy/egress-conn (mux? %t / fwd? %t) for addr(%s/%s)",
			cid, uid, mux, canportfwd, target, selectedTarget)
		return nil, smm, errUdpSetupConn // disconnect
	}

	var laddr net.Addr
	switch x := pc.(type) {
	case *net.UDPConn: // direct
		laddr = x.LocalAddr()
	case core.UDPConn: // connected
		laddr = x.LocalAddr()
	case net.Conn: // muxed
		laddr = x.LocalAddr()
	default:
		clos(pc)
		log.E("udp: connect: %s [%s] proxy(%s) does not impl core.UDPConn(%s/%s); mux? %t",
			cid, uid, pxid, target, selectedTarget, mux, canportfwd, uid)
		return nil, smm, errUdpSetupConn // disconnect
	}

	log.I("udp: connect: %s [%s] (proxy? %s@%s) %v => %s/%s; fallback? %t / mux? %t / fwd? %t",
		cid, uid, pxid, px.GetAddr(), laddr, target, selectedTarget, fallingback, mux, canportfwd)

	return pc, smm, nil // connect
}
