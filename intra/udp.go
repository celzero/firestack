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
	errUdpInEstErr     = errors.New("udp: ingress establish error")
	errUdpSetupConn    = errors.New("udp: could not create conn")
	errProxyMismatch   = errors.New("udp: proxy mismatch")
	errUidMismatch     = errors.New("udp: uid mismatch")
	errUdpUnconnected  = errors.New("udp: cannot connect")
	errUdpEnd          = errors.New("udp: stopped")
	errIcmpEnd         = errors.New("icmp: stopped")
)

const (
	// RFC 4787 REQ-5 requires a timeout no shorter than 5 minutes; but most
	// routers do not keep udp mappings for that long (usually just for 30s)
	udptimeout = 2 * 60 // seconds
	// TODO: 2h 40m?
	tcptimeout = 0 // no timeout
)

var _ netstack.GUDPConnHandler = (*udpHandler)(nil)

// rwext wraps MinConn and extends deadline to minimum(min, settings.DialerOpts)
// on every read and write.
type rwext struct {
	net.Conn        // underlying conn
	minidle  uint32 // min idle timeout in secs
}

func (rw rwext) IsZeroDeadline() bool {
	r, w := rw.deadlines()
	return r == 0 && w == 0
}

func (rw rwext) SetAsTCPSockOpt() (core.TCPConn, bool) {
	r, _ := rw.deadlines()
	c, ok := rw.Conn.(core.TCPConn) // no-op for tcp conns
	if ok && r > 0 {
		// always returns false for udp conns
		ok = core.SetTimeoutSockOpt(c, int(r)*1000)
	}
	return c, ok
}

func (rw rwext) Unwrap() net.Conn {
	return rw.Conn
}

func (rw rwext) Read(b []byte) (n int, err error) {
	rw.extend()
	return rw.Conn.Read(b)
}

func (rw rwext) Write(b []byte) (n int, err error) {
	rw.extend()
	return rw.Conn.Write(b)
}

func (rw rwext) deadlines() (r, w uint32) {
	dopt := settings.GetDialerOpts()
	// -ve ints go higher than 2^31 w/ uint: go.dev/play/p/Rrqk_V8a7W0
	return max(rw.minidle, uint32(dopt.ReadTimeoutSec)),
		max(rw.minidle, uint32(dopt.WriteTimeoutSec))
}

func (rw rwext) extend() {
	r, w := rw.deadlines()

	tw := time.Second * time.Duration(w)
	tr := time.Second * time.Duration(r)

	extendc(rw.Conn, tr, tw)
}

// NewUDPHandler makes a UDP handler with Intra-style DNS redirection:
// All packets are routed directly to their destination.
// `timeout` controls the effective NAT mapping lifetime.
// `config` is used to bind new external UDP ports.
// `listener` receives a summary about each UDP binding when it expires.
func NewUDPHandler(pctx context.Context, resolver dnsx.Resolver, prox ipn.Proxies, tunMode *settings.TunMode, listener SocketListener) netstack.GUDPConnHandler {
	if listener == nil || core.IsNil(listener) {
		log.W("udp: using noop listener")
		listener = nooplistener
	}
	h := &udpHandler{
		baseHandler: newBaseHandler(pctx, dnsx.NetTypeUDP, resolver, prox, tunMode, listener),
		mux:         newMuxTable(),
	}

	go h.processSummaries()

	log.I("udp: new handler created")
	return h
}

func (h *udpHandler) ReverseProxy(gconn *netstack.GUDPConn, in net.Conn, to, from netip.AddrPort) (ok bool) {
	fm := h.onInflow(to, from)
	cid, uid, _, pids := h.judge(fm)
	smm := udpSummary(cid, uid, from.Addr())
	if isAnyBlockPid(pids) {
		log.I("udp: %s reverse: block %s => %s", cid, from, to)
		clos(gconn, in) // blocked
		h.queueSummary(smm.done(errUdpInFirewalled))
		return true // ok
	} // else: pid should only be ipn.Ingress

	if err := gconn.Establish(); err != nil { // gconn.Establish() failed
		log.W("udp: %s reverse: %s gconn.Est, err %s => %s", cid, to, from, err)
		clos(gconn, in) // teardown
		h.queueSummary(smm.done(errUdpInEstErr))
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
	defer clos(gconn) // if open

	log.W("udp: proxy: %v =>  %v; err %v", src, target, err)
	if !src.IsValid() || !target.IsValid() {
		return
	}
	res, _, _, _ := h.onFlow(src, target)
	cid, uid, _, pids := h.judge(res)
	smm := udpSummary(cid, uid, target.Addr())

	if isAnyBlockPid(pids) {
		err = errUdpFirewalled
	}
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
		h.queueSummary(smm.done(err))
		return false // not ok
	} else if remote == nil || smm == nil { // dnsOverride or ipn.Block
		// do not close gconn here; it is either
		// connected (overridden) or disconnected (blocked) already
		// no summary for dns queries; for blocked connection,
		// summary is queued in Connect()
		return true // ok
	}

	cid := smm.ID
	core.Go("udp.forward."+cid, func() {
		h.forward(gconn, rwext{remote, udptimeout}, smm)
	})
	return true // ok
}

// Connect connects the proxy server; thread-safe.
func (h *udpHandler) Connect(gconn *netstack.GUDPConn, src, target netip.AddrPort, dmx netstack.DemuxerFn) (pc net.Conn, smm *SocketSummary, err error) {
	mux := dmx != nil
	smmTarget := target.Addr()

	// flow is alg/nat-aware, do not change target or any addrs
	res, undidAlg, realips, domains := h.onFlow(src, target)
	actualTargets := makeIPPorts(realips, target, 0)
	cid, uid, fid, pids := h.judge(res, domains, target.String())
	if len(actualTargets) > 0 {
		smmTarget = actualTargets[0].Addr()
	}
	smm = udpSummary(cid, uid, smmTarget)

	if h.status.Load() == HDLEND {
		log.D("udp: connect: %s %v => %v, end", cid, src, target)
		return nil, smm, errUdpEnd // disconnect, no nat
	}

	if !target.IsValid() { // must call h.Bind?
		log.E("udp: connect: %s %s => %s; invalid dst", cid, src, target)
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
			log.I("udp: %s firewalled from %s => %s (dom: %s / real: %s) for %s; stall? %ds",
				cid, src, target, domains, realips, uid, secs)
		})
		return nil, nil, nil // disconnect override, no dst
	}

	// connect gconn right away, since we assume a duplex-stream from here on
	if err = gconn.Establish(); err != nil {
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
	if isAnyBasePid(pids) {
		if h.dnsOverride(gconn, target) {
			// SocketSummary is not sent to listener; x.DNSSummary is
			return nil, nil, nil // connect override, no dst
		} // else: not a dns query or target is not a dns addr
	} // else: proxy src to dst

	var px ipn.Proxy
	var errs error
	var selectedTarget netip.AddrPort

	if mux {
		if muxpid := h.mux.pid(src); len(muxpid) > 0 && containsPid(pids, muxpid) {
			log.D("udp: connect: %s mux: %s => %s using muxed-pid %s; discard pids %s",
				cid, src, target, muxpid, pids)
			pids = []string{muxpid}
		} // else: mxr will dial this conn with a different pid
	}
	// note: fake-dns-ips shouldn't be un-nated / un-alg'd
	for i, dstipp := range actualTargets {
		rttstart := time.Now()

		if px, err = h.prox.ProxyTo(dstipp, uid, pids); err != nil || px == nil {
			log.W("udp: connect: %s failed to get proxy from %s: %v", cid, pids, err)
			errs = err // disconnect if loop terminates
			continue
		}
		selectedTarget = dstipp
		if mux { // mux is not supported by all proxies (few like Exit, Base, WG support it)
			pc, err = h.mux.associate(cid, px.ID(), uid, src, selectedTarget, px.Dialer().Announce, vendor(dmx))
		} else {
			if settings.PortForward.Load() {
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
		rtt := time.Since(rttstart)
		smm.Rtt = int32(rtt.Seconds() * 1000)
		log.W("udp: connect: #%d: %s failed; mux? %t, addr(%s); for uid %s (%dms) w err(%v)",
			i, cid, mux, dstipp, uid, end.Milliseconds(), err)
		if end > retrytimeout {
			break
		}
	}

	// pc.RemoteAddr may be that of the proxy, not the actual dst
	// ex: pc.RemoteAddr is 127.0.0.1 for Orbot
	smm.Target = selectedTarget.Addr().String()
	if px != nil { // nil when all ProxyTo attempts for actualTargets fail
		smm.PID = px.ID()
		smm.RPID = ipn.ViaID(px)
	}

	if errs != nil {
		return nil, smm, errs // disconnect
	} else if px == nil || pc == nil || core.IsNil(pc) {
		log.W("udp: connect: %s no proxy/egress-conn (mux? %t) for addr(%s/%s), uid %s",
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
		clos(pc)
		log.E("udp: connect: %s proxy(%s) does not impl core.UDPConn(%s/%s); mux? %t, uid %s",
			cid, px.ID(), target, selectedTarget, mux, uid)
		return nil, smm, errUdpSetupConn // disconnect
	}

	log.I("udp: connect: %s (proxy? %s@%s) %v => %s/%s; mux? %t, uid %s",
		cid, px.ID(), px.GetAddr(), laddr, target, selectedTarget, mux, uid)

	return pc, smm, nil // connect
}
