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
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/netstack"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
)

type tcpHandler struct {
	*baseHandler
}

type ioinfo struct {
	bytes int64
	err   error
}

const (
	retryTimeout  = 15 * time.Second
	onFlowTimeout = 5 * time.Second
)

var (
	errTcpFirewalled = errors.New("tcp: firewalled")
	errTcpSetupConn  = errors.New("tcp: could not create conn")
)

var _ netstack.GTCPConnHandler = (*tcpHandler)(nil)

// NewTCPHandler returns a TCP forwarder with Intra-style behavior.
// Connections to `fakedns` are redirected to DOH.
// All other traffic is forwarded using `dialer`.
// `listener` is provided with a summary of each socket when it is closed.
func NewTCPHandler(pctx context.Context, resolver dnsx.Resolver, prox ipn.ProxyProvider, listener SocketListener) netstack.GTCPConnHandler {
	if listener == nil || core.IsNil(listener) {
		log.W("tcp: using noop listener")
		listener = nooplistener
	}

	h := &tcpHandler{
		baseHandler: newBaseHandler(pctx, dnsx.NetTypeTCP, resolver, prox, listener),
	}

	go h.processSummaries()

	log.I("tcp: new handler created")
	return h
}

// Error implements netstack.GTCPConnHandler.
// It must be called from a goroutine.
func (h *tcpHandler) Error(gconn *netstack.GTCPConn, src, dst netip.AddrPort, err error) {
	err = log.EE("tcp: error: %s => %s; err %v", src, dst, err)
	if !src.IsValid() || !dst.IsValid() {
		return
	}
	res, undidAlg, realips, domains := h.onFlow(src, dst)

	h.maybeReplaceDest(res, &dst)

	cid, uid, fid, pids := h.judge(res)
	smm := tcpSummary(cid, uid, src.Addr(), dst.Addr())

	if isAnyBlockPid(pids) {
		smm.PID = ipn.Block

		if undidAlg && len(realips) <= 0 && len(domains) > 0 {
			err = core.JoinErr(err, errNoIPsForDomain)
		} else {
			err = core.JoinErr(errTcpFirewalled, err)
		}
		core.Go("tcp.stall."+fid, func() {
			defer clos(gconn)
			defer h.queueSummary(smm.done(err))
			secs := h.stall(fid)
			log.I("tcp: error: %s firewalled from %s => %s (dom: %s / real: %s) for %s; stall? %ds; err %v",
				cid, src, dst, domains, realips, uid, secs, err)
		})
		return
	}

	h.queueSummary(smm.done(err))
}

func (h *tcpHandler) ReverseProxy(gconn *netstack.GTCPConn, in net.Conn, to, from netip.AddrPort) (open bool) {
	fm := h.onInflow(to, from)
	cid, uid, _, pids := h.judge(fm)
	smm := tcpSummary(cid, uid, to.Addr(), from.Addr())

	if settings.Debug {
		log.VV("tcp: %s [%s]: reverse: %s => %s; pids: %v", cid, uid, from, to, pids)
	}

	if isAnyBlockPid(pids) {
		log.I("tcp: %s [%s]: reverse: block %s => %s", cid, uid, from, to)
		clos(gconn, in)
		h.queueSummary(smm.done(errUdpInFirewalled))
		return true
	} // else: pid is ipn.Ingress

	// handshake; since we assume a duplex-stream from here on
	if open, err := gconn.Establish(); !open {
		err = log.EE("tcp: %s [%s]: reverse: gconn.Est, err %v; %s => %s for %s",
			cid, uid, err, to, from, uid)
		h.queueSummary(smm.done(err))
		return false
	}

	core.Go("tcp.reverse:"+cid, func() {
		h.forward(gconn, rwext{in, tcptimeout}, smm)
	})
	return true
}

func (h *tcpHandler) handshakeIfNeededOrClose(gconn *netstack.GTCPConn, smm *SocketSummary) (bool, error) {
	const allow bool = true  // allowed
	const deny bool = !allow // blocked

	if _, err := gconn.Establish(); err != nil {
		err = log.EE("tcp: %s handshake err %v; %s => %s for %s",
			smm.ID, err, smm.Source, smm.Target, smm.UID)
		clos(gconn)
		h.queueSummary(smm.done(err))
		return deny, err // == !open
	}
	return allow, nil
}

// Proxy implements netstack.GTCPConnHandler
// It must be called from a goroutine.
func (h *tcpHandler) Proxy(gconn *netstack.GTCPConn, src, target netip.AddrPort) (open bool) {
	const allow bool = true  // allowed
	const deny bool = !allow // blocked
	var smm *SocketSummary
	var err error

	defer core.Recover(core.Exit11, "tcp.Proxy")

	if !src.IsValid() || !target.IsValid() {
		log.E("tcp: nil addr %s => %s; close err? %v", src, target, err)
		clos(gconn) // gconn may be nil
		return deny
	}

	// flow/dns-override are nat-aware, as in, they can deal with
	// nat-ed ips just fine, and so, use target as-is instead of ipx4
	res, undidAlg, realips, domains := h.onFlow(src, target)

	h.maybeReplaceDest(res, &target)

	// TODO: use res.IP only if set
	filtered, _, fallingback := filterFamilyForDialing(realips)
	actualTargets := makeIPPorts(filtered, target, 0)
	cid, uid, fid, pids := h.judge(res, domains, target.String())

	if len(actualTargets) <= 0 { // unlikely
		actualTargets = []netip.AddrPort{target}
	}
	// actualTargets[0] may be same as target
	smm = tcpSummary(cid, uid, src.Addr(), actualTargets[0].Addr())

	if h.status.Load() == HDLEND {
		err = log.EE("tcp: proxy: %s end %s => %s [%v]", cid, src, target, actualTargets)
		clos(gconn)
		h.queueSummary(smm.done(err))
		return deny
	}

	if isAnyBlockPid(pids) {
		smm.PID = ipn.Block
		if undidAlg && len(realips) <= 0 && len(domains) > 0 {
			err = errNoIPsForDomain
		} else {
			err = errTcpFirewalled
		}
		core.Go("tcp.stall."+fid, func() {
			defer clos(gconn)
			defer h.queueSummary(smm.done(err))
			secs := h.stall(fid)
			log.I("tcp: %s firewalled from %s => %s (dom: %s / real: %s) for %s; stall? %ds",
				cid, src, target, domains, realips, uid, secs)
		})
		return deny
	}

	if isAnyBasePid(pids) { // see udp.go:Connect
		if synack, _ := h.handshakeIfNeededOrClose(gconn, smm); synack && h.dnsOverride(gconn, target, uid) {
			// SocketSummary not sent; x.DNSSummary supercedes it
			// conn closed by resolver
			return allow
		} // else not a dns request
	} // if ipn.Exit then let it connect as-is (aka exit)

	if settings.Debug {
		log.VV("tcp: %s proxying %s => %s [%v] for %s; pids: %s",
			cid, src, target, actualTargets, uid, pids)
	}

	cont := true
	boundSrc := makeAnyAddrPort(src)
	// pick all realips to connect to
	for i, dstipp := range actualTargets {
		targetstr := dstipp.Addr().String()

		var px ipn.Proxy = nil
		px, err = h.prox.ProxyTo(dstipp, uid, pids)

		// last chosen (but not dialed in) proxy (which error)
		smm.Target = targetstr // addr may be invalid
		smm.PID = pidstr(px)   // px may be nil
		smm.RPID = ipn.ViaID(px)

		if err != nil || px == nil {
			err = log.WE("tcp: dial: #%d: %s proxy(%s) to dst(%s) for %s; err %v",
				i, cid, pidstr(px), dstipp, uid, err)
			continue
		}

		if cont, err = h.handle(px, gconn, boundSrc, dstipp, smm); err == nil {
			return allow // smm instead queued by handle() => forward()
		} else {
			end := time.Since(smm.start)
			err = log.WE("tcp: dial: #%d: %s failed; addr(%s) / fallback? %t / cont? %t; for uid %s (%s); w err(%v)",
				i, cid, dstipp, fallingback, cont, uid, core.FmtPeriod(end), err)
			if !cont || end > retryTimeout {
				break // return err
			} // else: continue; try the next realip
		}
	}

	h.queueSummary(smm.done(err))
	clos(gconn) // denied
	return deny
}

// handle connects to the target via the proxy, and pipes data between the src, target; thread-safe.
func (h *tcpHandler) handle(px ipn.Proxy, src *netstack.GTCPConn, boundSrc, target netip.AddrPort, smm *SocketSummary) (next bool, err error) {
	cont := true
	stop := !cont
	targetstr := target.String()

	// make sure to not synack in HappyEyeballs scenarios
	if canroute := px.Router().Contains(x.StrOf(targetstr)); !canroute {
		return cont, log.WE("proxy(%s) has no route to %s", pidstr(px), targetstr)
	}

	var pc protect.Conn
	var dst net.Conn

	start := time.Now()

	if settings.Debug {
		log.VV("tcp: %s dial %s: attempt:  %s [%s] => %s for %s",
			smm.ID, pidstr(px), src.LocalAddr(), boundSrc, targetstr, smm.UID)
	}

	// github.com/google/gvisor/blob/5ba35f516b5c2/test/benchmarks/tcp/tcp_proxy.go#L359
	// ref: stackoverflow.com/questions/63656117
	// ref: stackoverflow.com/questions/40328025
	if settings.PortForward.Load() {
		pc, err = px.Dialer().DialBind("tcp", boundSrc.String(), targetstr)
	} else {
		pc, err = px.Dialer().Dial("tcp", targetstr)
	}
	if err == nil {
		smm.Rtt = time.Since(start).Milliseconds()
		switch uc := pc.(type) {
		case *net.TCPConn: // usual
			dst = uc
		case *gonet.TCPConn: // from wgproxy
			dst = uc
		case core.DuplexConn: // using retrier (local proxies like: exit & base)
			dst = uc
		case core.TCPConn: // from confirming proxy dialers
			dst = uc
		case net.Conn: // from non-confirming proxy dialers
			// TODO: log warn?
			dst = uc
		default:
			err = errTcpSetupConn
		}
	}

	// pc.RemoteAddr may be that of the proxy, not the actual dst
	// ex: pc.RemoteAddr is 127.0.0.1 for Orbot
	smm.Target = target.Addr().String()
	smm.PID = pidstr(px)
	smm.RPID = ipn.ViaID(px)

	if err != nil {
		clos(pc)
		log.W("tcp: err dialing %s proxy(%s) to dst(%v) for %s: %v",
			smm.ID, smm.PID, smm.Target, smm.UID, err)
		return cont, err
	}

	if _, synackerr := h.handshakeIfNeededOrClose(src, smm); synackerr != nil {
		clos(pc)
		return stop, synackerr
	}

	core.Go("tcp.forward."+smm.ID, func() {
		h.listener.PostFlow(smm.postMark())
		h.forward(src, rwext{dst, tcptimeout}, smm) // src always *gonet.TCPConn
	})
	return cont, nil // handled; takes ownership of src
}
