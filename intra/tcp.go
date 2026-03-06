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
	"sync"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/netstack"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

type tcpHandler struct {
	*baseHandler
	nat *tcpNat
}

type tcpNat struct {
	sync.Mutex
	m map[string]map[netip.AddrPort]netip.AddrPort // proxyID => src => ext
}

func newTCPNat() *tcpNat {
	return &tcpNat{m: make(map[string]map[netip.AddrPort]netip.AddrPort)}
}

func (t *tcpNat) assoc(pid string, src, ext netip.AddrPort) {
	if t == nil || len(pid) == 0 || !sameFamily(src.Addr(), ext.Addr()) {
		return
	}
	t.Lock()
	defer t.Unlock()

	m := t.m[pid]
	if m == nil {
		m = make(map[netip.AddrPort]netip.AddrPort)
		t.m[pid] = m
	}
	m[src] = ext
}

func (t *tcpNat) lookup(pid string, src netip.AddrPort) (zz netip.AddrPort, ok bool) {
	if t == nil || len(pid) == 0 || !src.IsValid() {
		return
	}
	t.Lock()
	defer t.Unlock()

	if m := t.m[pid]; m != nil {
		if ext, ok := m[src]; ok {
			return ext, true
		}
	}
	return
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
		nat:         newTCPNat(),
	}

	core.Gx("tcp.ps", h.processSummaries)

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
		// clos(gconn)
		// h.queueSummary(smm.done(err))
		return deny, err // == !open
	}
	return allow, nil
}

func (h *tcpHandler) natAssoc(pid string, src netip.AddrPort, addr net.Addr) {
	if ext := netAddrPort(addr); ext.IsValid() {
		h.nat.assoc(pid, src, ext)
	}
}

func (h *tcpHandler) natLookup(pid string, src, target netip.AddrPort) (zz netip.AddrPort) {
	if ext, ok := h.nat.lookup(pid, src); ok && sameFamily(ext.Addr(), target.Addr()) {
		return ext
	}
	return
}

func netAddrPort(addr net.Addr) (zz netip.AddrPort) {
	if addr == nil {
		return
	}
	if v, ok := addr.(*net.TCPAddr); ok {
		return v.AddrPort()
	} else if ap, err := netip.ParseAddrPort(addr.String()); err == nil {
		return ap
	}
	return
}

func sameFamily(a, b netip.Addr) bool {
	if !a.IsValid() || !b.IsValid() {
		return false
	}
	return a.Is4() == b.Is4()
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
	filtered, excluded, fallingback := filterFamilyForDialingWithFailSafe(realips)
	actualTargets := makeIPPorts(filtered, target, !undidAlg, 0)
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

	is6 := target.Addr().Is6() || src.Addr().Is6()
	happyeyeballs := settings.HappyEyeballs.Load()
	delayForHappyEyeballs := happyeyeballs && is6

	if isAnyBasePid(pids) && h.isDNS(target) { // see udp.go:Connect
		synack, synackerr := h.handshakeIfNeededOrClose(gconn, smm)
		if !synack {
			// if IPv6, stall a bit more so apps doing HappyEyeballs will try IPv4
			if delayForHappyEyeballs {
				time.Sleep(400 * time.Millisecond)
			}
			clos(gconn)
			h.queueSummary(smm.done(synackerr))
			return deny
		}
		if h.dnsOverride(gconn, uid) {
			// SocketSummary not sent; x.DNSSummary supercedes it
			// conn closed by resolver
			return allow
		} // else not a dns request
	} // if ipn.Exit then let it connect as-is (aka exit)

	if settings.Debug {
		log.VV("tcp: %s proxying %s => %s [%v] (excluded: %v) for %s; pids: %s",
			cid, src, target, actualTargets, excluded, uid, pids)
	}

	cont := true
	// pick all realips to connect to
	for i, dstipp := range actualTargets {
		// dstipp may be v4 or v6 regardless of target addr
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

		if cont, err = h.handle(px, gconn, src, dstipp, delayForHappyEyeballs, smm); err == nil {
			return allow // smm instead queued by handle() => forward()
		} else {
			end := time.Since(smm.start)
			err = log.WE("tcp: dial: #%d: %s failed; addr(%s) / fallback? %t / cont? %t / he? %t; for uid %s (%s); w err(%v)",
				i, cid, dstipp, fallingback, cont, happyeyeballs, uid, core.FmtPeriod(end), err)
			if !cont || end > retryTimeout {
				break // return err
			} // else: continue; try the next realip
		}
	}

	// if IPv6, stall a bit more so apps doing HappyEyeballs will try IPv4
	if delayForHappyEyeballs {
		time.Sleep(400 * time.Millisecond)
	}
	h.queueSummary(smm.done(err))
	clos(gconn) // denied
	return deny
}

// handle connects to the target via the proxy, and pipes data between the src, target; thread-safe.
func (h *tcpHandler) handle(px ipn.Proxy, gconn *netstack.GTCPConn, src, target netip.AddrPort, errOnNoRoute bool, smm *SocketSummary) (cont bool, err error) {
	cont = true
	stop := !cont
	targetstr := target.String()

	if errOnNoRoute {
		if canroute := px.Router().Contains(targetstr); !canroute {
			// make sure to not delay in HappyEyeballs scenario?
			return cont, log.WE("proxy(%s) has no route to %s (<= %s)", pidstr(px), targetstr, src)
		}
	}

	var bindAddr netip.AddrPort
	pid := pidstr(px)
	eim := settings.EndpointIndependentMapping.Load()
	portfwd := settings.PortForward.Load()
	canportfwd := portfwd && ipn.Remote(pid)

	if eim { // bindAddr may be invalid
		bindAddr = h.natLookup(pid, src, target)
	}
	if !bindAddr.IsValid() && canportfwd { // port forwarding overriden by eim
		bindAddr = makeAnyAddrPort(src)
	}

	var pc protect.Conn
	var dst net.Conn

	start := time.Now()

	if settings.Debug {
		log.VV("tcp: %s dial %s: attempt(eim? %t / fwd? %t / canfwd? %t):  %s [%s [%s]] => %s for %s",
			smm.ID, pid, eim, portfwd, canportfwd, src, gconn.LocalAddr(), bindAddr, targetstr, smm.UID)
	}

	dialbindOK := false
	// github.com/google/gvisor/blob/5ba35f516b5c2/test/benchmarks/tcp/tcp_proxy.go#L359
	// ref: stackoverflow.com/questions/63656117
	// ref: stackoverflow.com/questions/40328025
	if bindAddr.IsValid() {
		pc, err = px.Dialer().DialBind("tcp", bindAddr.String(), targetstr)
		dialbindOK = err == nil
		logwif(!dialbindOK)("tcp: %s dialbind ok? %t (%s [%s] => %s via %s); err? %v",
			smm.ID, dialbindOK, src, bindAddr, targetstr, pid, err)
	}
	if !dialbindOK {
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
		log.W("tcp: err dialing %s proxy(%s) %v [%v] => %v (bind? %t) for %s: %v",
			smm.ID, smm.PID, src, bindAddr, smm.Target, dialbindOK, smm.UID, err)
		return cont, err
	}

	if _, synackerr := h.handshakeIfNeededOrClose(gconn, smm); synackerr != nil {
		clos(pc)
		return stop, synackerr
	}

	core.Go("tcp.forward."+smm.ID, func() {
		h.listener.PostFlow(smm.postMark())
		h.forward(gconn, rwext{dst, tcptimeout}, smm) // src always *gonet.TCPConn
		// TODO assoc if forward was successful
		if eim {
			h.natAssoc(smm.PID, src, dst.LocalAddr())
		}
	})
	return cont, nil // handled; takes ownership of src
}
