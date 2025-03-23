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
	"fmt"
	"net"
	"net/netip"
	"time"

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
	errTcpEnd        = errors.New("tcp: stopped")
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
	log.W("tcp: error: %s => %s; err %v", src, dst, err)
	if !src.IsValid() || !dst.IsValid() {
		return
	}
	res, _, _, _ := h.onFlow(src, dst)
	cid, uid, _, pids := h.judge(res)
	smm := tcpSummary(cid, uid, dst.Addr())

	if isAnyBlockPid(pids) {
		err = errTcpFirewalled
	}
	h.queueSummary(smm.done(err))
}

func (h *tcpHandler) ReverseProxy(gconn *netstack.GTCPConn, in net.Conn, to, from netip.AddrPort) (open bool) {
	fm := h.onInflow(to, from)
	cid, uid, _, pids := h.judge(fm)
	smm := tcpSummary(cid, uid, from.Addr())

	if isAnyBlockPid(pids) {
		log.I("tcp: reverse: block %s => %s", from, to)
		clos(gconn, in)
		h.queueSummary(smm.done(errUdpInFirewalled))
		return true
	} // else: pid is ipn.Ingress

	// handshake; since we assume a duplex-stream from here on
	if open, err := gconn.Establish(); !open {
		err = fmt.Errorf("tcp: %s reverse: gconn.Est, err %v; %s => %s for %s",
			cid, err, to, from, uid)
		log.E("%v", err)
		h.queueSummary(smm.done(err))
		return false
	}

	core.Go("tcp.reverse:"+cid, func() {
		h.forward(gconn, rwext{in, tcptimeout}, smm)
	})
	return true
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
	smmTarget := target.Addr()
	first, _, fallingback := filterFamilyForDialing(realips)
	actualTargets := makeIPPorts(first, target, 0)
	boundSrc := makeAnyAddrPort(src)
	cid, uid, fid, pids := h.judge(res, domains, target.String())
	if len(actualTargets) > 0 {
		smmTarget = actualTargets[0].Addr()
	} else { // unlikely
		actualTargets = []netip.AddrPort{target}
	}
	smm = tcpSummary(cid, uid, smmTarget)

	if h.status.Load() == HDLEND {
		err = errTcpEnd
		log.D("tcp: proxy: end %s => %s", src, target)
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

	// handshake; since we assume a duplex-stream from here on
	if open, err = gconn.Establish(); !open {
		log.E("tcp: %s connect err %v; %s => %s for %s", cid, err, src, target, uid)
		clos(gconn)
		h.queueSummary(smm.done(err))
		return deny // == !open
	}

	if isAnyBasePid(pids) { // see udp.go:Connect
		if h.dnsOverride(gconn, target, uid) {
			// SocketSummary not sent; x.DNSSummary supercedes it
			return allow
		} // else not a dns request
	} // if ipn.Exit then let it connect as-is (aka exit)

	// pick all realips to connect to
	for i, dstipp := range actualTargets {
		var px ipn.Proxy = nil
		if px, err = h.prox.ProxyTo(dstipp, uid, pids); err != nil || px == nil {
			continue
		}

		if err = h.handle(px, gconn, boundSrc, dstipp, smm); err == nil {
			// smm instead queued by handle() => forward()
			return allow
		} // else try the next realip
		end := time.Since(smm.start)
		elapsed := int32(end.Seconds() * 1000)
		log.W("tcp: dial: #%d: %s failed; addr(%s) / fallback? %t; for uid %s (%d); w err(%v)",
			i, cid, dstipp, fallingback, uid, elapsed, err)
		if end > retryTimeout {
			break
		}
	}

	h.queueSummary(smm.done(err))
	clos(gconn) // denied
	return deny
}

// handle connects to the target via the proxy, and pipes data between the src, target; thread-safe.
func (h *tcpHandler) handle(px ipn.Proxy, src net.Conn, boundSrc, target netip.AddrPort, smm *SocketSummary) (err error) {
	var pc protect.Conn
	var dst net.Conn

	start := time.Now()

	// github.com/google/gvisor/blob/5ba35f516b5c2/test/benchmarks/tcp/tcp_proxy.go#L359
	// ref: stackoverflow.com/questions/63656117
	// ref: stackoverflow.com/questions/40328025
	if settings.PortForward.Load() {
		pc, err = px.Dialer().DialBind("tcp", boundSrc.String(), target.String())
	} else {
		pc, err = px.Dialer().Dial("tcp", target.String())
	}
	if err == nil {
		smm.Rtt = int32(time.Since(start).Seconds() * 1000)
		switch uc := pc.(type) {
		case *net.TCPConn: // usual
			dst = uc
		case *gonet.TCPConn: // from wgproxy
			dst = uc
		case core.TCPConn: // from confirming proxy dialers
			dst = uc
		case net.Conn: // from non-confirming proxy dialers
			dst = uc
		default:
			err = errTcpSetupConn
		}
	}

	// pc.RemoteAddr may be that of the proxy, not the actual dst
	// ex: pc.RemoteAddr is 127.0.0.1 for Orbot
	smm.Target = target.Addr().String()
	smm.PID = px.ID()
	smm.RPID = ipn.ViaID(px)

	if err != nil {
		clos(pc)
		log.W("tcp: err dialing %s proxy(%s) to dst(%v) for %s: %v",
			smm.ID, px.ID(), target, smm.UID, err)
		return err
	}

	core.Go("tcp.forward."+smm.ID, func() {
		h.forward(src, rwext{dst, tcptimeout}, smm) // src always *gonet.TCPConn
	})
	return nil // handled; takes ownership of src
}
