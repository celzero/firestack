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
	prox ipn.Proxies // proxy provider for egress
}

type ioinfo struct {
	bytes int64
	err   error
}

const (
	retrytimeout  = 15 * time.Second
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
func NewTCPHandler(pctx context.Context, resolver dnsx.Resolver, prox ipn.Proxies, tunMode *settings.TunMode, listener SocketListener) netstack.GTCPConnHandler {
	if listener == nil || core.IsNil(listener) {
		log.W("tcp: using noop listener")
		listener = nooplistener
	}

	h := &tcpHandler{
		baseHandler: newBaseHandler(pctx, dnsx.NetTypeTCP, resolver, tunMode, listener),
		prox:        prox,
	}

	go h.processSummaries()

	log.I("tcp: new handler created")
	return h
}

// Error implements netstack.GTCPConnHandler.
// It must be called from a goroutine.
func (h *tcpHandler) Error(gconn *netstack.GTCPConn, src, dst netip.AddrPort, err error) {
	log.W("tcp: error: %v -> %v; err %v", src, dst, err)
	if !src.IsValid() || !dst.IsValid() {
		return
	}
	res, _, _, _ := h.onFlow(src, dst)
	cid, pid, uid := splitCidPidUid(res)
	smm := tcpSummary(cid, pid, uid, dst.Addr())

	if pid == ipn.Block {
		err = errTcpFirewalled
	}
	h.queueSummary(smm.done(err))
}

func (h *tcpHandler) ReverseProxy(gconn *netstack.GTCPConn, in net.Conn, to, from netip.AddrPort) (open bool) {
	uid := UNKNOWN_UID
	nn := ntoa("tcp")
	// TODO: default fm as optionsBase or optionsBlock
	// inflow does not go through nat/alg/dns/proxy
	fm, ok := core.Grx("tcp.inflow", func() *Mark {
		return h.listener.Inflow(nn, int32(uid), to.String(), from.String())
	}, onFlowTimeout)
	if !ok || fm == nil {
		log.E("tcp: reverse: inflow timeout %v <= %v", to, from)
		return false
	}
	cid := fm.CID
	pid := fm.PID
	smm := tcpSummary(cid, pid, fm.UID, from.Addr())
	if pid == ipn.Block {
		log.I("tcp: reverse: block %s -> %s", from, to)
		clos(gconn, in)
		h.queueSummary(smm.done(errUdpInFirewalled))
		return true
	}

	// handshake; since we assume a duplex-stream from here on
	if open, err := gconn.Establish(); !open {
		err = fmt.Errorf("tcp: %s reverse: gconn.Est, err %v; %s => %s for %d",
			cid, err, to, from, uid)
		log.E("%v", err)
		h.queueSummary(smm.done(err))
		return false
	}

	core.Go("tcp.reverse:"+cid, func() {
		h.forward(gconn, &rwext{in}, smm)
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

	defer func() {
		if !open {
			clos(gconn) // gconn may be nil
		}
	}()

	if !src.IsValid() || !target.IsValid() {
		log.E("tcp: nil addr %v -> %v; close err? %v", src, target, err)
		return deny
	}

	defer func() {
		if !open { // when open, smm instead queued by handle() -> forward()
			h.queueSummary(smm.done(err)) // smm may be nil
		}
	}()

	// flow/dns-override are nat-aware, as in, they can deal with
	// nat-ed ips just fine, and so, use target as-is instead of ipx4
	res, undidAlg, realips, domains := h.onFlow(src, target)
	cid, pid, uid := splitCidPidUid(res)
	smm = tcpSummary(cid, pid, uid, target.Addr())

	if h.status.Load() == HDLEND {
		err = errTcpEnd
		log.D("tcp: proxy: end %v -> %v", src, target)
		return deny
	}

	actualTargets := makeIPPorts(realips, target, 0)

	if pid == ipn.Block {
		if undidAlg && len(realips) <= 0 && len(domains) > 0 {
			err = errNoIPsForDomain
		} else {
			err = errTcpFirewalled
		}
		var k string
		if len(domains) > 0 {
			k = uid + domains
		} else {
			k = uid + target.String()
		}
		secs := h.stall(k)
		if len(actualTargets) > 0 {
			smm.Target = actualTargets[0].Addr().String()
		}
		log.I("tcp: gconn %s firewalled from %s -> %s (dom: %s / real: %s) for %s; stall? %ds",
			cid, src, target, domains, realips, uid, secs)

		return deny
	}

	// handshake; since we assume a duplex-stream from here on
	if open, err = gconn.Establish(); !open {
		err = fmt.Errorf("tcp: %s connect err %v; %s -> %s for %s", cid, err, src, target, uid)
		log.E("%v", err)
		return deny // == !open
	}

	var px ipn.Proxy = nil
	if px, err = h.prox.ProxyFor(pid); err != nil || px == nil {
		return deny
	}

	if pid == ipn.Base { // see udp.go Connect
		if h.dnsOverride(gconn, target) {
			// SocketSummary not sent; x.DNSSummary supercedes it
			return allow
		} // else not a dns request
	} // if ipn.Exit then let it connect as-is (aka exit)

	// pick all realips to connect to
	for i, dstipp := range actualTargets {
		if err = h.handle(px, gconn, dstipp, smm); err == nil {
			return allow
		} // else try the next realip
		end := time.Since(smm.start)
		elapsed := int32(end.Seconds() * 1000)
		log.W("tcp: dial: #%d: %s failed; addr(%s); for uid %s (%d); w err(%v)", i, cid, dstipp, uid, elapsed, err)
		if end > retrytimeout {
			break
		}
	}

	return deny
}

// handle connects to the target via the proxy, and pipes data between the src, target; thread-safe.
func (h *tcpHandler) handle(px ipn.Proxy, src net.Conn, target netip.AddrPort, smm *SocketSummary) (err error) {
	var pc protect.Conn

	start := time.Now()
	var dst net.Conn

	// TODO: handle wildcard addrs?
	// github.com/google/gvisor/blob/5ba35f516b5c2/test/benchmarks/tcp/tcp_proxy.go#L359
	// ref: stackoverflow.com/questions/63656117
	// ref: stackoverflow.com/questions/40328025
	if pc, err = px.Dialer().Dial("tcp", target.String()); err == nil {
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

	if err != nil {
		log.W("tcp: err dialing %s proxy(%s) to dst(%v) for %s: %v", smm.ID, px.ID(), target, smm.UID, err)
		return err
	}

	core.Go("tcp.forward:"+smm.ID, func() {
		h.forward(src, dst, smm) // src always *gonet.TCPConn
	})

	log.I("tcp: new conn %s via proxy(%s); src(%s) -> dst(%s) for %s", smm.ID, px.ID(), src.LocalAddr(), target, smm.UID)
	return nil // handled; takes ownership of src
}
