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
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
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
	prox        ipn.Proxies     // proxy provider for egress
	fwtracker   *core.ExpMap    // uid+dst(domainOrIP) -> blockSecs
	conntracker core.ConnMapper // connid -> [local,remote]
	smmch       chan *SocketSummary
	done        chan struct{} // always unbuffered, never nil

	once sync.Once

	// fields below are mutable

	status *core.Volatile[int] // status of this handler
}

type ioinfo struct {
	bytes int64
	err   error
}

const (
	TCPOK = iota
	TCPEND
)

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
func NewTCPHandler(resolver dnsx.Resolver, prox ipn.Proxies, tunMode *settings.TunMode, ctl protect.Controller, listener SocketListener) netstack.GTCPConnHandler {
	if listener == nil || core.IsNil(listener) {
		log.W("tcp: using noop listener")
		listener = nooplistener
	}

	h := &tcpHandler{
		baseHandler: &baseHandler{
			resolver: resolver,
			tunMode:  tunMode,
			listener: listener,
		},
		prox:        prox,
		fwtracker:   core.NewExpiringMap(),
		conntracker: core.NewConnMap(),
		smmch:       make(chan *SocketSummary, smmchSize),
		done:        make(chan struct{}),
		status:      core.NewVolatile(TCPOK),
	}

	go sendSummary(h.smmch, h.done, listener)

	log.I("tcp: new handler created")
	return h
}

func (h *tcpHandler) End() error {
	h.once.Do(func() {
		h.CloseConns(nil)
		h.status.Store(TCPEND)
		close(h.done)  // signal close listener send
		close(h.smmch) // close listener chan
		log.I("tcp: handler end %x %x", h.done, h.smmch)
	})
	return nil
}

// CloseConns implements netstack.GTCPConnHandler
func (h *tcpHandler) CloseConns(cids []string) (closed []string) {
	return closeconns(h.conntracker, cids)
}

// Error implements netstack.GTCPConnHandler.
// It must be called from a goroutine.
func (h *tcpHandler) Error(gconn *netstack.GTCPConn, src, dst netip.AddrPort, err error) {
	ok := h.Proxy(gconn, src, dst)
	log.I("tcp: proxy: %v -> %v; err %v; recovered? %t", src, dst, err, ok)
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
			queueSummary(h.smmch, h.done, smm.done(err)) // smm may be nil
		}
	}()

	// flow/dns-override are nat-aware, as in, they can deal with
	// nat-ed ips just fine, and so, use target as-is instead of ipx4
	res, realips, domains, probableDomains := h.onFlow("tcp", src, target)
	cid, pid, uid := splitCidPidUid(res)
	smm = tcpSummary(cid, pid, uid, target.Addr())

	if h.status.Load() == TCPEND {
		err = errTcpEnd
		log.D("tcp: proxy: end %v -> %v", src, target)
		return deny
	}

	if pid == ipn.Block {
		var secs uint32
		k := uid + target.String()
		if len(domains) > 0 { // probableDomains are not reliable to use for firewalling
			k = uid + domains
		}
		if secs = stall(h.fwtracker, k); secs > 0 {
			waittime := time.Duration(secs) * time.Second
			time.Sleep(waittime)
		}
		log.I("tcp: gconn %s firewalled from %s -> %s (dom: %s + %s/ real: %s) for %s; stall? %ds", cid, src, target, domains, probableDomains, realips, uid, secs)
		err = errTcpFirewalled
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

	if pid != ipn.Exit { // see udp.go Connect
		if dnsOverride(h.resolver, dnsx.NetTypeTCP, gconn, target) {
			// SocketSummary not sent; x.DNSSummary supercedes it
			return allow
		} // else not a dns request
	} // if ipn.Exit then let it connect as-is (aka exit)

	// pick all realips to connect to
	for i, dstipp := range makeIPPorts(realips, target, 0) {
		// h.conntracker.TrackDest(ct, dstipp) // may be untracked by handle()
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

	// h.conntracker.Untrack(cid) // untrack if disallowed
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
		// pc.RemoteAddr may be that of the proxy, not the actual dst
		// ex: pc.RemoteAddr is 127.0.0.1 for Orbot
		smm.Target = target.Addr().String()

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

	if err != nil {
		log.W("tcp: err dialing %s proxy(%s) to dst(%v) for %s: %v", smm.ID, px.ID(), target, smm.UID, err)
		return err
	}

	h.conntracker.Track(smm.ID, src, dst)
	core.Go("tcp.forward:"+smm.ID, func() {
		defer h.conntracker.Untrack(smm.ID)
		forward(src, dst, h.smmch, h.done, smm) // src always *gonet.TCPConn
	})

	log.I("tcp: new conn %s via proxy(%s); src(%s) -> dst(%s) for %s", smm.ID, px.ID(), src.LocalAddr(), target, smm.UID)
	return nil // handled; takes ownership of src
}
