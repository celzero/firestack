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
	"time"

	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/netstat"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/netstack"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
)

type tcpHandler struct {
	resolver    dnsx.Resolver
	tunMode     *settings.TunMode
	listener    SocketListener
	prox        ipn.Proxies
	fwtracker   *core.ExpMap
	status      int
	conntracker core.ConnMapper // connid -> [local,remote]
}

type ioinfo struct {
	bytes int64
	err   error
}

const (
	TCPOK = iota
	TCPEND
)

const retrytimeout = 1 * time.Minute

var (
	errTcpFirewalled = errors.New("tcp: firewalled")
	errTcpSetupConn  = errors.New("tcp: could not create conn")
)

var _ netstack.GTCPConnHandler = (*tcpHandler)(nil)

// NewTCPHandler returns a TCP forwarder with Intra-style behavior.
// Connections to `fakedns` are redirected to DOH.
// All other traffic is forwarded using `dialer`.
// `listener` is provided with a summary of each socket when it is closed.
func NewTCPHandler(resolver dnsx.Resolver, prox ipn.Proxies, tunMode *settings.TunMode, ctl protect.Controller, listener SocketListener) netstack.GTCPConnHandler {
	h := &tcpHandler{
		resolver:    resolver,
		tunMode:     tunMode,
		listener:    listener,
		prox:        prox,
		fwtracker:   core.NewExpiringMap(),
		conntracker: core.NewConnMap(),
		status:      TCPOK,
	}

	log.I("tcp: new handler created")
	return h
}

func (h *tcpHandler) onFlow(localaddr, target netip.AddrPort, realips, domains, probableDomains, blocklists string) *Mark {
	// BlockModeNone returns false, BlockModeSink returns true
	if h.tunMode.BlockMode == settings.BlockModeSink {
		return optionsBlock
	} else if h.tunMode.BlockMode == settings.BlockModeNone {
		// todo: block-mode none should call into listener.Flow to determine upstream proxy
		return optionsBase
	}

	if len(realips) <= 0 || len(domains) <= 0 {
		log.D("onFlow: no realips(%s) or domains(%s + %s), for src=%s dst=%s", realips, domains, probableDomains, localaddr, target)
	}

	// Implict: BlockModeFilter or BlockModeFilterProc
	uid := -1
	if h.tunMode.BlockMode == settings.BlockModeFilterProc {
		procEntry := netstat.FindProcNetEntry("tcp", localaddr, target)
		if procEntry != nil {
			uid = procEntry.UserID
		}
	}

	var proto int32 = 6 // tcp
	src := localaddr.String()
	dst := target.String()
	dup := hasActiveConn(h.conntracker, dst, realips)
	res := h.listener.Flow(proto, uid, dup, src, dst, realips, domains, probableDomains, blocklists)

	if res == nil {
		log.W("tcp: onFlow: empty res from kt; using base")
		return optionsBase
	} else if len(res.PID) <= 0 {
		log.W("tcp: onFlow: no pid from kt; using base")
		res.PID = ipn.Base
	}

	return res
}

func (h *tcpHandler) End() error {
	h.status = TCPEND
	h.CloseConns(nil)
	return nil
}

// CloseConns implements netstack.GTCPConnHandler
func (h *tcpHandler) CloseConns(cids []string) (closed []string) {
	return closeconns(h.conntracker, cids)
}

// Proxy implements netstack.GTCPConnHandler
func (h *tcpHandler) Proxy(gconn *netstack.GTCPConn, src, target netip.AddrPort) (open bool) {
	const allow bool = true  // allowed
	const deny bool = !allow // blocked
	const rst bool = true    // tear down conn
	const ack bool = !rst    // send synack
	var s *SocketSummary
	var err error

	defer func() {
		if !open {
			gconn.Close()
			if s != nil {
				s.done(err)
				go sendNotif(h.listener, s)
			} // else: summary not created
		}
	}()

	if h.status == TCPEND {
		log.D("tcp: proxy: end")
		gconn.Connect(rst) // fin
		return deny
	}

	if !src.IsValid() || !target.IsValid() {
		log.E("tcp: nil addr %v -> %v", src, target)
		gconn.Connect(rst) // fin
		return deny
	}

	// alg happens after nat64, and so, alg knows nat-ed ips
	// that is, realips are un-nated
	realips, domains, probableDomains, blocklists := undoAlg(h.resolver, target.Addr())

	// flow/dns-override are nat-aware, as in, they can deal with
	// nat-ed ips just fine, and so, use target as-is instead of ipx4
	res := h.onFlow(src, target, realips, domains, probableDomains, blocklists)

	cid, pid, uid := splitCidPidUid(res)
	s = tcpSummary(cid, pid, uid, target.Addr())

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
		gconn.Connect(rst) // fin
		return deny
	}

	// handshake; since we assume a duplex-stream from here on
	if open, err = gconn.Connect(ack); !open {
		err = fmt.Errorf("tcp: %s connect err %v; %s -> %s for %s", cid, err, src, target, uid)
		log.E("%v", err)
		return deny // == !open
	}

	var px ipn.Proxy
	if px, err = h.prox.ProxyFor(pid); err != nil {
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
		if err = h.handle(px, gconn, dstipp, s); err == nil {
			return allow
		} // else try the next realip
		end := time.Since(s.start)
		elapsed := int32(end.Seconds() * 1000)
		log.W("tcp: dial: #%d: %s failed; addr(%s); for uid %s (%d); w err(%v)", i, cid, dstipp, uid, elapsed, err)
		if end > retrytimeout {
			break
		}
	}
	return deny
}

func (h *tcpHandler) handle(px ipn.Proxy, src net.Conn, target netip.AddrPort, smm *SocketSummary) (err error) {
	var pc protect.Conn

	start := time.Now()
	var dst net.Conn

	// TODO: handle wildcard addrs?
	// github.com/google/gvisor/blob/5ba35f516b5c2/test/benchmarks/tcp/tcp_proxy.go#L359
	// ref: stackoverflow.com/questions/63656117
	// ref: stackoverflow.com/questions/40328025
	if pc, err = px.Dial("tcp", target.String()); err == nil {
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

	go func() {
		cm := h.conntracker
		l := h.listener
		defer func() {
			if r := recover(); r != nil {
				log.W("tcp: forward: panic %v", r)
			}
		}()
		forward(src, dst, cm, l, smm) // src always *gonet.TCPConn
	}()

	log.I("tcp: new conn %s via proxy(%s); src(%s) -> dst(%s) for %s", smm.ID, px.ID(), src.LocalAddr(), target, smm.UID)
	return nil // handled; takes ownership of src
}
