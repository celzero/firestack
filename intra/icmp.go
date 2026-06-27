// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package intra

import (
	"context"
	"net"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"

	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/netstack"
)

type icmpHandler struct {
	*baseHandler
}

var _ netstack.GICMPHandler = (*icmpHandler)(nil)

func NewICMPHandler(pctx context.Context, resolver dnsx.Resolver, prox ipn.ProxyProvider, listener Listener) netstack.GICMPHandler {
	h := &icmpHandler{
		baseHandler: newBaseHandler(pctx, "icmp", resolver, prox, listener),
	}

	core.Gx("icmp.ps", h.processSummaries)

	log.I("icmp: new handler created")
	return h
}

// Ping implements netstack.GICMPHandler. Takes ownership of msg.
// Nb: to send icmp pings, root access is required; and so,
// send "unprivileged" icmp pings via udp reqs; which do
// work on Vanilla Android, because ping_group_range is
// set to 0 2147483647
// ref: cs.android.com/android/platform/superproject/+/master:system/core/rootdir/init.rc;drc=eef0f563fd2d16343aa1ac01eebe98126f26e352;l=297
// ref: androidxref.com/9.0.0_r3/xref/libcore/luni/src/test/java/libcore/java/net/InetAddressTest.java#265
// see: sturmflut.github.io/linux/ubuntu/2015/01/17/unprivileged-icmp-sockets-on-linux/
// ex: github.com/prometheus-community/pro-bing/blob/0bacb2d5e/ping.go#L703
func (h *icmpHandler) Ping(msg []byte, source, target netip.AddrPort) (echoed bool) {
	var px ipn.Proxy = nil
	var err error
	var tx, rx int
	var rtt time.Duration

	// flow is alg/nat-aware, do not change target or any addrs
	res, undidAlg, realips, doms := h.onFlow(source, target)

	h.maybeReplaceDest(res, &target)

	preferred, _, _ := filterFamilyForDialing(realips)
	dst := oneRealIPPort(preferred, target, !undidAlg)
	// on Android, uid is always "unknown" for icmp
	cid, uid, _, pids := h.judge(res)
	smm := icmpSummary(cid, uid)

	defer func() {
		smm.PID = pidstr(px)
		smm.RPID = ipn.ViaID(px)
		smm.Target = dst.Addr().String()
		smm.Tx = int64(tx)
		smm.Rx = int64(rx)
		smm.Rtt = rtt.Milliseconds()
		h.queueSummary(smm.done(err)) // err may be nil
	}()

	if h.status.Load() == HDLEND {
		err = log.EE("t.icmp: handler ended (%s => %s)", source, target)
		return false // not handled
	}

	if isAnyBlockPid(pids) {
		smm.PID = ipn.Block
		if undidAlg && len(realips) <= 0 && len(doms) > 0 {
			err = errNoIPsForDomain
		} else {
			err = errIcmpFirewalled
		}
		log.I("t.icmp: egress: firewalled %s => %s", source, target)
		// sleep for a while to avoid busy conns? will also block netstack
		// see: netstack/dispatcher.go:newReadvDispatcher
		// time.Sleep(blocktime)
		return false // denied
	}

	if px, err = h.prox.ProxyTo(dst, uid, pids); err != nil || px == nil {
		err = log.EE("t.icmp: egress: no proxy(%s); err %v", pids, err)
		return false // denied
	}

	smm.PID = pidstr(px)
	smm.RPID = ipn.ViaID(px)
	smm.Target = dst.Addr().String()

	if h.loopDetected(smm) {
		log.I("t.icmp: loop: break %s => %s via %s for %s; exiting...", source, dst, pidstr(px), uid)
		px, err = h.prox.ProxyTo(dst, uid, onlyExitPid)
		smm.PID = ipn.Exit
		smm.RPID = ""
	}

	if px == nil || err != nil {
		return false // unhandled
	}

	h.loopAssoc(smm)
	defer h.loopUnassoc(smm)

	rttstart := time.Now()
	proto, anyaddr := anyaddrFor(dst)

	uc, err := px.Dialer().Probe(proto, anyaddr)
	defer core.Close(uc)
	ucnil := uc == nil || core.IsNil(uc)

	// nilaway: tx.socks5 returns nil conn even if err == nil
	if err != nil || ucnil {
		err = core.OneErr(err, unix.ENETUNREACH)
		err = log.EE("t.icmp: egress: dial(%s); hasConn? %s(%t); err %v",
			dst, pids, !ucnil, err)
		return false // unhandled
	}

	h.conntracker.Track(cid, uid, pidstr(px), uc)
	defer h.conntracker.Untrack(cid)

	awaited := core.Await(func() {
		h.flowing(smm)
	}, onFlowTimeout)

	tx = len(msg)
	// todo: construct ICMP header? github.com/prometheus-community/pro-bing/blob/0bacb2d5e7/ping.go#L717
	reply, from, err := core.Echo(uc, msg, net.UDPAddrFromAddrPort(dst), target.Addr().Is4())
	rx = len(reply)
	rtt = time.Since(rttstart)
	// todo: ignore non-ICMP replies in b: github.com/prometheus-community/pro-bing/blob/0bacb2d5e7/ping.go#L630
	logev(err)("t.icmp: ingress: read(%v <= %v / %v) ping done (send: %d, recv: %d, rtt: %s); postflow? %t; err? %v",
		source, from, dst, tx, rx, core.FmtPeriod(rtt), awaited, err)

	// TODO: on timeout errs, return false?
	return true // echoed
}
