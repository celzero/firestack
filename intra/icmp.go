// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package intra

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/netstack"
	"github.com/celzero/firestack/intra/settings"
)

type icmpHandler struct {
	*baseHandler
	prox  ipn.Proxies
	smmch chan *SocketSummary
	done  chan struct{} // always unbuffered, never nil

	once sync.Once

	// mutable fields below

	status *core.Volatile[int]
}

const (
	ICMPOK = iota
	ICMPEND
)

const (
	blocktime   = 25 * time.Second
	icmptimeout = 10 * time.Second
)

var _ netstack.GICMPHandler = (*icmpHandler)(nil)

func NewICMPHandler(resolver dnsx.Resolver, prox ipn.Proxies, tunMode *settings.TunMode, listener Listener) netstack.GICMPHandler {
	h := &icmpHandler{
		baseHandler: &baseHandler{
			resolver: resolver,
			tunMode:  tunMode,
			listener: listener,
		},
		prox:   prox,
		smmch:  make(chan *SocketSummary, smmchSize),
		done:   make(chan struct{}),
		status: core.NewVolatile(ICMPOK),
	}

	go sendSummary(h.smmch, h.done, listener)

	log.I("icmp: new handler created")
	return h
}

func (h *icmpHandler) flow(source, target netip.AddrPort) (_ *Mark, _ bool, _, _ string) {
	proto := "icmp"
	if target.Addr().Is6() {
		proto = "icmp6"
	}
	return h.onFlow(proto, source, target)
}

// End implements netstack.GICMPHandler.
func (h *icmpHandler) End() error {
	h.once.Do(func() {
		h.CloseConns(nil)
		h.status.Store(ICMPEND)
		close(h.done)
		close(h.smmch) // close listener chan
		log.I("icmp: handler end %x %x", h.done, h.smmch)
	})
	return nil
}

// TODO: stub
func (h *icmpHandler) OpenConns() string {
	return ""
}

// CloseConns implements netstack.GICMPHandler.
func (h *icmpHandler) CloseConns(cids []string) []string { return nil }

// Ping implements netstack.GICMPHandler.
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

	// flow is alg/nat-aware, do not change target or any addrs
	res, undidAlg, realips, doms := h.flow(source, target)
	dst := oneRealIPPort(realips, target)
	// on Android, uid is always "unknown" for icmp
	cid, pid, uid := splitCidPidUid(res)
	smm := icmpSummary(cid, pid, uid)

	defer func() {
		smm.Tx = int64(tx)
		smm.Rx = int64(rx)
		smm.Target = dst.Addr().String()
		queueSummary(h.smmch, h.done, smm.done(err)) // err may be nil
	}()

	if h.status.Load() == ICMPEND {
		err = errIcmpEnd
		log.D("t.icmp: handler ended (%s => %s)", source, target)
		return false // not handled
	}

	if pid == ipn.Block {
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

	if px, err = h.prox.ProxyFor(pid); err != nil || px == nil {
		log.E("t.icmp: egress: no proxy(%s); err %v", pid, err)
		return false // denied
	}

	proto, anyaddr := anyaddrFor(dst)

	uc, err := px.Dialer().Probe(proto, anyaddr)
	defer core.Close(uc)

	ucnil := uc == nil || core.IsNil(uc)
	smm.Target = dst.Addr().String()
	if err != nil || ucnil { // nilaway: tx.socks5 returns nil conn even if err == nil
		if err == nil {
			err = unix.ENETUNREACH
		}
		log.E("t.icmp: egress: dial(%s); hasConn? %s(%t); err %v", dst, pid, !ucnil, err)
		return false // unhandled
	}

	extend(uc, icmptimeout)
	// todo: construct ICMP header? github.com/prometheus-community/pro-bing/blob/0bacb2d5e7/ping.go#L717
	tx, err = uc.WriteTo(msg, net.UDPAddrFromAddrPort(dst))
	logei(err)("t.icmp: egress: write(%v <= %v) ping; done %d; err? %v", dst, source, len(msg), err)
	if err != nil {
		return false // write error
	}

	bptr := core.Alloc()
	b := *bptr
	b = b[:cap(b)]
	defer func() {
		*bptr = b
		core.Recycle(bptr)
	}()

	extend(uc, icmptimeout)
	rx, from, err := uc.ReadFrom(b) // todo: assert from == dst
	// todo: ignore non-ICMP replies in b: github.com/prometheus-community/pro-bing/blob/0bacb2d5e7/ping.go#L630
	logei(err)("t.icmp: ingress: read(%v <= %v / %v) ping done; err? %v", source, from, dst, err)

	return true // echoed; even if err != nil
}

func extend(c core.MinConn, t time.Duration) {
	if c != nil && core.IsNotNil(c) {
		_ = c.SetDeadline(time.Now().Add(t))
	}
}

func anyaddrFor(ipp netip.AddrPort) (proto, anyaddr string) {
	anyaddr = "0.0.0.0:0"
	proto = "udp4"
	if ipp.Addr().Is6() {
		proto = "udp6"
		anyaddr = "[::]:0"
	}
	return
}

func logei(err error) log.LogFn {
	f := log.E
	if err == nil {
		f = log.I
	}
	return f
}

func logev(err error) log.LogFn {
	f := log.E
	if err == nil {
		f = log.VV
	}
	return f
}
