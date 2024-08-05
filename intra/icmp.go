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
	"github.com/celzero/firestack/intra/netstat"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/netstack"
	"github.com/celzero/firestack/intra/settings"
)

type icmpHandler struct {
	resolver dnsx.Resolver
	tunMode  *settings.TunMode
	prox     ipn.Proxies
	listener Listener
	smmch    chan *SocketSummary
	done     chan struct{} // always unbuffered, never nil

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
		resolver: resolver,
		tunMode:  tunMode,
		prox:     prox,
		listener: listener,
		smmch:    make(chan *SocketSummary, smmchSize),
		done:     make(chan struct{}),
		status:   core.NewVolatile(ICMPOK),
	}

	go sendSummary(h.smmch, h.done, listener)

	log.I("icmp: new handler created")
	return h
}

func (h *icmpHandler) onFlow(source, target netip.AddrPort, realips, domains, probableDomains, blocklists string) (pid, cid string, block bool) {
	// BlockModeNone returns false, BlockModeSink returns true
	blockmode := h.tunMode.BlockMode.Load()
	if blockmode == settings.BlockModeSink {
		pid = ipn.Block
		block = true
		return
	}
	// todo: block-mode none should call into listener.Flow to determine upstream proxy
	if blockmode == settings.BlockModeNone {
		pid = ipn.Base
		block = false
		return
	}

	uid := -1
	if blockmode == settings.BlockModeFilterProc {
		procEntry := netstat.FindProcNetEntry("icmp", source, target)
		if procEntry != nil {
			uid = procEntry.UserID
		}
	}

	var proto int32 = 1 // icmp
	src := source.String()
	dst := target.String()
	// todo: handle forwarding icmp to appropriate proxy?
	res := h.listener.Flow(proto, int32(uid), src, dst, realips, domains, probableDomains, blocklists)

	cid, pid, _ = splitCidPidUid(res)
	block = pid == ipn.Block
	return
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

// CloseConns implements netstack.GICMPHandler.
func (h *icmpHandler) CloseConns(cids []string) []string { return nil }

// PingOnce implements netstack.GICMPHandler.
func (h *icmpHandler) PingOnce(src, dst netip.AddrPort, msg []byte) bool {
	return h.Ping(src, dst, msg)
}

// Ping implements netstack.GICMPHandler.
// Nb: to send icmp pings, root access is required; and so,
// send "unprivileged" icmp pings via udp reqs; which do
// work on Vanilla Android, because ping_group_range is
// set to 0 2147483647
// ref: cs.android.com/android/platform/superproject/+/master:system/core/rootdir/init.rc;drc=eef0f563fd2d16343aa1ac01eebe98126f26e352;l=297
// ref: androidxref.com/9.0.0_r3/xref/libcore/luni/src/test/java/libcore/java/net/InetAddressTest.java#265
// see: sturmflut.github.io/linux/ubuntu/2015/01/17/unprivileged-icmp-sockets-on-linux/
// ex: github.com/prometheus-community/pro-bing/blob/0bacb2d5e/ping.go#L703
func (h *icmpHandler) Ping(source, target netip.AddrPort, msg []byte) (echoed bool) {
	if h.status.Load() == ICMPEND {
		log.D("t.icmp: handler ended")
		return // not handled
	}
	var px ipn.Proxy = nil
	var err error

	realips, domains, probableDomains, blocklists := undoAlg(h.resolver, target.Addr())

	// flow is alg/nat-aware, do not change target or any addrs
	pid, cid, block := h.onFlow(source, target, realips, domains, probableDomains, blocklists)
	smm := icmpSummary(cid, pid)

	defer func() {
		if !echoed {
			queueSummary(h.smmch, h.done, smm.done(err))
		}
	}()

	if block {
		log.I("t.icmp: egress: firewalled %s -> %s", source, target)
		// sleep for a while to avoid busy conns? will also block netstack
		// see: netstack/dispatcher.go:newReadvDispatcher
		// time.Sleep(blocktime)
		return false // denied
	}

	if px, err = h.prox.ProxyFor(pid); err != nil || px == nil {
		log.E("t.icmp: egress: no proxy(%s); err %v", pid, err)
		return false // denied
	}

	defer func() {
		queueSummary(h.smmch, h.done, smm.done(err))
	}()

	dst := oneRealIp(realips, target)
	uc, err := px.Dialer().Dial("udp", dst.String())
	ucnil := uc == nil || core.IsNil(uc)
	if err != nil || ucnil { // nilaway: tx.socks5 returns nil conn even if err == nil
		if err == nil {
			err = unix.ENETUNREACH
		}
		log.E("t.icmp: egress: dial(%s); hasConn? %s(%t); err %v", dst, pid, ucnil, err)
		return // unhandled
	}

	defer queueSummary(h.smmch, h.done, smm.done(err)) // err may be nil
	defer clos(uc)

	extend(uc, icmptimeout)

	_, err = uc.Write(msg)
	logei(err, "t.icmp: egress: write(%v <- %v) ping; done %d; err? %v", dst, source, len(msg), err)
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
	_, err = uc.Read(b)
	logei(err, "t.icmp: ingress: read(%v <- %v) ping done; err? %v", source, dst, err)

	return true // echoed; even if err != nil
}

func extend(c net.Conn, t time.Duration) {
	if c != nil && core.IsNotNil(c) {
		_ = c.SetDeadline(time.Now().Add(t))
	}
}

func logei(err error, msg string, args ...any) {
	f := log.E
	if err == nil {
		f = log.I
	}
	f(msg, args...)
}
