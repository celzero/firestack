// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package intra

import (
	"net"
	"net/netip"
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
	status   int
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
		status:   ICMPOK,
	}

	log.I("icmp: new handler created")
	return h
}

func (h *icmpHandler) onFlow(source, target netip.AddrPort, realips, domains, probableDomains, blocklists string) (pid, cid string, block bool) {
	// BlockModeNone returns false, BlockModeSink returns true
	if h.tunMode.BlockMode == settings.BlockModeSink {
		pid = ipn.Block
		block = true
		return
	}
	// todo: block-mode none should call into listener.Flow to determine upstream proxy
	if h.tunMode.BlockMode == settings.BlockModeNone {
		pid = ipn.Base
		block = false
		return
	}

	uid := -1
	if h.tunMode.BlockMode == settings.BlockModeFilterProc {
		procEntry := netstat.FindProcNetEntry("icmp", source, target)
		if procEntry != nil {
			uid = procEntry.UserID
		}
	}

	var proto int32 = 1 // icmp
	src := source.String()
	dst := target.String()
	dup := false // TODO: find if dup traffic
	// todo: handle forwarding icmp to appropriate proxy?
	res := h.listener.Flow(proto, uid, dup, src, dst, realips, domains, probableDomains, blocklists)

	cid, pid, _ = splitCidPidUid(res)
	block = pid == ipn.Block
	return
}

// End implements netstack.GICMPHandler.
func (h *icmpHandler) End() error {
	h.status = ICMPEND
	h.CloseConns(nil)
	return nil
}

// CloseConns implements netstack.GICMPHandler.
func (h *icmpHandler) CloseConns(cids []string) []string { return nil }

// PingOnce implements netstack.GICMPHandler.
func (h *icmpHandler) PingOnce(src, dst netip.AddrPort, msg []byte) bool {
	return h.Ping(src, dst, msg, nil /*no pong*/)
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
func (h *icmpHandler) Ping(source, target netip.AddrPort, msg []byte, pong netstack.Pong) (open bool) {
	if h.status == ICMPEND {
		log.D("t.icmp: handler ended")
		return
	}
	var px ipn.Proxy
	var err error

	realips, domains, probableDomains, blocklists := undoAlg(h.resolver, target.Addr())

	// flow is alg/nat-aware, do not change target or any addrs
	pid, cid, block := h.onFlow(source, target, realips, domains, probableDomains, blocklists)
	summary := icmpSummary(cid, pid)

	defer func() {
		if !open {
			summary.done(err)
			go h.sendNotif(summary)
		}
	}()

	if block {
		log.I("t.icmp: egress: firewalled %s -> %s", source, target)
		// sleep for a while to avoid busy conns
		time.Sleep(blocktime)
		return false // denied
	}

	if px, err = h.prox.ProxyFor(pid); err != nil {
		log.E("t.icmp: egress: no proxy(%s); err %v", pid, err)
		return false // denied
	}

	dst := oneRealIp(realips, target)
	uc, err := px.Dialer().Dial("udp", dst.String())
	if err != nil || uc == nil { // nilaway: tx.socks5 returns nil conn even if err == nil
		if err == nil {
			err = unix.ENETUNREACH
		}
		log.E("t.icmp: egress: dial(%s); hasConn? %s(%t); err %v", dst, pid, uc != nil, err)
		return false // denied
	}
	defer clos(uc)

	uc.SetDeadline(time.Now().Add(icmptimeout))
	if _, err = uc.Write(msg); err != nil {
		log.E("t.icmp: egress:  write(%v) ping; err %v", target, err)
		return false // denied
	}
	log.I("t.icmp: egress: writeTo(%v) ping; done %d", target, len(msg))

	if pong == nil {
		// single ping, block until done
		return h.fetch(uc, nil, summary)
	} else {
		// multi ping, non-blocking
		go h.fetch(uc, pong, summary)
		return true
	}
}

func (h *icmpHandler) fetch(c net.Conn, pong netstack.Pong, summary *SocketSummary) (success bool) {
	var err error
	var n int

	defer func() {
		clos(c)
		summary.done(err)
		go h.sendNotif(summary)
	}()

	bptr := core.Alloc()
	b := *bptr
	b = b[:cap(b)]
	defer func() {
		*bptr = b
		core.Recycle(bptr)
	}()

	src := c.LocalAddr()
	dst := c.RemoteAddr()
	for {
		if h.status == ICMPEND {
			log.D("icmp: handler ended")
			return
		}

		c.SetDeadline(time.Now().Add(icmptimeout))
		if n, err = c.Read(b); err != nil {
			log.E("t.icmp: ingress: read(%v <- %v) ping err %v", src, dst, err)
			success = success || false
			break // on error, stop
		} else if pong != nil { // process multiple pings
			if err = pong(b[:n]); err != nil {
				if err != unix.ENETUNREACH {
					log.E("t.icmp: ingress: write(%v <- %v) pong err %v", src, dst, err)
				}
				break // on error, stop
			} else {
				success = true
				continue // on success, continue
			}
		} else { // just the first ping
			success = true
			break
		}
	}
	log.I("t.icmp: ingress: ReadFrom(%v <- %v) ping done; ok? %t", src, dst, success)
	return
}

func (h *icmpHandler) sendNotif(s *SocketSummary) {
	l := h.listener
	if l == nil || s == nil || h.status == ICMPEND {
		return
	}
	l.OnSocketClosed(s)
}
