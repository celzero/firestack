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

	go sendSummary(h.smmch, listener)

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
		h.status.Store(ICMPEND)
		close(h.done)
		h.CloseConns(nil)
		core.Go("icmp.Close", func() {
			time.Sleep(2 * time.Second) // wait a bit
			close(h.smmch)              // close listener chan
			log.I("icmp: smm chan closed %x", h.smmch)
		})
		log.I("icmp: handler end %x %x", h.done, h.smmch)
	})
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
	if h.status.Load() == ICMPEND {
		log.D("t.icmp: handler ended")
		return
	}
	var px ipn.Proxy = nil
	var err error

	realips, domains, probableDomains, blocklists := undoAlg(h.resolver, target.Addr())

	// flow is alg/nat-aware, do not change target or any addrs
	pid, cid, block := h.onFlow(source, target, realips, domains, probableDomains, blocklists)
	smm := icmpSummary(cid, pid)

	defer func() {
		if !open {
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

	// always forward in a goroutine to avoid blocking netstack
	// see: netstack/dispatcher.go:newReadvDispatcher
	core.Gx("icmp.Ping", func() {
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
		defer clos(uc)

		extend(uc, icmptimeout)
		if _, err = uc.Write(msg); err != nil {
			log.E("t.icmp: egress:  write(%v) ping; err %v", target, err)
			return // unhandled
		}
		log.I("t.icmp: egress: writeTo(%v) ping; done %d", target, len(msg))

		if pong == nil {
			// single ping, block until done
			h.fetch(uc, nil, smm)
		} else {
			// multi ping, non-blocking
			h.fetch(uc, pong, smm)
		}
	})
	return true // handled
}

// fetch reads from the connection and sends the pong back to the caller.
// If pong is nil, it reads only the first ping and returns.
// If pong is not nil, it reads multiple pings and sends the pongs back.
// Returns true if the ping was successful, false otherwise.
// c is owned by fetch, and summary is sent back to the listener.
// Must be called in a goroutine.
func (h *icmpHandler) fetch(c net.Conn, pong netstack.Pong, smm *SocketSummary) (success bool) {
	var err error
	var n int

	defer func() {
		clos(c)
		queueSummary(h.smmch, h.done, smm.done(err))
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
		if h.status.Load() == ICMPEND {
			log.D("icmp: handler ended")
			return
		}

		extend(c, icmptimeout)
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

func extend(c net.Conn, t time.Duration) {
	if c != nil && core.IsNotNil(c) {
		_ = c.SetDeadline(time.Now().Add(t))
	}
}
