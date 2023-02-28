// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package intra

import (
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/netstack"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
)

type ICMPHandler interface {
	netstack.GICMPHandler
}

type icmpHandler struct {
	UDPHandler
	sync.RWMutex

	resolver dnsx.Resolver
	timeout  time.Duration
	udpConns map[core.UDPConn]*tracker
	config   *net.ListenConfig
	dialer   *net.Dialer
	blocker  protect.Blocker
	tunMode  *settings.TunMode
	pt       ipn.NAT64
}

// NewUDPHandler makes a UDP handler with Intra-style DNS redirection:
// All packets are routed directly to their destination.
// `timeout` controls the effective NAT mapping lifetime.
// `config` is used to bind new external UDP ports.
func NewICMPHandler(resolver dnsx.Resolver, pt ipn.NAT64, blocker protect.Blocker,
	tunMode *settings.TunMode) ICMPHandler {
	udptimeout, _ := time.ParseDuration("30s")
	c := protect.MakeListenConfig2(blocker)
	d := protect.MakeDialer2(blocker)
	h := &icmpHandler{
		timeout:  udptimeout,
		udpConns: make(map[core.UDPConn]*tracker, 8),
		resolver: resolver,
		blocker:  blocker,
		tunMode:  tunMode,
		config:   c,
		dialer:   d,
		pt:       pt,
	}

	return h
}

func (h *icmpHandler) onFlow(source *net.UDPAddr, target *net.UDPAddr, realips, domains, blocklists string) (block bool) {
	// BlockModeNone returns false, BlockModeSink returns true
	if h.tunMode.BlockMode == settings.BlockModeSink {
		return true
	}
	if h.tunMode.BlockMode == settings.BlockModeNone {
		return false
	}

	uid := -1
	if h.tunMode.BlockMode == settings.BlockModeFilterProc {
		procEntry := settings.FindProcNetEntry("icmp", source.IP, source.Port, target.IP, target.Port)
		if procEntry != nil {
			uid = procEntry.UserID
		}
	}

	var proto int32 = 1 // icmp
	src := source.String()
	dst := target.String()
	if len(realips) > 0 && len(domains) > 0 {
		block = h.blocker.BlockAlg(proto, uid, src, dst, realips, domains, blocklists)
	} else {
		block = h.blocker.Block(proto, uid, src, dst)
	}

	if block {
		log.Infof("t.icmp.egress: firewalled src(%s:%s) -> dst(%s:%s)",
			source.Network(), src, target.Network(), dst)
	}
	return block
}

func (h *icmpHandler) Ping(source *net.UDPAddr, destination *net.UDPAddr, message []byte, pong netstack.Pong) bool {
	ipx4 := maybeUndoNat64(h.pt, destination.IP)
	realips, domains, blocklists := undoAlg(h.resolver, ipx4)

	// flow is alg/nat-aware, do not change target or any addrs
	if h.onFlow(source, destination, realips, domains, blocklists) {
		log.Errorf("t.icmp.connect: firewalled")
		return false
	}

	destination.IP = oneRealIp(realips, ipx4)
	c, err := h.dialer.Dial(destination.Network(), destination.String())
	if err != nil {
		log.Errorf("t.icmp.connect: dail err %v", err)
		c.Close()
		return false
	}
	c.SetDeadline(time.Now().Add(h.timeout))
	if _, err = c.Write(message); err != nil {
		log.Errorf("t.icmp.egress:  write(%v) ping; err %v", destination, err)
		c.Close()
		return false
	}

	go h.fetch(c, pong)

	return true
}

func (h *icmpHandler) fetch(c net.Conn, pong netstack.Pong) {
	defer c.Close()
	b := core.NewBytes(core.BufSize)
	defer core.FreeBytes(b)
	for {
		c.SetDeadline(time.Now().Add(h.timeout))
		if n, err := c.Read(b); err != nil {
			log.Errorf("t.icmp.ingress: read(%v <- %v) ping err %v", c.LocalAddr(), c.RemoteAddr(), err)
			break
		} else if err = pong(b[:n]); err != nil {
			if err != unix.ENETUNREACH {
				log.Errorf("t.icmp.ingress: write(%v <- %v) pong err %v", c.LocalAddr(), c.RemoteAddr(), err)
			}
			break
		}
	}
}
