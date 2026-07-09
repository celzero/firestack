// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"context"
	"sync/atomic"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
)

const fakeBaseAddr = "127.8.4.5:3690"

// base is no-op proxy that dials into the underlying network,
// which typically is wifi or mobile but may also be a tun device.
type base struct {
	NoDNS
	ProtoAgnostic
	SkipRefresh
	CantPause
	GW
	id       string
	addr     string
	outbound *protect.RDial                      // outbound dialer
	via      atomic.Pointer[core.WeakRef[Proxy]] // via dialer
	px       ProxyProvider
	status   atomic.Int32
	lastaddr atomic.Pointer[string]
	done     context.CancelFunc
}

// Base returns a base proxy.
func NewBaseProxy(ctx context.Context, c protect.Controller, px ProxyProvider) *base {
	return newBasicProxy(Base, fakeBaseAddr, ctx, c, px)
}

func newBasicProxy(id, addr string, ctx context.Context, c protect.Controller, px ProxyProvider) *base {
	ctx, done := context.WithCancel(ctx)
	h := &base{
		id:       id,
		addr:     addr,
		px:       px,
		outbound: protect.MakeNsRDial(Base, ctx, c),
		done:     done,
	}
	h.status.Store(TUP)
	h.since.Store(now())
	return h
}

func NewBasicProxy(id string, ctx context.Context, c protect.Controller, px ProxyProvider) Proxy {
	return newBasicProxy(id, fakeBaseAddr, ctx, c, px)
}

// Handle implements Proxy.
func (h *base) Handle() uint64 {
	return core.Loc(h)
}

// DialerHandle implements Proxy.
func (h *base) DialerHandle() uint64 {
	return core.Loc(h.outbound)
}

// Dial implements Proxy.
func (h *base) Dial(network, addr string) (c protect.Conn, err error) {
	return h.dial(network, "", addr)
}

// DialBind implements Proxy.
func (h *base) DialBind(network, local, remote string) (c protect.Conn, err error) {
	return h.dial(network, local, remote)
}

func (h *base) dial(network, local, remote string) (c protect.Conn, err error) {
	if err := candial(&h.status); err != nil {
		return nil, err
	}

	who := idstr(h)
	if ref := h.via.Load(); ref != nil {
		if v, vok := ref.Get(); vok { // dial via another proxy
			who = idstr(v)
			c, err = v.DialBind(network, local, remote)
		} else {
			err = errNoHop
			if removeViaOnErrors {
				h.Hop(nil, false /*dryrun*/) // stale; unset
			}
			log.W("proxy: base: via(%s) failing...", idhandle(v))
		}
	} else {
		if settings.Loopingback.Load() { // loopback (rinr) mode
			// TODO: test if binding to local address works in rinr mode
			c, err = dialers.DialBind(h.outbound, network, local, remote)
		} else {
			c, err = localDialStrat(h.outbound, network, local, remote)
		}
	}
	defer localDialStatus(&h.status, err)

	if a, ok := laddr(c); ok {
		h.lastaddr.Store(&a)
	}
	kaenabled := maybeKeepAlive(c)
	n, berr := changeBufferSizes(c)
	log.I("proxy: base: dial(%s) to %s=>%s (via %s), ka? %t, sz? %d (%v); err? %v",
		network, local, remote, who, kaenabled, n, berr, err)
	return
}

// Announce implements Proxy.
func (h *base) Announce(network, local string) (protect.PacketConn, error) {
	if err := candial(&h.status); err != nil {
		return nil, err
	}
	c, err := dialers.ListenPacket(h.outbound, network, local)
	defer localDialStatus(&h.status, err)

	n, berr := changeBufferSizes(c)
	log.I("proxy: base: announce(%s) on %s; sz? %d (%v); err? %v", network, local, n, berr, err)
	return c, err
}

// Accept implements Proxy.
func (h *base) Accept(network, local string) (protect.Listener, error) {
	if err := candial(&h.status); err != nil {
		return nil, err
	}
	return dialers.Listen(h.outbound, network, local)
}

// Probe implements Proxy.
func (h *base) Probe(network, local string) (protect.PacketConn, error) {
	if err := candial(&h.status); err != nil {
		return nil, err
	}
	c, err := dialers.Probe(h.outbound, network, local)
	defer localDialStatus(&h.status, err)
	log.I("proxy: base: probe(%s) on %s; err? %v", network, local, err)
	return c, err
}

func (h *base) Dialer() protect.RDialer {
	return h
}

func (h *base) ID() string {
	return Base
}

func (h *base) Type() string {
	return NOOP
}

func (h *base) Router() x.Router {
	return h
}

// Reaches implements x.Router.
func (h *base) Reaches(hostportOrIPPortCsv string) bool {
	return Reaches(h, hostportOrIPPortCsv)
}

// Hop implements Proxy.
func (h *base) Hop(via *core.WeakRef[Proxy], dryrun bool) error {
	if via == nil {
		if !dryrun {
			old := h.via.Swap(nil)
			log.I("proxy: base: hop removed; was %s", refhandle(old))
		}
		return nil
	}
	if p, pok := via.Get(); pok && p != nil {
		if idstr(p) != GlobalH1 {
			return errHopGlobalProxy
		}
	}

	if !dryrun {
		old := h.via.Swap(via)
		log.I("proxy: base: hop %s => %s", refhandle(old), refhandle(via))
	}
	return nil
}

// Via implements x.Router.
func (h *base) Via() (x.Proxy, error) {
	if ref := h.via.Load(); ref != nil {
		if v, ok := ref.Get(); ok && v != nil {
			return v, nil
		}
	}
	return nil, errNoHop
}

func (h *base) GetAddr() string {
	return h.addr
}

func (h *base) Status() int32 {
	return h.status.Load()
}

func (h *base) Stop() error {
	h.status.Store(END)
	h.done()
	log.I("proxy: base: stopped")
	return nil
}
