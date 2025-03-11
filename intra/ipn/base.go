// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"context"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
)

// base is no-op proxy that dials into the underlying network,
// which typically is wifi or mobile but may also be a tun device.
type base struct {
	NoDNS
	ProtoAgnostic
	SkipRefresh
	GW
	addr     string
	outbound *protect.RDial         // outbound dialer
	via      *core.WeakRef[Proxy]   // via dialer
	viaID    *core.Volatile[string] // via proxy ID
	px       ProxyProvider
	status   *core.Volatile[int]
	done     context.CancelFunc
}

// Base returns a base proxy.
func NewBaseProxy(ctx context.Context, c protect.Controller, px ProxyProvider) *base {
	ctx, done := context.WithCancel(ctx)
	h := &base{
		addr:     "127.8.4.5:3690",
		px:       px,
		outbound: protect.MakeNsRDial(Base, ctx, c),
		viaID:    core.NewZeroVolatile[string](),
		status:   core.NewVolatile(TUP),
		done:     done,
	}
	var err error
	h.via, err = core.NewWeakRef[Proxy](h.viafor, viaok)
	if err != nil {
		panic(err) // unlikely
	}
	return h
}

func (h *base) viafor() *Proxy {
	return viafor(h.ID(), h.viaID.Load(), h.px)
}

func (h *base) swapVia(new Proxy) (old Proxy) {
	return swapVia(h.ID(), new, h.viaID, h.via)
}

// Handle implements Proxy.
func (h *base) Handle() uintptr {
	return core.Loc(h)
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
	if h.status.Load() == END {
		return nil, errProxyStopped
	}

	who := h.ID()
	if usevia(h.viaID) {
		if v, vok := h.via.Get(); vok { // dial via another proxy
			who = idstr(v)
			c, err = v.DialBind(network, local, remote)
		} else {
			err = errNoHop
			if removeViaOnErrors {
				h.Hop(nil, false /*dryrun*/) // stale; unset
			}
			log.W("proxy: base: via(%s@%s) failing...", idstr(v), idhandle(v))
		}
	} else {
		if settings.Loopingback.Load() { // loopback (rinr) mode
			// TODO: test if binding to local address works in rinr mode
			c, err = dialers.DialBind(h.outbound, network, local, remote)
		} else {
			c, err = localDialStrat(h.outbound, network, local, remote)
		}
	}
	defer localDialStatus(h.status, err)

	maybeKeepAlive(c)
	log.I("proxy: base: dial(%s) to %s=>%s (via %s); err? %v", network, local, remote, who, err)
	return
}

// Announce implements Proxy.
func (h *base) Announce(network, local string) (protect.PacketConn, error) {
	if h.status.Load() == END {
		return nil, errProxyStopped
	}
	c, err := dialers.ListenPacket(h.outbound, network, local)
	defer localDialStatus(h.status, err)
	log.I("proxy: base: announce(%s) on %s; err? %v", network, local, err)
	return c, err
}

// Accept implements Proxy.
func (h *base) Accept(network, local string) (protect.Listener, error) {
	if h.status.Load() == END {
		return nil, errProxyStopped
	}
	return dialers.Listen(h.outbound, network, local)
}

// Probe implements Proxy.
func (h *base) Probe(network, local string) (protect.PacketConn, error) {
	if h.status.Load() == END {
		return nil, errProxyStopped
	}
	c, err := dialers.Probe(h.outbound, network, local)
	defer localDialStatus(h.status, err)
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
func (h *base) Hop(p Proxy, dryrun bool) error {
	if p == nil {
		if !dryrun {
			old := h.swapVia(nil)
			log.I("proxy: base: hop(%s@%s) removed", idstr(old), idhandle(old))
		}
		return nil
	}
	if p.Status() == END {
		return errProxyStopped
	}
	if p.ID() != GlobalH1 {
		return errHopGlobalProxy
	}

	if !dryrun {
		old := h.swapVia(nil)
		log.I("proxy: base: hop(%s@%s) => %s", idstr(old), idhandle(old), idhandle(p))
	}
	return nil
}

// Via implements x.Router.
func (h *base) Via() (x.Proxy, error) {
	if v := h.via.Load(); v != nil {
		return v, nil
	}
	return nil, errNoHop
}

func (h *base) GetAddr() string {
	return h.addr
}

func (h *base) Status() int {
	return h.status.Load()
}

func (h *base) Stop() error {
	h.status.Store(END)
	h.done()
	log.I("proxy: base: stopped")
	return nil
}
