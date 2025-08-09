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
	outbound *protect.RDial         // outbound dialer
	via      *core.WeakRef[Proxy]   // via dialer
	viaID    *core.Volatile[string] // via proxy ID
	px       ProxyProvider
	status   *core.Volatile[int]
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
		viaID:    core.NewZeroVolatile[string](),
		status:   core.NewVolatile(TUP),
		done:     done,
	}
	var err error
	h.via, err = core.NewWeakRef(h.viafor, viaok)
	if err != nil {
		panic(err) // unlikely
	}
	return h
}

func NewBasicProxy(id string, ctx context.Context, c protect.Controller, px ProxyProvider) Proxy {
	return newBasicProxy(id, fakeBaseAddr, ctx, c, px)
}

func (h *base) viafor() *Proxy {
	return viafor(idstr(h), h.viaID.Load(), h.px)
}

func (h *base) swapVia(new Proxy) (old Proxy) {
	return swapVia(idstr(h), new, h.viaID, h.via)
}

// Handle implements Proxy.
func (h *base) Handle() uintptr {
	return core.Loc(h)
}

// DialerHandle implements Proxy.
func (h *base) DialerHandle() uintptr {
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
	if err := candial(h.status); err != nil {
		return nil, err
	}

	who := idstr(h)
	if usevia(h.viaID) {
		if v, vok := h.via.Get(); vok { // dial via another proxy
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
	defer localDialStatus(h.status, err)

	kaenabled := maybeKeepAlive(c)
	log.I("proxy: base: dial(%s) to %s=>%s (via %s), ka? %t; err? %v",
		network, local, remote, who, kaenabled, err)
	return
}

// Announce implements Proxy.
func (h *base) Announce(network, local string) (protect.PacketConn, error) {
	if err := candial(h.status); err != nil {
		return nil, err
	}
	c, err := dialers.ListenPacket(h.outbound, network, local)
	defer localDialStatus(h.status, err)
	log.I("proxy: base: announce(%s) on %s; err? %v", network, local, err)
	return c, err
}

// Accept implements Proxy.
func (h *base) Accept(network, local string) (protect.Listener, error) {
	if err := candial(h.status); err != nil {
		return nil, err
	}
	return dialers.Listen(h.outbound, network, local)
}

// Probe implements Proxy.
func (h *base) Probe(network, local string) (protect.PacketConn, error) {
	if err := candial(h.status); err != nil {
		return nil, err
	}
	c, err := dialers.Probe(h.outbound, network, local)
	defer localDialStatus(h.status, err)
	log.I("proxy: base: probe(%s) on %s; err? %v", network, local, err)
	return c, err
}

func (h *base) Dialer() protect.RDialer {
	return h
}

func (h *base) ID() *x.Gostr {
	return x.StrOf(Base)
}

func (h *base) Type() *x.Gostr {
	return x.StrOf(NOOP)
}

func (h *base) Router() x.Router {
	return h
}

// Reaches implements x.Router.
func (h *base) Reaches(hostportOrIPPortCsv *x.Gostr) bool {
	return Reaches(h, hostportOrIPPortCsv.V())
}

// Hop implements Proxy.
func (h *base) Hop(p Proxy, dryrun bool) error {
	if p == nil {
		if !dryrun {
			old := h.swapVia(nil)
			log.I("proxy: base: hop(%s) removed", idhandle(old))
		}
		return nil
	}
	if p.Status() == END {
		return errProxyStopped
	}
	if idstr(p) != GlobalH1 {
		return errHopGlobalProxy
	}

	if !dryrun {
		old := h.swapVia(nil)
		log.I("proxy: base: hop %s => %s", idhandle(old), idhandle(p))
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

func (h *base) GetAddr() *x.Gostr {
	return x.StrOf(h.addr)
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
