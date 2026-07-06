// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"context"
	"crypto/tls"
	"net/url"
	"sync/atomic"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	tx "github.com/celzero/firestack/intra/ipn/h1"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	"golang.org/x/net/proxy"
)

type http1 struct {
	NoFwd       // no forwarding/listening
	NoDNS       // no dns
	SkipRefresh // no refresh
	GW          // dual stack gateway

	id       string
	outbound proxy.Dialer
	via      atomic.Pointer[core.WeakRef[Proxy]]
	px       ProxyProvider
	opts     *settings.ProxyOptions
	lastdial time.Time
	status   atomic.Int32
	lastaddr atomic.Pointer[string]
}

func NewHTTPProxy(id string, ctx context.Context, c protect.Controller, px ProxyProvider, po *settings.ProxyOptions) (*http1, error) {
	var err error
	if po == nil {
		log.W("proxy: err setting up http1 w(%v): %v", po, err)
		return nil, errMissingProxyOpt
	}

	u, err := url.Parse(po.Url())
	if err != nil {
		log.W("proxy: http1: err proxy opts(%v): %v", po, err)
		return nil, errProxyScheme
	}

	d := protect.MakeNsRDial(id, ctx, c)

	opts := make([]tx.Opt, 0)
	optdialer := tx.WithDialer(d)
	opts = append(opts, optdialer)
	if po.Scheme == "https" && len(po.Host) > 0 {
		opttls := tx.WithTls(&tls.Config{
			ServerName: po.Host,
			MinVersion: tls.VersionTLS12,
		})
		opts = append(opts, opttls)
	}
	if po.HasAuth() {
		optauth := tx.WithProxyAuth(tx.AuthBasic(po.Auth.User, po.Auth.Password))
		opts = append(opts, optauth)
	}

	hp := tx.New(u, opts...)

	h := &http1{
		outbound: hp, // does not support udp
		px:       px,
		id:       id,
		opts:     po,
	}
	h.status.Store(TUP)

	logeif(err != nil)("proxy: http1: created %s with opts(%s); err? %v",
		h.ID(), po, err)

	return h, nil
}

// Handle implements Proxy.
func (h *http1) Handle() uint64 {
	return core.Loc(h)
}

// DialerHandle implements Proxy.
func (h *http1) DialerHandle() uint64 {
	return core.Loc(h.outbound)
}

// Dial implements Proxy.
func (h *http1) Dial(network, addr string) (c protect.Conn, err error) {
	if err := candial(&h.status); err != nil {
		return nil, err
	}

	h.lastdial = time.Now()

	who := idstr(h)
	if ref := h.via.Load(); ref != nil {
		if v, vok := ref.Get(); vok { // dial via another proxy
			who = idstr(v)
			c, err = v.Dial(network, addr)
		} else {
			err = errNoHop
			if removeViaOnErrors {
				h.Hop(nil, false /*dryrun*/) // stale; unset
			}
			log.W("http1: via(%s) failing...", idhandle(v))
		}
	} else {
		// actually, dialers.ProxyDial not needed, because
		// tx.HttpTunnel.Dial() supports dialing into hostnames
		c, err = dialers.ProxyDial(h.outbound, network, addr)
	}
	defer localDialStatus(&h.status, err)

	if a, ok := laddr(c); ok {
		h.lastaddr.Store(&a)
	}
	log.I("proxy: http1: dial(%s) from %s => %s (via %s); err? %v", network, h.GetAddr(), addr, who, err)
	return
}

// DialBind implements Proxy.
func (h *http1) DialBind(network, local, remote string) (c protect.Conn, err error) {
	log.D("http1: dialbind(%s) from %s to %s not supported", network, local, remote)
	// TODO: error instead?
	return h.Dial(network, remote)
}

func (h *http1) Dialer() protect.RDialer {
	return h
}

func (h *http1) ID() string {
	return h.id
}

func (h *http1) Type() string {
	return HTTP1
}

func (h *http1) Router() x.Router {
	return h
}

// Reaches implements x.Router.
func (h *http1) Reaches(hostportOrIPPortCsv string) bool {
	return Reaches(h, hostportOrIPPortCsv)
}

// Hop implements Proxy.
func (h *http1) Hop(via *core.WeakRef[Proxy], dryrun bool) error {
	if h.id == GlobalH1 {
		return errNop // global proxy exits as-is
	}

	if !dryrun {
		old := h.via.Swap(via)
		log.I("http1: hop %s => %s", refhandle(old), refhandle(via))
	}
	return nil
}

// Via implements x.Router.
func (h *http1) Via() (x.Proxy, error) {
	if ref := h.via.Load(); ref != nil {
		if v, ok := ref.Get(); ok && v != nil {
			return v, nil
		}
	}
	return nil, errNoHop
}

// GetAddr implements Proxy.
func (h *http1) GetAddr() string {
	if a := h.lastaddr.Load(); a != nil {
		return *a
	}
	return h.opts.IPPort
}

// Status implements Proxy.
func (h *http1) Status() int32 {
	s := h.status.Load()
	if s != END && idling(h.lastdial) {
		return TZZ
	}
	return s
}

// Pause implements x.Proxy.
func (h *http1) Pause() bool {
	st := h.status.Load()
	if st == END {
		log.W("proxy: http1: pause called when stopped")
		return false
	}

	ok := h.status.CompareAndSwap(st, TPU)
	log.I("proxy: http1: paused? %t", ok)
	return ok
}

// Resume implements x.Proxy.
func (h *http1) Resume() bool {
	st := h.status.Load()
	if st != TPU {
		log.W("proxy: http1: resume called when not paused; status %d", st)
		return false
	}

	ok := h.status.CompareAndSwap(st, TUP)
	go h.Refresh() // no-op since SkipRefresh
	log.I("proxy: http1: resumed? %t", ok)
	return ok
}

// Stop implements Proxy.
func (h *http1) Stop() error {
	h.status.Store(END)
	log.I("proxy: http1: stopped %s", h.id)
	return nil
}

// OnProtoChange implements Proxy.
func (h *http1) OnProtoChange(_ LinkProps) (string, bool) {
	if err := candial(&h.status); err != nil {
		return "", false
	}
	return h.opts.FullUrl(), true
}
