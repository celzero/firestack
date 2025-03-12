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
	via      *core.WeakRef[Proxy]
	viaID    *core.Volatile[string]
	px       ProxyProvider
	opts     *settings.ProxyOptions
	lastdial time.Time
	status   *core.Volatile[int]
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
		viaID:    core.NewZeroVolatile[string](),
		status:   core.NewVolatile(TUP),
		id:       id,
		opts:     po,
	}
	h.via, err = core.NewWeakRef(h.viafor, viaok)

	logeif(err != nil)("proxy: http1: created %s with opts(%s); err? %v",
		h.ID(), po, err)

	return h, nil
}

func (h *http1) viafor() *Proxy {
	return viafor(h.id, h.viaID.Load(), h.px)
}

func (h *http1) swapVia(new Proxy) Proxy {
	return swapVia(h.id, new, h.viaID, h.via)
}

// Handle implements Proxy.
func (h *http1) Handle() uintptr {
	return core.Loc(h)
}

// Dial implements Proxy.
func (h *http1) Dial(network, addr string) (c protect.Conn, err error) {
	if h.status.Load() == END {
		return nil, errProxyStopped
	}

	h.lastdial = time.Now()

	who := h.ID()
	if usevia(h.viaID) {
		if v, vok := h.via.Get(); vok { // dial via another proxy
			who = idstr(v)
			c, err = v.Dial(network, addr)
		} else {
			err = errNoHop
			if removeViaOnErrors {
				h.Hop(nil, false /*dryrun*/) // stale; unset
			}
			log.W("http1: via(%s@%s) failing...", idstr(v), idhandle(v))
		}
	} else {
		// actually, dialers.ProxyDial not needed, because
		// tx.HttpTunnel.Dial() supports dialing into hostnames
		c, err = dialers.ProxyDial(h.outbound, network, addr)
	}
	defer localDialStatus(h.status, err)

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
func (h *http1) Hop(p Proxy, dryrun bool) error {
	if h.id == GlobalH1 {
		return errNop // global proxy exits as-is
	}

	if p == nil {
		if !dryrun {
			old := h.swapVia(nil)
			log.I("proxy: http1: hop(%s@%s) removed", idstr(old), idhandle(old))
		}
		return nil
	}
	if p.Status() == END {
		return errProxyStopped
	}

	if !dryrun {
		old := h.swapVia(p)
		log.I("http1: hop(%s@%s) => %s@%s",
			idstr(old), idhandle(old), idstr(p), idhandle(p))
	}
	return nil
}

// Via implements x.Router.
func (h *http1) Via() (x.Proxy, error) {
	if v := h.via.Load(); v != nil {
		return v, nil
	}
	return nil, errNoHop
}

// GetAddr implements Proxy.
func (h *http1) GetAddr() string {
	return h.opts.IPPort
}

// Status implements Proxy.
func (h *http1) Status() int {
	s := h.status.Load()
	if s != END && idling(h.lastdial) {
		return TZZ
	}
	return s
}

// Stop implements Proxy.
func (h *http1) Stop() error {
	h.status.Store(END)
	log.I("proxy: http1: stopped %s", h.id)
	return nil
}

// OnProtoChange implements Proxy.
func (h *http1) OnProtoChange(_ LinkProps) (string, bool) {
	if h.status.Load() == END {
		return "", false
	}
	return h.opts.FullUrl(), true
}
