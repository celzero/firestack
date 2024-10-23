// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     Copyright 2019 The Outline Authors
//
//     Licensed under the Apache License, Version 2.0 (the "License");
//     you may not use this file except in compliance with the License.
//     You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
//     Unless required by applicable law or agreed to in writing, software
//     distributed under the License is distributed on an "AS IS" BASIS,
//     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//     See the License for the specific language governing permissions and
//     limitations under the License.

package intra

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/netstack"
	"github.com/celzero/firestack/intra/rnet"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/x64"
	"github.com/celzero/firestack/tunnel"
)

var bar = core.NewKeyedBarrier[*x.NetStat, string](30 * time.Second)

var (
	errNoStatCache = errors.New("netstat: stat in cache is nil")
	errClosed      = errors.New("tunnel closed for business")
)

type Bridge interface {
	Listener
	x.Controller
	Console
}

// Listener receives usage statistics when a UDP or TCP socket is closed,
// or a DNS query is completed.
type Listener interface {
	SocketListener
	x.DNSListener
	rnet.ServerListener
	x.ProxyListener
}

// Tunnel represents an Intra session.
type Tunnel interface {
	tunnel.Tunnel
	internalCtx() context.Context
	// Get the resolver.
	GetResolver() (x.DNSResolver, error)
	// Get the internal resolver.
	internalResolver() (dnsx.Resolver, error)
	// Get proxies.
	GetProxies() (x.Proxies, error)
	// Get the internal proxies.
	internalProxies() (ipn.Proxies, error)
	// A bridge to the client code.
	getBridge() Bridge
	// Sets new default routes for the given engine, where engine is
	// one of the constants (Ns4, Ns6, Ns46) defined in package settings.
	SetRoute(engine int) error
	// Sets pcap output to fpcap which is the absolute filepath
	// to which a PCAP file will be written to.
	// If len(fpcap) is 0, no PCAP file will be written.
	// If len(fpcap) is 1, PCAP be written to stdout.
	SetPcap(fpcap string) error
	// Set DNSMode, BlockMode, PtMode.
	SetTunMode(dnsmode, blockmode, ptmode int32)
}

type rtunnel struct {
	tunnel.Tunnel
	ctx      context.Context
	done     context.CancelFunc
	tunmode  *settings.TunMode
	bridge   Bridge
	proxies  ipn.Proxies
	resolver dnsx.Resolver
	services rnet.Services
	closed   atomic.Bool
	once     sync.Once
}

func NewTunnel(fd, mtu int, fakedns string, tunmode *settings.TunMode, dtr DefaultDNS, bdg Bridge) (t Tunnel, err error) {
	defer core.Recover(core.Exit11, "i.newTunnel")

	if bdg == nil || dtr == nil {
		return nil, fmt.Errorf("tun: no bridge? %t or default-dns? %t", bdg == nil, dtr == nil)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		if err != nil {
			cancel()
		}
	}()

	log.SetConsole(bdg)
	natpt := x64.NewNatPt(tunmode, bdg)
	proxies := ipn.NewProxifier(ctx, bdg, bdg)
	services := rnet.NewServices(ctx, proxies, bdg, bdg)

	if proxies == nil || services == nil {
		return nil, fmt.Errorf("tun: no proxies? %t or services? %t", proxies == nil, services == nil)
	}

	if err := dtr.kickstart(proxies, bdg); err != nil {
		log.I("tun: <<< new >>>; kickstart err(%v)", err)
		return nil, err
	}

	resolver := dnsx.NewResolver(ctx, fakedns, tunmode, dtr, bdg, natpt)
	resolver.Add(newGoosTransport(ctx, bdg, proxies))     // os-resolver; fixed
	resolver.Add(newBlockAllTransport())                  // fixed
	resolver.Add(newFixedTransport())                     // fixed
	resolver.Add(newDNSCryptTransport(ctx, proxies, bdg)) // fixed
	resolver.Add(newMDNSTransport(ctx, settings.IP46))    // fixed

	addIPMapper(ctx, resolver, settings.IP46) // namespace aware os-resolver for pkg dialers

	tcph := NewTCPHandler(ctx, resolver, proxies, tunmode, bdg)
	udph := NewUDPHandler(ctx, resolver, proxies, tunmode, bdg)
	icmph := NewICMPHandler(ctx, resolver, proxies, tunmode, bdg)
	hdl := netstack.NewGConnHandler(tcph, udph, icmph)

	gt, revhdl, err := tunnel.NewGTunnel(ctx, fd, mtu, hdl)

	if err != nil {
		log.I("tun: <<< new >>>; err(%v)", err)
		return nil, err
	}

	proxies.Reverser(revhdl)

	t = &rtunnel{
		Tunnel:   gt,
		ctx:      ctx,
		done:     cancel,
		tunmode:  tunmode,
		bridge:   bdg,
		proxies:  proxies,
		resolver: resolver,
		services: services,
	}

	log.I("tun: <<< new >>>; ok")
	return t, nil
}

func (t *rtunnel) getBridge() Bridge {
	return t.bridge // may return nil, esp after Disconnect()
}

func (t *rtunnel) Disconnect() {
	defer core.Recover(core.Exit11, "intra.Disconnect")

	if t.closed.Load() {
		log.I("tun: <<< disconnect >>> already closed")
		return
	}
	t.once.Do(func() {
		t.closed.Store(true)
		t.done()
		t.bridge = nil // "free" ref to the client
		log.I("tun: <<< disconnect >>>")
	})
}

func (t *rtunnel) SetRoute(engine int) error {
	if t.closed.Load() {
		log.W("tun: <<< set route >>>; already closed")
		return errClosed
	}

	return t.Tunnel.SetRoute(engine)
}

func (t *rtunnel) SetLinkAndRoutes(fd, mtu, engine int) error {
	if t.closed.Load() {
		log.W("tun: <<< set link and route >>>; already closed")
		return errClosed
	}

	defer func() {
		core.Gx("i.setLinkAndRoutes", func() {
			l3 := settings.L3(engine)
			if diff := dialers.IPProtos(l3); diff {
				// dialers.IPProtos must always preced calls to other refreshes
				// as it carries the global state for dialers and ipn/multihost
				go t.proxies.RefreshProto(l3)
				t.resolver.Add(newMDNSTransport(t.ctx, l3))
			}
		})
	}()
	return t.Tunnel.SetLink(fd, mtu) // route is always dual-stack
}

func (t *rtunnel) internalCtx() context.Context {
	return t.ctx
}

func (t *rtunnel) GetResolver() (x.DNSResolver, error) {
	return t.internalResolver()
}

func (t *rtunnel) internalResolver() (dnsx.Resolver, error) {
	ko := t.closed.Load()
	if ko || t.resolver == nil {
		log.W("tun: <<< get internal resolver >>>; already closed? %t / %t", ko, t.resolver == nil)
		return nil, errClosed
	}

	return t.resolver, nil
}

func (t *rtunnel) GetProxies() (x.Proxies, error) {
	return t.internalProxies()
}

func (t *rtunnel) internalProxies() (ipn.Proxies, error) {
	ko := t.closed.Load()
	if ko || t.proxies == nil {
		log.W("tun: <<< get internal proxies >>>; already closed; %t / %t", ko, t.proxies == nil)
		return nil, errClosed
	}

	return t.proxies, nil
}

func (t *rtunnel) GetServices() (rnet.Services, error) {
	ko := t.closed.Load()

	if ko || t.proxies == nil {
		log.W("tun: <<< get svc >>>; already closed; %t / %t", ko, t.services == nil)
		return nil, errClosed
	}

	return t.services, nil
}

func (t *rtunnel) SetTunMode(dnsmode, blockmode, ptmode int32) {
	t.tunmode.SetMode(dnsmode, blockmode, ptmode)
}

func (t *rtunnel) Stat() (*x.NetStat, error) {
	v, err := bar.DoIt("stat", func() (*x.NetStat, error) {
		return t.stat()
	})

	if err != nil {
		return nil, err
	} else if v == nil {
		return nil, errNoStatCache
	}

	return v, nil
}

func (t *rtunnel) stat() (*x.NetStat, error) {
	out, err := t.Tunnel.Stat()

	if err != nil {
		return nil, err
	}
	// rdns info
	out.RDNSIn.Open = !t.closed.Load()
	out.RDNSIn.Debug = settings.Debug
	out.RDNSIn.Looping = settings.Loopingback.Load()
	out.RDNSIn.Slowdown = settings.SingleThreaded.Load()
	out.RDNSIn.NewWireGuard = settings.ExperimentalWireGuard.Load()
	out.RDNSIn.Transparency = settings.EndpointIndependentFiltering.Load()
	out.RDNSIn.Dialer4 = dialers.Use4()
	out.RDNSIn.Dialer6 = dialers.Use6()
	out.RDNSIn.DialerOpts = csv2ssv(settings.GetDialerOpts().String())
	out.RDNSIn.TunMode = csv2ssv(t.tunmode.String())

	var mm runtime.MemStats
	runtime.ReadMemStats(&mm) // stw & expensive
	out.GOSt.Alloc = core.FmtBytes(mm.Alloc)
	out.GOSt.TotalAlloc = core.FmtBytes(mm.TotalAlloc)
	out.GOSt.Sys = core.FmtBytes(mm.Sys)
	out.GOSt.Lookups = int64(mm.Lookups)
	out.GOSt.Mallocs = int64(mm.Mallocs)
	out.GOSt.Frees = int64(mm.Frees)
	out.GOSt.HeapAlloc = core.FmtBytes(mm.HeapAlloc)
	out.GOSt.HeapSys = core.FmtBytes(mm.HeapSys)
	out.GOSt.HeapIdle = core.FmtBytes(mm.HeapIdle)
	out.GOSt.HeapInuse = core.FmtBytes(mm.HeapInuse)
	out.GOSt.HeapReleased = core.FmtBytes(mm.HeapReleased)
	out.GOSt.HeapObjects = int64(mm.HeapObjects)
	out.GOSt.StackInuse = core.FmtBytes(mm.StackInuse)
	out.GOSt.StackSys = core.FmtBytes(mm.StackSys)
	out.GOSt.MSpanInuse = core.FmtBytes(mm.MSpanInuse)
	out.GOSt.MSpanSys = core.FmtBytes(mm.MSpanSys)
	out.GOSt.MCacheInuse = core.FmtBytes(mm.MCacheInuse)
	out.GOSt.MCacheSys = core.FmtBytes(mm.MCacheSys)
	out.GOSt.BuckHashSys = core.FmtBytes(mm.BuckHashSys)
	out.GOSt.GCSys = core.FmtBytes(mm.GCSys)
	out.GOSt.OtherSys = core.FmtBytes(mm.OtherSys)
	out.GOSt.NextGC = core.FmtTimeNs(mm.NextGC)
	out.GOSt.LastGC = core.FmtTimeNs(mm.LastGC)
	out.GOSt.PauseSecs = core.FmtTimeSecs(mm.PauseTotalNs)
	out.GOSt.NumGC = int32(mm.NumGC)
	out.GOSt.NumForcedGC = int32(mm.NumForcedGC)
	out.GOSt.GCCPUFraction = fmt.Sprintf("%0.4f", mm.GCCPUFraction)
	out.GOSt.EnableGC = mm.EnableGC
	out.GOSt.DebugGC = mm.DebugGC

	out.GOSt.NumGoroutine = int64(runtime.NumGoroutine())
	out.GOSt.NumCgo = int64(runtime.NumCgoCall())
	out.GOSt.NumCPU = int64(runtime.NumCPU())

	if r := t.resolver; r != nil {
		out.RDNSIn.DNSPreferred = fetchaddr(r, x.Preferred)
		out.RDNSIn.DNSDefault = fetchaddr(r, x.Default)
		out.RDNSIn.DNSSystem = fetchaddr(r, x.System)
		out.RDNSIn.DNS = csv2ssv(r.LiveTransports())
	}
	if p := t.proxies; p != nil {
		out.RDNSIn.Proxies = csv2ssv(p.LiveProxies())
		out.RDNSIn.ProxiesHas4 = p.Router().IP4()
		out.RDNSIn.ProxiesHas6 = p.Router().IP6()
		if ps := p.Router().Stat(); ps != nil {
			out.RDNSIn.ProxyLastOKMs = ps.LastOK
			out.RDNSIn.ProxySinceMs = ps.Since
		}
	}
	return out, nil
}

func csv2ssv(csv string) string {
	return strings.ReplaceAll(csv, ",", ";")
}

func fetchaddr(r dnsx.Resolver, id string) string {
	if tr, rerr := r.Get(id); rerr == nil {
		return tr.GetAddr()
	} else {
		return rerr.Error()
	}
}
