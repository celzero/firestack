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

var bar = core.NewKeyedBarrier[*x.NetStat, string](10 * time.Second)

var (
	errNoStatCache = errors.New("netstat: stat in cache is nil")
	errNoStat      = errors.New("netstat: no stat")
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
	tunmode  *settings.TunMode
	bridge   Bridge
	proxies  ipn.Proxies
	resolver dnsx.Resolver
	services rnet.Services
	closed   atomic.Bool
	once     sync.Once
}

func NewTunnel(fd, mtu int, fakedns string, tunmode *settings.TunMode, dtr DefaultDNS, bdg Bridge) (Tunnel, error) {
	defer core.Recover(core.Exit11, "i.newTunnel")

	if bdg == nil || dtr == nil {
		return nil, fmt.Errorf("tun: no bridge? %t or default-dns? %t", bdg == nil, dtr == nil)
	}

	log.SetConsole(bdg)
	natpt := x64.NewNatPt(tunmode)
	proxies := ipn.NewProxifier(bdg, bdg)
	services := rnet.NewServices(proxies, bdg, bdg)

	if proxies == nil || services == nil {
		return nil, fmt.Errorf("tun: no proxies? %t or services? %t", proxies == nil, services == nil)
	}

	if err := dtr.kickstart(proxies, bdg); err != nil {
		log.I("tun: <<< new >>>; kickstart err(%v)", err)
		return nil, err
	}

	resolver := dnsx.NewResolver(fakedns, tunmode, dtr, bdg, natpt)
	resolver.Add(newGoosTransport(bdg, proxies))     // os-resolver; fixed
	resolver.Add(newBlockAllTransport())             // fixed
	resolver.Add(newFixedTransport())                // fixed
	resolver.Add(newDNSCryptTransport(proxies, bdg)) // fixed
	resolver.Add(newMDNSTransport(settings.IP46))    // fixed

	addIPMapper(resolver, settings.IP46) // namespace aware os-resolver for pkg dialers

	tcph := NewTCPHandler(resolver, proxies, tunmode, bdg, bdg)
	udph := NewUDPHandler(resolver, proxies, tunmode, bdg, bdg)
	icmph := NewICMPHandler(resolver, proxies, tunmode, bdg)
	hdl := netstack.NewGConnHandler(tcph, udph, icmph)

	gt, revhdl, err := tunnel.NewGTunnel(fd, mtu, hdl)

	if err != nil {
		log.I("tun: <<< new >>>; err(%v)", err)
		return nil, err
	}

	proxies.Reverser(revhdl)

	t := &rtunnel{
		Tunnel:   gt,
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

		removeIPMapper()
		err0 := t.resolver.StopResolvers()
		err1 := t.proxies.StopProxies()
		n := t.services.StopServers()
		t.bridge = nil // "free" ref to the client
		log.I("tun: <<< disconnect >>>; err0(%v); err1(%v); svc(%d)", err0, err1, n)

		t.Tunnel.Disconnect()
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
				t.resolver.Add(newMDNSTransport(l3))
			}
		})
	}()
	return t.Tunnel.SetLink(fd, mtu) // route is always dual-stack
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
	v, _ := bar.Do("stat", func() (*x.NetStat, error) {
		return t.stat()
	})
	if v == nil {
		return nil, errNoStat
	} else if v.Err != nil {
		return nil, v.Err
	} else if v.Val == nil {
		return nil, errNoStatCache
	}

	return v.Val, nil
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
	out.RDNSIn.Transparency = settings.EndpointIndependentFiltering.Load()
	out.RDNSIn.Dialer4 = dialers.Use4()
	out.RDNSIn.Dialer6 = dialers.Use6()
	out.RDNSIn.DialerOpts = csv2ssv(settings.GetDialerOpts().String())
	out.RDNSIn.TunMode = csv2ssv(t.tunmode.String())

	var mm runtime.MemStats
	runtime.ReadMemStats(&mm)
	out.GOSt.Alloc = formatBytes(mm.Alloc)
	out.GOSt.TotalAlloc = formatBytes(mm.TotalAlloc)
	out.GOSt.Sys = formatBytes(mm.Sys)
	out.GOSt.Lookups = int64(mm.Lookups)
	out.GOSt.Mallocs = int64(mm.Mallocs)
	out.GOSt.Frees = int64(mm.Frees)
	out.GOSt.HeapAlloc = formatBytes(mm.HeapAlloc)
	out.GOSt.HeapSys = formatBytes(mm.HeapSys)
	out.GOSt.HeapIdle = formatBytes(mm.HeapIdle)
	out.GOSt.HeapInuse = formatBytes(mm.HeapInuse)
	out.GOSt.HeapReleased = formatBytes(mm.HeapReleased)
	out.GOSt.HeapObjects = int64(mm.HeapObjects)
	out.GOSt.StackInuse = formatBytes(mm.StackInuse)
	out.GOSt.StackSys = formatBytes(mm.StackSys)
	out.GOSt.MSpanInuse = formatBytes(mm.MSpanInuse)
	out.GOSt.MSpanSys = formatBytes(mm.MSpanSys)
	out.GOSt.MCacheInuse = formatBytes(mm.MCacheInuse)
	out.GOSt.MCacheSys = formatBytes(mm.MCacheSys)
	out.GOSt.BuckHashSys = formatBytes(mm.BuckHashSys)
	out.GOSt.GCSys = formatBytes(mm.GCSys)
	out.GOSt.OtherSys = formatBytes(mm.OtherSys)
	out.GOSt.NextGC = formatTime(mm.NextGC)
	out.GOSt.LastGC = formatTime(mm.LastGC)
	out.GOSt.PauseSecs = formatPeriod(mm.PauseTotalNs)
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

var units = []string{" b", "kb", "mb", "gb"}

// from: github.com/google/gops/blob/35c854fb84/agent/agent.go
func formatBytes(val uint64) string {
	var i int
	var target uint64
	for i = range units {
		target = 1 << uint(10*(i+1))
		if val < target {
			break
		}
	}
	if i > 0 {
		return fmt.Sprintf("%0.2f%s (%d bytes)",
			float64(val)/(float64(target)/1024), units[i], val)
	}
	return fmt.Sprintf("%d bytes", val)
}

func formatTime(ns uint64) string {
	return time.Now().Add(-time.Duration(ns)).Format(time.TimeOnly)
}

func formatPeriod(ns uint64) int64 {
	return int64(time.Duration(ns).Seconds() * 1000)
}
