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
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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

const mktunTimeout = 8 * time.Second

var bar = core.NewKeyedBarrier[*x.NetStat, string](30 * time.Second)

var (
	errNoStatCache = errors.New("netstat: stat in cache is nil")
	errClosed      = errors.New("tunnel closed for business")
	errMakeTunnel  = errors.New("could not make tunnel")
)

type Bridge interface {
	Listener
	Controller
	Console
}

// Listener receives usage statistics when a UDP or TCP socket is closed,
// or a DNS query is completed.
type Listener interface {
	SocketListener
	DNSListener
	ServerListener
	ProxyListener
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
	// Get local services.
	GetServices() (x.Services, error)

	// SetLinkAndRoutes sets the tun fd as link with mtu & engine as routes for the tunnel.
	// where engine is one of the constants (Ns4, Ns6, Ns46) defined in package settings.
	SetLinkAndRoutes(fd, mtu, engine int) error
	// SetLinkAndRoutes2 is like SetLinkAndRoutes except it runs the tunnel with tunmtu
	// & proxies with linkmtu. tunmtu may be a "fake" MTU (assigned to the TUN device) and
	// can be quite large, while linkmtu must be the actual MTU of the underlying network
	// or min of MTUs of all available underlying networks.
	SetLinkAndRoutes2(fd, tunmtu, linkmtu, engine int) error
	// SetLinkMtu sets the link MTU (which must the MTU matching the underlying network or
	// min of MTUs of all available underlying networks). Link MTU is different from
	// tun MTU which must match the TUN device's MTU. Link MTU is used as a hint by
	// some Proxy implementations (eg. WireGuard).
	SetLinkMtu(linkmtu int) (didchange bool)
	// Restart restarts the tunnel with the given fd, linkmtu & tunmtu, and engine.
	// fd is the TUN device file descriptor.
	// linkmtu is the MTU of the underlying network, tunmtu is the MTU of the TUN device.
	// linkmtu can be different from tunmtu. If linkmtu <= 0, it is assumed to be same as tunmtu.
	// engine is one of the constants (Ns4, Ns6, Ns46) defined in package settings.
	Restart(fd, linkmtu, tunmtu, engine int) error

	// Close connections by pid, cid, uid.
	CloseConns(activecsv string) (closedcsv string)

	// Sets pcap output to fpcap which is the absolute filepath
	// to which a PCAP file will be written to.
	// If len(fpcap) is 0, no PCAP file will be written.
	// If len(fpcap) is 1, PCAP be written to stdout.
	SetPcap(fpcap string) error
	// NIC, IP, TCP, UDP, and ICMP stats.
	Stat() (*x.NetStat, error)
}

type rtunnel struct {
	t        *core.Volatile[tunnel.Tunnel]
	ctx      context.Context
	done     context.CancelFunc
	handlers netstack.GConnHandler
	proxies  ipn.Proxies
	resolver dnsx.Resolver
	services rnet.Services
	linkmtu  *core.Volatile[int]
	closed   atomic.Bool
	once     sync.Once
}

var _ Tunnel = (*rtunnel)(nil)

type clogAdapter struct {
	b Bridge
}

var _ log.Console = (*clogAdapter)(nil)

func (l *clogAdapter) Log(lvl log.LogLevel, msg log.Logmsg) {
	if bdg := l.b; bdg != nil {
		bdg.Log(int32(lvl), x.StrOf(msg)) // adopt the log message
	}
}

func NewTunnel(fd, tunmtu int, ifaddrs, fakedns string, dtr DefaultDNS, bdg Bridge) (t Tunnel, err error) {
	return NewTunnel2(fd, tunmtu, tunmtu, ifaddrs, fakedns, dtr, bdg)
}

func NewTunnel2(fd, linkmtu, tunmtu int, ifaddrs, fakedns string, dtr DefaultDNS, bdg Bridge) (t Tunnel, err error) {
	defer core.Recover(core.Exit11, "i.newTunnel")

	if dtr == nil || core.IsNil(dtr) {
		dtr, err = NewBuiltinDefaultDNS()
		log.D("tun: using builtin default dns; err? %v", err)
		err = nil // used only for logging
	}

	if bdg == nil || dtr == nil {
		return nil, fmt.Errorf("tun: no bridge? %t or default-dns? %t", bdg == nil, dtr == nil)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		if err != nil {
			cancel()
		}
	}()

	countdown := make(chan struct{})
	defer close(countdown)

	ontimeout := func() {
		log.E("tun: <<< new >>>; timed out ...")
		cancel()
	}

	go core.EitherOr(countdown, ontimeout, mktunTimeout)

	const dualstack = settings.IP46

	logfd := false
	if r, c, err := log.NewFilebased(); err == nil {
		closeall := func() {
			core.Close(c)
			core.Close(r)
		}
		if logfd = bdg.LogFD(int(r.Fd())); logfd {
			log.SetConsole(ctx, c)
			context.AfterFunc(ctx, closeall)
		} else {
			closeall()
		}
	}
	if !logfd {
		log.SetConsole(ctx, &clogAdapter{bdg})
	}

	crashfd := pipeCrashOutput(bdg)

	natpt := x64.NewNatPt2(ctx)
	proxies := ipn.NewProxifier(ctx, dualstack, linkmtu, bdg, bdg)
	services := rnet.NewServices(ctx, proxies, bdg, bdg)

	if proxies == nil || services == nil {
		return nil, fmt.Errorf("tun: no proxies? %t or services? %t",
			proxies == nil, services == nil)
	}

	if err := dtr.kickstart(proxies); err != nil {
		log.W("tun: <<< new >>>; kickstart err(%v)", err)
		return nil, err
	}

	log.D("tun: <<< new >>>; proxies, svcs, bootstrap: ok; fds (log? %t / crash? %t)", logfd, crashfd)

	resolver := dnsx.NewResolver(ctx, fakedns, dtr, bdg, natpt)
	resolver.Add(newGoosTransport(ctx, proxies))            // os-resolver; fixed
	resolver.Add(newBlockAllTransport())                    // fixed
	resolver.Add(newFixedTransport())                       // fixed
	resolver.Add(newPlusTransport(ctx, resolver))           // fixed
	resolver.Add(newDNSCryptTransport(ctx, proxies, bdg))   // fixed
	resolver.Add(newMDNSTransport(ctx, dualstack, proxies)) // fixed

	log.D("tun: <<< new >>>; resolvers: ok")

	dialers.IPProtos(dualstack)           // assume dual-stack
	addIPMapper(ctx, resolver, dualstack) // namespace aware os-resolver for pkg dialers

	var src []netip.Prefix
	for s := range strings.SplitSeq(ifaddrs, ",") {
		if p, err := netip.ParsePrefix(s); p.IsValid() && err == nil {
			src = append(src, p)
		} else {
			log.W("tun: <<< new >>>; invalid ifaddr %s; err? %v", s, err)
		}
	}

	// usually, 10.111.222.0/24 / [fd66:f83a:c650::0]/120
	// github.com/celzero/rethink-app/blob/59aa0daae/app/src/main/java/com/celzero/bravedns/service/BraveVPNService.kt#L2813
	if len(src) <= 0 { // default
		src = []netip.Prefix{netip.MustParsePrefix("10.111.222.1/24"), netip.MustParsePrefix("fd66:f83a:c650::1/120")}
	}

	tcph := NewTCPHandler(ctx, resolver, proxies, bdg)
	udph := NewUDPHandler(ctx, resolver, proxies, bdg)
	icmph := NewICMPHandler(ctx, resolver, proxies, bdg)
	hdl := netstack.NewGConnHandler(src, tcph, udph, icmph)

	log.D("tun: <<< new >>>; protocol handlers: ok")

	gt, revhdl, err := tunnel.NewGTunnel(ctx, fd, tunmtu, dualstack, hdl)

	if gt == nil || err != nil {
		log.W("tun: <<< new >>>; err(%v)", err)
		return nil, core.OneErr(err, errMakeTunnel)
	}

	log.D("tun: <<< new >>>; netstack: ok")

	// TODO: err on reverser errors too?
	rerr := proxies.Reverser(revhdl)

	t = &rtunnel{
		t:        core.NewVolatile[tunnel.Tunnel](gt),
		ctx:      ctx,
		done:     cancel,
		handlers: hdl,
		proxies:  proxies,
		resolver: resolver,
		services: services,
		linkmtu:  core.NewVolatile(linkmtu),
	}

	log.I("tun: <<< new >>>; tunnel ok; reverser? %v", rerr)
	return t, nil
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
		log.I("tun: <<< disconnect >>>")
	})
}

func (t *rtunnel) SetLinkMtu(linkmtu int) (didchange bool) {
	prev := t.linkmtu.Swap(linkmtu)
	mtudiff := prev != linkmtu
	logiif(mtudiff)("tun: set link mtu; set(%d) <= prev(%d); refresh protos? %t", linkmtu, prev, mtudiff)
	if mtudiff {
		core.Gx("i.setLinkMtuRefresh", func() {
			t.proxies.RefreshProto("" /*use existing*/, linkmtu, false /*force*/)
		})
	}
	return mtudiff
}

func (t *rtunnel) SetLinkAndRoutes(fd, tunmtu, engine int) error {
	return t.SetLinkAndRoutes2(fd, tunmtu, tunmtu, engine)
}

func (t *rtunnel) SetLinkAndRoutes2(fd, tunmtu, linkmtu, engine int) error {
	if t.closed.Load() {
		log.W("tun: <<< set link and route >>>; already closed")
		return errClosed
	}

	tunnel := t.t.Load()

	mtudiff := t.linkmtu.Swap(linkmtu) != linkmtu
	l3 := settings.L3(engine)
	l3diff := dialers.IPProtos(l3)

	err := tunnel.SetLinkAndRoutes(fd, tunmtu, engine) // route is always dual-stack

	if l3diff {
		if mdns, err := t.resolver.MDNS(); err == nil {
			mdns.RefreshProto(l3)
		}
	}

	if l3diff || mtudiff {
		// TODO: skip refresh on err?
		core.Gx("i.setLinkAndRoutesRefresh", func() {
			// dialers.IPProtos must always precede calls to other refreshes
			// as it carries the global state for dialers and ipn/multihost
			t.proxies.RefreshProto(l3, linkmtu, false /*force*/)
		})
	}

	return err
}

func (t *rtunnel) Restart(fd, linkmtu, tunmtu, engine int) error {
	if t.closed.Load() {
		log.W("tun: <<< restart >>>; for: %d, intra closed", fd)
		return errClosed
	}

	if linkmtu <= 0 {
		linkmtu = tunmtu
	}

	countdown := make(chan struct{})
	defer close(countdown)

	ontimeout := func() {
		log.E("tun: <<< restart >>>; for: %d, timed out ...", fd)
		t.done()
	}

	go core.EitherOr(countdown, ontimeout, mktunTimeout)

	dualstack := settings.IP46
	l3 := settings.L3(engine)
	l3diff := dialers.IPProtos(l3)

	old := t.t.Load()
	old.Disconnect() // could have been disconnected by the client already

	gt, revhdl, err := tunnel.NewGTunnel(t.ctx, fd, tunmtu, dualstack, t.handlers)

	if err != nil || gt == nil || core.IsNil(gt) {
		log.W("tun: <<< restart >>>; for: %d, new? %t / mtu? %d; err(%v)", fd, tunmtu, gt != nil, err)
		return core.OneErr(err, errMakeTunnel)
	}

	// TODO: CompareAndSwap
	if !t.t.Cas(old, gt) { // gt never nil
		gt.Disconnect() // close the new tunnel
		log.W("tun: <<< restart >>>; for: %d (mtu: %d), cas failed; old %X, new %X", fd, tunmtu, old, gt)
	}

	// TODO: err on reverser errors too?
	rerr := t.proxies.Reverser(revhdl)

	log.I("tun: <<< restart >>>; for: %d (linkmtu: %d / tunmtu: %d), netstack ok; rev err? %v", fd, linkmtu, tunmtu, rerr)

	if l3diff {
		if mdns, err := t.resolver.MDNS(); err == nil {
			mdns.RefreshProto(l3)
		}
	}
	core.Gx("i.RestartRefresh", func() {
		// Refresh proxies to update to the new reverser
		t.proxies.RefreshProto(l3, linkmtu, true /*force; reverser changed*/) // also updates reverser
	})

	return err
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

func (t *rtunnel) GetServices() (x.Services, error) {
	ko := t.closed.Load()

	if ko || t.proxies == nil {
		log.W("tun: <<< get svc >>>; already closed; %t / %t", ko, t.services == nil)
		return nil, errClosed
	}

	return t.services, nil
}

func (t *rtunnel) Stat() (*x.NetStat, error) {
	if settings.Debug {
		// if debugging, bypass the barrier
		return t.stat()
	}

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
	tunnel := t.t.Load()

	// NICInfo, NICStat, IPStat, IPFwdStat, TCPStat, UDPStat, ICMPStat, TUNStat
	out, err := tunnel.Stat()

	if err != nil {
		return nil, err
	}
	// rdns info
	out.RDNSIn.Open = !t.closed.Load()
	out.RDNSIn.Debug = settings.Debug
	out.RDNSIn.Recording = core.Recording()
	out.RDNSIn.Looping = settings.Loopingback.Load()
	out.RDNSIn.Slowdown = settings.SingleThreaded.Load()
	out.RDNSIn.NewWireGuard = boolstr(settings.ExperimentalWireGuard.Load(), settings.FloodWireGuard.Load())
	out.RDNSIn.HappyEyeballs = settings.HappyEyeballs.Load()
	out.RDNSIn.EIMEIF = boolstr(settings.EndpointIndependentMapping.Load(), settings.EndpointIndependentFiltering.Load())
	out.RDNSIn.OwnTunFd = settings.OwnTunFd.Load()
	out.RDNSIn.PortForward = settings.PortForward.Load()
	out.RDNSIn.Transparency = settings.EndpointIndependentFiltering.Load()
	out.RDNSIn.PanicTest = settings.PanicAtRandom.Load()
	out.RDNSIn.FatalTest = settings.FatalAtRandom.Load()
	out.RDNSIn.SetUserAgent = settings.SetUserAgent.Load()
	out.RDNSIn.SystemDNSForUndelegated = settings.SystemDNSForUndelegatedDomains.Load()
	out.RDNSIn.DefaultDNSAsFallback = settings.DefaultDNSAsFallback.Load()
	out.RDNSIn.Dialer4 = dialers.Use4()
	out.RDNSIn.Dialer6 = dialers.Use6()
	out.RDNSIn.DialerOpts = csv2ssv(settings.GetDialerOpts().String())
	out.RDNSIn.AutoMode = settings.AutoModeStr()
	out.RDNSIn.AutoDialsParallel = settings.AutoDialsParallel.Load()
	out.RDNSIn.LinkMTU = core.FmtBytes(uint64(t.linkmtu.Load()))

	firewall := settings.Mode2String("block", settings.BlockMode.Load())
	dns := settings.Mode2String("dns", settings.DNSMode.Load())
	pt := settings.Mode2String("pt", settings.PtMode.Load())
	out.RDNSIn.TunMode = fmt.Sprintf("%s;%s;%s", firewall, dns, pt)

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
	out.GOSt.PauseSecs = core.Nano2Sec(mm.PauseTotalNs)
	out.GOSt.NumGC = int32(mm.NumGC)
	out.GOSt.NumForcedGC = int32(mm.NumForcedGC)
	out.GOSt.GCCPUFraction = fmt.Sprintf("%0.4f", mm.GCCPUFraction)
	out.GOSt.EnableGC = mm.EnableGC
	out.GOSt.DebugGC = mm.DebugGC

	out.GOSt.NumGoroutine = int64(runtime.NumGoroutine())
	out.GOSt.NumCgo = int64(runtime.NumCgoCall())
	out.GOSt.NumCPU = int64(runtime.NumCPU())

	l, all, crash := core.RuntimeGotraceback()
	out.GOSt.Trac = fmt.Sprintf("%d; all? %t; crash? %t", l, all, crash)

	sm1, sm2 := core.RuntimeSecureMode()
	uid := fmt.Sprintf("uid=%d", syscall.Getuid())
	pid := fmt.Sprintf("pid=%d", syscall.Getpid())
	sec := fmt.Sprintf("sec=%t/%t", sm1, sm2)
	out.GOSt.Args = strings.Join(append(os.Args, uid, pid, sec), ";")
	out.GOSt.Env = strings.Join(core.RuntimeEnviron(), ";")
	out.GOSt.Pers, _ = os.Executable()

	if r := t.resolver; r != nil {
		out.RDNSIn.DNSPreferred = fetchDNSInfo(r, x.Preferred)
		out.RDNSIn.DNSDefault = fetchDNSInfo(r, x.Default)
		out.RDNSIn.DNSSystem = fetchDNSInfo(r, x.System)
		dns := make([]string, 0, 3)
		if csv := r.LiveTransports().V(); len(csv) > 0 {
			for tr := range strings.SplitSeq(csv, ",") {
				dns = append(dns, fetchDNSInfo(r, tr))
			}
		}
		out.RDNSIn.DNS = strconv.Itoa(len(dns)) + "\n" + strings.Join(dns, ";")
		out.RDNSIn.ALG = t.resolver.S()
	}
	if p := t.proxies; p != nil {
		rr := p.Router()
		ss := rr.Stat()
		out.RDNSIn.Proxies = csv2ssv(p.LiveProxies())
		out.RDNSIn.ProxiesHas4 = rr.IP4()
		out.RDNSIn.ProxiesHas6 = rr.IP6()
		if ss.LastOK > 0 {
			out.RDNSIn.ProxyLastOK = core.FmtUnixMillisAsPeriod(ss.LastOK)
		} else {
			out.RDNSIn.ProxyLastOK = "unknown"
		}
		if ss.Since > 0 {
			out.RDNSIn.ProxySince = core.FmtUnixMillisAsPeriod(ss.Since)
		} else {
			out.RDNSIn.ProxySince = "down"
		}
		out.RDNSIn.ProxyStatus = ss.Status
	}
	return out, nil
}

// CloseConns implements Tunnel.
func (t *rtunnel) CloseConns(activecsv string) (closedcsv string) {
	defer core.Recover(core.Exit11, "i.CloseConns")

	return t.handlers.CloseConns(activecsv)
}

// Enabled implements Tunnel.
func (t *rtunnel) Enabled() bool {
	tunnel := t.t.Load()
	return tunnel.Enabled()
}

// IsConnected implements Tunnel.
func (t *rtunnel) IsConnected() bool {
	tunnel := t.t.Load()
	return tunnel.IsConnected()
}

// Mtu implements Tunnel.
func (t *rtunnel) Mtu() int32 {
	tunnel := t.t.Load()
	return tunnel.Mtu()
}

// SetPcap implements Tunnel.
func (t *rtunnel) SetPcap(fpcap string) error {
	tunnel := t.t.Load()
	return tunnel.SetPcap(fpcap)
}

// Unlink implements Tunnel.
func (t *rtunnel) Unlink() error {
	tunnel := t.t.Load()
	return tunnel.Unlink()
}

func boolstr(b ...bool) string {
	var sb strings.Builder
	for i, v := range b {
		if i > 0 {
			sb.WriteString("; ")
		}
		if v {
			sb.WriteString("y")
		} else {
			sb.WriteString("n")
		}
	}
	return sb.String()
}
