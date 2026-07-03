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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	crt "github.com/celzero/firestack/intra/core/runtime"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/netstack"
	"github.com/celzero/firestack/intra/rnet"
	"github.com/celzero/firestack/intra/settings"

	"github.com/celzero/firestack/intra/log"
)

// pkg.go.dev/runtime#hdr-Environment_Variables
type traceout string

type Console x.Console
type Controller x.Controller
type ProxyListener x.ProxyListener
type DNSListener x.DNSListener
type ServerListener rnet.ServerListener

const (
	// none traceout = "none"   // 0; no stack trace
	one  traceout = "single" // offending go routine
	usr  traceout = "all"    // 1; all user go routines
	sys  traceout = "system" // 2; all user + system go routines
	abrt traceout = "crash"  // GOOS-specific crash after tracing
)

func (t traceout) s() string { return string(t) }

const minMemLimit = 32 * 1024 * 1024       // 32MiB
const maxMemLimit = 1 * 1024 * 1024 * 1024 // 1GiB

// onetime console setup
var csetup atomic.Bool

func init() {
	// increase garbage collection frequency: archive.is/WQBf7
	debug.SetGCPercent(50)
	debug.SetMemoryLimit(maxMemLimit / 2)
	debug.SetPanicOnFault(true)

	/*
		TODO: disable cgocheck at runtime: github.com/golang/go/issues/60426
		removes runtime pointer-validity checks on cgo calls;
		godebug := os.Getenv("GODEBUG")
		if !strings.Contains(godebug, "cgocheck") {
			if godebug == "" {
				godebug = "cgocheck=0"
			} else {
				godebug = godebug + ",cgocheck=0"
			}
			os.Setenv("GODEBUG", godebug)
			runtime.RuntimeFinishDebugVarsSetup()
		}
	*/
}

// SetupConsole wires up firestack's logger to bdg.
func SetupConsole(console Console) error {
	if !csetup.CompareAndSwap(false, true) {
		return errMakeTunnel
	}

	ctx := context.Background()
	logch := make(chan bool, 1)
	core.Gx("console.setup", func() {
		logfd, memfd := false, false
		var cons x.LogConsumer
		// memfd double-buffer (shared memory, zero kernel copy).
		if mc, merr := log.NewMemoryBased(); merr == nil {
			mfd1, mfd2 := mc.FDs()
			if cons = console.LogMemFD(mfd1, mfd2, mc.BufSize(), mc.SlotSize()); cons != nil {
				log.SetConsole(ctx, mc)
				mc.SetReader(log.MemReader(cons))
				context.AfterFunc(ctx, func() { core.Close(mc) })
				memfd = true
			} else {
				core.Close(mc)
			}
		}
		if !memfd {
			if r, c, err := log.NewFilebased(); err == nil {
				closeall := func() {
					core.Close(c)
					core.Close(r)
				}
				if logfd = console.LogFD(int(r.Fd())); logfd {
					log.SetConsole(ctx, c)
					context.AfterFunc(ctx, closeall)
					logfd = true
				} else {
					closeall()
				}
			}
		}
		if !logfd && !memfd {
			log.SetConsole(ctx, &clogAdapter{console})
		}
		log.D("tun: <<< console >>>; log out ok; memfd? %t / logfd? %t", memfd, logfd)
		logch <- memfd || logfd
		log.ConsoleReady(ctx)
	})

	fd := <-logch

	log.I("tun: <<< console >>>; logger: ok; logfd? %t", fd)
	return nil
}

// Connect creates firestack-administered tunnel.
// `fd` is the TUN device. The tunnel acquires an additional reference to it, which is
// released by Disconnect(), so the caller must close `fd` and Disconnect() to close the TUN device.
// `linkmtu` is the MTU of the underlying link (actual network). If <= 0, it is assumed to be same as `tunmtu`.
// `tunmtu` is the MTU of the TUN device. This can be "faked", ie set to values larger than linkmtu. Typically, its value is same as `linkmtu`.
// `ifaddrs` is a comma-separated list of interface addresses with prefix lengths, "ip/prefixlen".
// `fakedns` is a comman-separated list of the nameservers that the system believes it is using, in "host:port" style.
// `bdg` is a kotlin object that implements the Bridge interface.
// `dtr` is the DefaultDNS (see: intra.NewDefaultDNS); can be nil. Changeable via intra.AddDefaultTransport.
// Throws an exception if the TUN file descriptor cannot be opened, or if the tunnel fails to
// connect.
func Connect(fd, linkmtu, tunmtu int, ifaddrs, fakedns string, dtr DefaultDNS, bdg Bridge) (t Tunnel, err error) {
	if linkmtu <= 0 {
		NewTunnel(fd, tunmtu, ifaddrs, fakedns, dtr, bdg)
	}
	return NewTunnel2(fd, linkmtu, tunmtu, ifaddrs, fakedns, dtr, bdg)
}

// Connect2 is like Connect, but assumes defaults for linkmtu, ifaddrs, and fakedns
// as -1, ["10.111.222.1/24", "fd66:f83a:c650::0/120"], and ["10.111.222.3", "fd66:f83a:c650::3"]
// respectively.
func Connect2(fd, tunmtu int, dtr DefaultDNS, bdg Bridge) (t Tunnel, err error) {
	// usually, 10.111.222.0/24 / [fd66:f83a:c650::1]/120
	// github.com/celzero/rethink-app/blob/59aa0daae/app/src/main/java/com/celzero/bravedns/service/BraveVPNService.kt#L2813
	return Connect(fd, -1, tunmtu, "10.111.222.1/24,fd66:f83a:c650::1/120", "10.111.222.3,fd66:f83a:c650::3", nil, bdg)
}

// Connect3 is like Connect2, but does not require passing a Default DNS resolver.
// The tunnel will instead attempt to use the system DNS resolver (best effort).
func Connect3(fd, tunmtu int, bdg Bridge) (t Tunnel, err error) {
	return Connect2(fd, tunmtu, nil, bdg)
}

// ControlledRouter creates a [backend.Router] over a [backend.Internet] proxy (like [backend.Exit]),
// but one that uses custom Controller c. id and addrport are used only for
// diagnostics and logging, and could be left empty. Typical usage is to use
// Router.Reaches() to check if a host:port is reachable over this Controller c.
func ControlledRouter(c Controller, id, addrport string) x.Router {
	return ipn.NewExitProxyWithID(id, addrport, context.Background(), c).Router()
}

// Change log level to very verbose (0), verbose (1), debug (2), info (3), warn (4), error (5),
// stacktraces (6), user notifications (7), or no logs (8). gologLevel and consolelogLevel can
// be set independently; ex: LogLevel(2, 6) or LogLevel(8, 0) etc.
// callerDepth can be any value between 0 and 9 which controls how many stack frames to
// unwind for every log call. 9 is more expensive, 1 is more prudent.
func LogLevel(gologLevel, consolelogLevel, callerDepth int32) {
	dlvl := log.LevelOf(gologLevel)
	clvl := log.LevelOf(consolelogLevel)
	log.SetLevel(dlvl)
	log.SetConsoleLevel(clvl)
	log.SetCallerDepth(uint8(callerDepth))

	dbg := dlvl <= log.DEBUG || clvl <= log.DEBUG
	verbose := dlvl <= log.VERBOSE || clvl <= log.VERBOSE
	vverbose := dlvl <= log.VVERBOSE || clvl <= log.VVERBOSE
	settings.Debug = dbg

	var rec bool
	var recerr error
	if core.SupportsRecording() {
		if vverbose {
			rec, recerr = core.RecordForever(true)
		} else {
			rec, recerr = core.RecordForever(false)
		}
	}

	var nslvl string
	if verbose {
		nslvl = netstack.DebugLog(true)
	} else {
		nslvl = netstack.DebugLog(false)
	}

	// turn off runtime's internal "secure mode" to enable tracebacks
	prevsm := crt.SecureMode(false /*off*/)
	// traceback is always set to "crash" for c-shared / c-archive buildmodes
	// github.com/golang/go/blob/fed3b0a298/src/runtime/runtime1.go#L586
	// gomobile builds a c-shared gojnilib:
	// github.com/golang/mobile/blob/2553ed8ce2/cmd/gomobile/bind_androidapp.go#L393
	prevtraceback, _ := crt.GetRuntimeEnviron("GOTRACEBACK")
	newtraceback := sys.s()
	didSet, overwrote, _ := crt.SetRuntimeEnviron("GOTRACEBACK", newtraceback)
	curtraceback, _ := crt.GetRuntimeEnviron("GOTRACEBACK")

	gotraceenv := crt.RuntimeResetTracebackEnv()
	crt.RuntimeFinishDebugVarsSetup()
	debug.SetTraceback(newtraceback) // always call this after finishdbeugvars

	gotracelevel, gotraceall, gotracecrash := crt.RuntimeGotraceback()

	log.I("tun: new levels; nslog: %s, golog: %d, consolelog: %d; debug? %t, rec? %t, recerr? %v; traceback (%d): %s => %s => %s (l: %d / a? %t / c? %t) | set? %t / overwrote? %t; sm? %t; args: %v",
		nslvl, dlvl, clvl, dbg, rec, recerr, gotraceenv, prevtraceback, newtraceback, curtraceback, gotracelevel, gotraceall, gotracecrash, didSet, overwrote, prevsm, os.Args)
}

// LowMem triggers garbage collection cycle & allows for
// setting maximum memory limit, if limit > 0.
// github.com/golang/proposal/blob/master/design/48409-soft-memory-limit.md
func LowMem(limitBytes int64) {
	limitBytes = max(limitBytes, minMemLimit)
	prevLimit := debug.SetMemoryLimit(limitBytes)
	go debug.FreeOSMemory()
	log.I("tun: lowmem; limits => new: %d, prev: %d", limitBytes, prevLimit)
}

// Slowdown sets the TUN forwarder in single-threaded mode.
func Slowdown(y bool) {
	ok := settings.SingleThreaded.CompareAndSwap(!y, y)
	log.I("tun: slowdown? %t / ok? %t", y, ok)
}

// ExperimentalWireGuard enables/disables experimental features for WireGuard like allowing incoming packets.
func ExperimentalWireGuard(y bool) {
	// todo: move to its own method
	wgok := settings.ExperimentalWireGuard.CompareAndSwap(!y, y)
	// PortForwarding does not work on Android as-is.
	// fwdok := settings.PortForward.CompareAndSwap(!y, y)
	fwdok := false
	log.I("tun: experimental settings? %t / wg? %t, portfwd? %t", y, wgok, fwdok)
}

// FloodWireGuard enables/disables flooding WireGuard tunnels with randomly sized non-null packets.
func FloodWireGuard(y bool) {
	ok := settings.FloodWireGuard.CompareAndSwap(!y, y)
	log.I("tun: flood wireguard? %t / ok? %t", y, ok)
}

// Loopback informs the network stack that it must deal with packets
// originating from its own process routed back into the tunnel.
func Loopback(y bool) {
	ok := settings.Loopingback.CompareAndSwap(!y, y)
	log.I("tun: loopback? %t / ok? %t", y, ok)
}

// If set, use SystemDNS to resolve undelegated (.lan, .internal, .arpa etc) domains.
func UndelegatedDomains(useSystemDNS bool) {
	ok := settings.SystemDNSForUndelegatedDomains.CompareAndSwap(!useSystemDNS, useSystemDNS)
	log.I("tun: resolve undelegated with system DNS? %t / ok? %t", useSystemDNS, ok)
}

// DefaultDNSAsFallback allows using the Default transport as a fallback when
// the Preferred transport is missing or paused or ended.
func DefaultDNSAsFallback(y bool) {
	ok := settings.DefaultDNSAsFallback.CompareAndSwap(!y, y)
	log.I("tun: allow default DNS as fallback? %t / ok? %t", y, ok)
}

// Transparency enables/disables endpoint-independent mapping/filtering.
// Currently applies only for UDP (RFC 4787).
func Transparency(eim, eif bool) {
	settings.EndpointIndependentMapping.Store(eim)
	settings.EndpointIndependentFiltering.Store(eif)
	settings.SetUserAgent.Store(eim || eif)
	log.I("tun: eim? %t / eif? %t", eim, eif)
}

// Build returns the build information.
func Build(full bool) (v string) {
	if !full {
		v = core.Version()
	} else {
		v = core.BuildInfo()
	}
	log.V("tun: build version %s", v)
	return v
}

func GoMet() *x.GoMetrics {
	out := new(x.GoMetrics)
	out.M = core.Metrics()
	out.C = core.Snapshot()
	out.L = log.Metrics()

	var mm runtime.MemStats
	runtime.ReadMemStats(&mm) // stw & expensive
	out.G.Alloc = core.FmtBytes(mm.Alloc)
	out.G.TotalAlloc = core.FmtBytes(mm.TotalAlloc)
	out.G.Sys = core.FmtBytes(mm.Sys)
	out.G.Lookups = int64(mm.Lookups)
	out.G.Mallocs = int64(mm.Mallocs)
	out.G.Frees = int64(mm.Frees)
	out.G.HeapAlloc = core.FmtBytes(mm.HeapAlloc)
	out.G.HeapSys = core.FmtBytes(mm.HeapSys)
	out.G.HeapIdle = core.FmtBytes(mm.HeapIdle)
	out.G.HeapInuse = core.FmtBytes(mm.HeapInuse)
	out.G.HeapReleased = core.FmtBytes(mm.HeapReleased)
	out.G.HeapObjects = int64(mm.HeapObjects)
	out.G.StackInuse = core.FmtBytes(mm.StackInuse)
	out.G.StackSys = core.FmtBytes(mm.StackSys)
	out.G.MSpanInuse = core.FmtBytes(mm.MSpanInuse)
	out.G.MSpanSys = core.FmtBytes(mm.MSpanSys)
	out.G.MCacheInuse = core.FmtBytes(mm.MCacheInuse)
	out.G.MCacheSys = core.FmtBytes(mm.MCacheSys)
	out.G.BuckHashSys = core.FmtBytes(mm.BuckHashSys)
	out.G.GCSys = core.FmtBytes(mm.GCSys)
	out.G.OtherSys = core.FmtBytes(mm.OtherSys)
	out.G.NextGC = core.FmtTimeNs(mm.NextGC)
	out.G.LastGC = core.FmtTimeNs(mm.LastGC)
	out.G.PauseSecs = core.Nano2Sec(mm.PauseTotalNs)
	out.G.NumGC = int32(mm.NumGC)
	out.G.NumForcedGC = int32(mm.NumForcedGC)
	out.G.GCCPUFraction = fmt.Sprintf("%0.4f", mm.GCCPUFraction)
	out.G.EnableGC = mm.EnableGC
	out.G.DebugGC = mm.DebugGC

	out.G.NumGoroutine = int64(runtime.NumGoroutine())
	out.G.NumCgo = int64(runtime.NumCgoCall())
	out.G.NumCPU = int64(runtime.NumCPU())

	l, all, crash := crt.RuntimeGotraceback()
	out.G.Trac = fmt.Sprintf("%d; all? %t; crash? %t", l, all, crash)

	cachedir, _ := os.UserCacheDir()
	homedir, _ := os.UserHomeDir()
	cfgdir, _ := os.UserConfigDir()
	sm1, sm2 := crt.RuntimeSecureMode()
	uid := fmt.Sprintf("uid=%d", syscall.Getuid())
	pid := fmt.Sprintf("pid=%d", syscall.Getpid())
	pgsz := fmt.Sprintf("pgsz=%d", os.Getpagesize())
	sec := fmt.Sprintf("sec=%t/%t", sm1, sm2)
	out.G.Args = strings.Join(append(os.Args, uid, pid, pgsz, sec), ";")
	out.G.Env = strings.Join(crt.RuntimeEnviron(), ";") +
		" / " +
		strings.Join([]string{cachedir, homedir, cfgdir}, ";")
	out.G.Pers, _ = os.Executable()

	return out
}

// PrintStack logs the stack trace of all active goroutines
// to stdout if where is 0, to Console if 1; otherwise returns
// it as bytes. For testing only.
func PrintStack(where int32) []byte {
	bptr := core.LOB()
	b := *bptr
	b = b[:cap(b)]
	recycle := true
	defer func() {
		if recycle {
			*bptr = b
			core.Recycle(bptr)
		}
	}()
	switch where {
	case 0:
		log.TALL("tun: debug trace (not a crash)", b)
		return nil
	case 1:
		log.C("tun: debug trace (not a crash)", b)
		return nil
	}
	recycle = false
	return log.S(b)
}

// Crash causes a crash by panicking on an out-of-bounds slice access. For testing only.
// Setting typ to 0 must send the crash output to stderr and abort, and 1 to console and not quit,
// while 2 must send the crash output to console and abort.
// afterMs is the number of milliseconds to wait before crashing.
func Crash(typ, afterMs int64) {
	go func() {
		if typ > 0 {
			exitcode := core.DontExit
			if typ == 2 {
				exitcode = core.Exit11
			}
			defer core.Recover(exitcode, "tun: debugging... not a crash")
		}
		log.I("tun: debug: crashing in %s", core.FmtMillis(afterMs))
		time.Sleep(time.Duration(afterMs) * time.Millisecond)
		var i []int
		i[10] = 1 // panic: runtime error: index out of range [10] with length 10
	}()
}

// setCrashFd sets dup(f) as output file to write go runtime crashes in to.
func setCrashFd(f *os.File) (ok bool) {
	// f is dup()ed by debug.SetCrashOutput before use
	err := debug.SetCrashOutput(f, debug.CrashOptions{})
	logei(err)("tun: crashout: set %s, err? %v", fname(f), err)
	return err == nil
}

var panicfd *os.File

func setPanicFd(f *os.File) bool {
	panicfd = f // keepalive
	return log.StackOutput(f)
}

// SetCrashOutput sets the crash output file at fp1 and caught panics in fp2.
// Returns true if successful, false on error (the files cannot be opened).
func SetCrashOutput(fp1, fp2 string) bool {
	return sync.OnceValue(func() (ok bool) {
		fout1, err := os.OpenFile(filepath.Clean(fp1), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		fout2, err2 := os.OpenFile(filepath.Clean(fp2), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err == nil && err2 == nil {
			ok = setCrashFd(fout1) && setPanicFd(fout2)
		}
		logei(err)("tun: crashout: open: %s + %s; err? %v", fp1, fp2, err)
		return ok
	})()
}

// SetFlightRecordOutput opens a writable file (and keeps it open) for Go's flight recorder
// to write to (on panics, for example). The flight recorder must be enabled via FlightRecorder(true)
// for this to be functional. Returns previous file name, if any. May error if fp cannot be opened.
// More: go.dev/blog/flight-recorder
func SetFlightRecordOutput(fp string) (prev string, err error) {
	return core.SetFlightRecordOutput(fp)
}

// CPUProfile starts a program-wide CPU profiler for durationSecs seconds (clamped to [10, 120]).
// The CPU profile is written to outproffile, and the flight recorder trace to outflightrecorder.
// If the flight recorder is not already running, it is started on-demand and stopped after.
// Returns the actual number of seconds profiled. Only one profile (cpu or mem) can run at a time.
func CPUProfile(outproffile, outflightrecorder string, durationSecs int32) (ranSecs int32, err error) {
	return core.CPUProfile(outproffile, outflightrecorder, durationSecs)
}

// MemProfile triggers GC and writes a heap profile to outprofile.
// rate controls memory profiling granularity: 1 most detailed, 0 disables.
// Only one profile (cpu or mem) can run at a time.
func MemProfile(rate int32, outprofile string) error {
	return core.MemProfile(rate, outprofile)
}

func fname(f *os.File) string {
	if f == nil {
		return "<nil file>"
	}
	return f.Name()
}
