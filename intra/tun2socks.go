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
	"os"
	"path/filepath"
	"runtime/debug"
	"sync/atomic"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/ipn"
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
	one  traceout = "single" // offending go routine
	usr  traceout = "all"    // all user go routines
	sys  traceout = "system" // all user + system go routines
	abrt traceout = "crash"  // GOOS-specific crash after tracing
)

func (t traceout) s() string { return string(t) }

const minMemLimit = 512 * 1024 * 1024      // 512MiB
const maxMemLimit = 4 * 1024 * 1024 * 1024 // 4GiB

// onetime console setup
var csetup atomic.Bool

func init() {
	// increase garbage collection frequency: archive.is/WQBf7
	debug.SetGCPercent(50)
	debug.SetMemoryLimit(maxMemLimit)
	debug.SetPanicOnFault(true)
}

// SetupConsole wires up firestack's logger to bdg.
func SetupConsole(console Console) error {
	if !csetup.CompareAndSwap(false, true) {
		return errMakeTunnel
	}

	ctx := context.Background()
	logch := make(chan bool, 1)
	go func() {
		logfd, memfd := false, false
		var cons x.LogConsumer
		// memfd double-buffer (shared memory, zero kernel copy).
		if mc, merr := log.NewMemoryBased(); merr == nil {
			mfd1, mfd2 := mc.FDs()
			if cons = console.LogMemFD(mfd1, mfd2, mc.BufSize()); cons != nil {
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
	}()

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
func LogLevel(gologLevel, consolelogLevel int32) {
	dlvl := log.LevelOf(gologLevel)
	clvl := log.LevelOf(consolelogLevel)
	log.SetLevel(dlvl)
	log.SetConsoleLevel(clvl)

	dbg := dlvl <= log.DEBUG || clvl <= log.DEBUG
	verbose := dlvl <= log.VERBOSE || clvl <= log.VERBOSE
	settings.Debug = dbg

	// turn off runtime's internal "secure mode" to enable tracebacks
	prevsm := core.SecureMode(false /*off*/)
	// traceback is always set to "crash" for c-shared / c-archive buildmodes
	// github.com/golang/go/blob/fed3b0a298/src/runtime/runtime1.go#L586
	// gomobile builds a c-shared gojnilib:
	// github.com/golang/mobile/blob/2553ed8ce2/cmd/gomobile/bind_androidapp.go#L393
	prevtraceback, _ := core.GetRuntimeEnviron("GOTRACEBACK")
	newtraceback := one.s()
	if verbose {
		newtraceback = sys.s()
	} else if dbg {
		newtraceback = usr.s()
	}
	core.SetRuntimeEnviron("GOTRACEBACK", newtraceback)
	debug.SetTraceback(newtraceback)
	curtraceback, _ := core.GetRuntimeEnviron("GOTRACEBACK")

	core.RuntimeFinishDebugVarsSetup()

	gotracelevel, gotraceall, gotracecrash := core.RuntimeGotraceback()

	log.I("tun: new levels; golog: %d, consolelog: %d; debug? %t; traceback: %s => %s => %s (l: %d / a? %t / c? %t); sm? %t",
		dlvl, clvl, dbg, prevtraceback, newtraceback, curtraceback, gotracelevel, gotraceall, gotracecrash, prevsm)
}

// FlightRecorder starts Go runtime's flight recorder if y is true,
// and stops it if y is false. The contents of the flight recorder
// (limited to 15s) is written to log.Console on panics. Thread-safe.
// go.dev/blog/flight-recorder
func FlightRecorder(y bool) (bool, error) {
	return core.Record(y)
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
	return b
}

// PrintFlightRecord dumps the contents of the flight recorder
// to Console if get is false, or returns the dumped bytes.
// For testing only. Thread-safe.
func PrintFlightRecord(get bool) []byte {
	if got, b := core.DumpRecorder(!get /* onConsole */); get && got {
		return b.Bytes()
	}
	return nil
}

// PanicAtRandom instructs portions under test to panic at random.
// For testing only.
func PanicAtRandom(y bool) {
	settings.PanicAtRandom.Store(y)
	log.I("tun: panic at random? %t", y)
}

// Crash causes a crash by panicking on an out-of-bounds slice access. For testing only.
func Crash(afterMs int64) {
	go func() {
		log.I("tun: crashing in %s", core.FmtMillis(afterMs))
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

// SetCrashOutput set crash output to file at fp; returns true if so.
// Disables crash output if fp cannot be opened; and returns false.
func SetCrashOutput(fp string) bool {
	fout, err := os.OpenFile(filepath.Clean(fp), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	defer core.CloseFile(fout)

	logei(err)("tun: crashout: f: %s; err? %v", fp, err)

	if err == nil {
		return setCrashFd(fout)
	}
	return false
}

func fname(f *os.File) string {
	if f == nil {
		return "<nil file>"
	}
	return f.Name()
}
