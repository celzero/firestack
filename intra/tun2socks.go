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
	"runtime"
	"runtime/debug"
	"sync/atomic"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/rnet"
	"github.com/celzero/firestack/intra/settings"
	"golang.org/x/sys/unix"

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

func init() {
	// increase garbage collection frequency: archive.is/WQBf7
	debug.SetGCPercent(50)
	debug.SetMemoryLimit(maxMemLimit)
	debug.SetPanicOnFault(true)
}

// SetupConsole wires up firestack's logger to bdg.
func SetupConsole(console Console) {
	ctx := context.Background()

	logch := make(chan bool, 1)
	crashch := make(chan bool, 1)
	go func() {
		logfd := false
		if r, c, err := log.NewFilebased(); err == nil {
			closeall := func() {
				core.Close(c)
				core.Close(r)
			}
			if logfd = console.LogFD(int(r.Fd())); logfd {
				log.SetConsole(ctx, c)
				context.AfterFunc(ctx, closeall)
			} else {
				closeall()
			}
		}
		if !logfd {
			log.SetConsole(ctx, &clogAdapter{console})
		}
		log.D("tun: <<< console >>>; log out ok; fd? %t", logfd)
		logch <- logfd
	}()

	go func() {
		crashfd := pipeCrashOutput(console)
		crashch <- crashfd
		log.D("tun: <<< console >>>; crash out ok; fd? %t", crashfd)
	}()

	logfd := <-logch
	crashfd := <-crashch
	crashpiped.Store(crashfd)

	log.ConsoleReady(ctx)

	log.I("tun: <<< console >>>; logger: ok; fds (log? %t / crash? %t)", logfd, crashfd)
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
// to stdout if onConsole is false, otherwise to Console.
// For testing only.
func PrintStack(onConsole bool) {
	bptr := core.LOB()
	b := *bptr
	b = b[:cap(b)]
	defer func() {
		*bptr = b
		core.Recycle(bptr)
	}()
	if onConsole {
		log.C("tun: debug trace (not a crash)", b)
	} else {
		log.TALL("tun: debug trace (not a crash)", b)
	}
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

// global references to keep go's finalizer from cleaning up the FDs
var crashReader, crashWriter, crashRWErr = os.Pipe()
var crashpiped atomic.Bool

func pipeCrashOutput(c Console) (ok bool) {
	if crashRWErr != nil {
		log.E("tun: err crash output pipe: %v", crashRWErr)
		return false
	}
	pipeBuffer256k(crashWriter)
	pipeBuffer256k(crashReader)
	// defer core.Close(crashReader) // close iff r is dup'd by client code
	defer core.Close(crashWriter) // always close as w is dup'd by the runtime
	if setCrashFd(crashWriter) && c.CrashFD(int(crashReader.Fd())) {
		return true
	}
	setCrashFd(nil)
	return false
}

// setCrashFd sets dup(f) as output file to write go runtime crashes in to.
func setCrashFd(f *os.File) (ok bool) {
	// f is dup()ed by debug.SetCrashOutput before use
	err := debug.SetCrashOutput(f, debug.CrashOptions{})
	logei(err)("tun: crash output file %s, err? %v", fname(f), err)
	return err == nil
}

// SetCrashOutput will set the crash output file to dup(fd), and return true if successful.
// Disables crash output if fd is less than 3.
func SetCrashOutput(fd int) bool {
	p := crashpiped.Swap(false)
	ok := setCrashFd(nil)
	// defer core.Close(crashReader) if fd not owned by the client
	log.I("tun: closing crash out... ok? %t; was piped? %t; new fd: %d", ok, p, fd)
	if fd >= 2 {
		return setCrashFd(os.NewFile(uintptr(fd), "ktcfd"))
	}
	return false
}

func pipeBuffer256k(f *os.File) bool {
	if f == nil {
		return false
	}
	const b256k = 4 * 64 * 1024
	fd := f.Fd()
	nom := f.Name()
	// kernel may round this up to the nearest page size multiple?
	x, err := unix.FcntlInt(fd, unix.F_SETPIPE_SZ, b256k)
	if err != nil {
		log.W("tun: pipe: (%s %d) err set size %d: %v", nom, fd, x, err)
		return false
	}

	x, err = unix.FcntlInt(fd, unix.F_GETPIPE_SZ, 0)
	if err != nil {
		log.W("tun: pipe: (%s %d) err get size: %v", nom, fd, err)
		return false
	}

	runtime.KeepAlive(f)
	log.W("tun: pipe: (%s %d) buffer %s", nom, fd, core.FmtBytes(uint64(x)))
	return true
}

func fname(f *os.File) string {
	if f == nil {
		return "<nil file>"
	}
	return f.Name()
}
