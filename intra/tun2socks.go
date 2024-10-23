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
	"os"
	"path/filepath"
	"runtime/debug"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/settings"

	"github.com/celzero/firestack/intra/log"
)

var buildinfo, _ = debug.ReadBuildInfo()

// pkg.go.dev/runtime#hdr-Environment_Variables
type traceout string

type Console log.Console

const (
	one  traceout = "single" // offending go routine
	usr  traceout = "all"    // all user go routines
	sys  traceout = "system" // all user + system go routines
	abrt traceout = "crash"  // GOOS-specific crash after tracing
)

func (t traceout) s() string { return string(t) }

func init() {
	// increase garbage collection frequency: archive.is/WQBf7
	debug.SetGCPercent(10)
	debug.SetMemoryLimit(1024 * 1024 * 1024 * 4) // 4GB
	debug.SetPanicOnFault(true)
}

// Connect creates firestack-administered tunnel.
// `fd` is the TUN device. The tunnel acquires an additional reference to it, which is
// released by Disconnect(), so the caller must close `fd` and Disconnect() to close the TUN device.
// `mtu` is the MTU of the TUN device.
// `fakedns` are the DNS servers that the system believes it is using, in "host:port" style.
// `bdg` is a kotlin object that implements the Bridge interface.
// `dtr` is a kotlin object that implements the DefaultDNS interface.
// Throws an exception if the TUN file descriptor cannot be opened, or if the tunnel fails to
// connect.
func Connect(fd, mtu int, fakedns string, dtr DefaultDNS, bdg Bridge) (t Tunnel, err error) {
	return NewTunnel(fd, mtu, fakedns, settings.DefaultTunMode(), dtr, bdg)
}

// Change log level to log.VERYVERBOSE, log.VERBOSE, log.DEBUG, log.INFO, log.WARN, log.ERROR.
func LogLevel(level, consolelevel int32) {
	dlvl := log.LevelOf(level)
	clvl := log.LevelOf(consolelevel)
	log.SetLevel(dlvl)
	log.SetConsoleLevel(clvl)
	settings.Debug = dlvl <= log.DEBUG
	if settings.Debug {
		debug.SetTraceback(usr.s())
	} else {
		debug.SetTraceback(one.s())
	}
	log.I("tun: new lvl: %d, clvl: %d", dlvl, clvl)
}

// LowMem triggers Go's garbage collection cycle.
func LowMem() {
	go debug.FreeOSMemory()
}

// Slowdown sets the TUN forwarder in single-threaded mode.
func Slowdown(y bool) {
	ok := settings.SingleThreaded.CompareAndSwap(!y, y)
	log.I("tun: slowdown? %t / ok? %t", y, ok)
}

func Experimental(y bool) {
	// todo: move to its own method
	wgok := settings.ExperimentalWireGuard.CompareAndSwap(!y, y)
	fwdok := settings.PortForward.CompareAndSwap(!y, y)
	log.I("tun: experimental settings? %t / wg? %t, portfwd? %t", y, wgok, fwdok)
}

// Loopback informs the network stack that it must deal with packets
// originating from its own process routed back into the tunnel.
func Loopback(y bool) {
	ok := settings.Loopingback.CompareAndSwap(!y, y)
	log.I("tun: loopback? %t / ok? %t", y, ok)
}

func UndelegatedDomains(useSystemDNS bool) {
	ok := settings.SystemDNSForUndelegatedDomains.CompareAndSwap(!useSystemDNS, useSystemDNS)
	log.I("tun: resolve undelegated with system DNS? %t / ok? %t", useSystemDNS, ok)
}

// Transparency enables/disables endpoint-independent mapping/filtering.
// Currently applies only for UDP (RFC 4787).
func Transparency(eim, eif bool) {
	settings.EndpointIndependentMapping.Store(eim)
	settings.EndpointIndependentFiltering.Store(eif)
	log.I("tun: eim? %t / eif? %t", eim, eif)
}

// Build returns the build information.
func Build(full bool) string {
	if !full {
		return core.Version()
	}
	if buildinfo == nil {
		return "unknown"
	}
	return buildinfo.String()
}

// PrintStack logs the stack trace of all active goroutines.
func PrintStack() {
	bptr := core.LOB()
	b := *bptr
	b = b[:cap(b)]
	defer func() {
		*bptr = b
		core.Recycle(bptr)
	}()
	log.TALL("tun: trace", b)
}

// SetCrashFd sets output file to go runtime crashes to.
func SetCrashFd(fp string) (ok bool) {
	defer func() {
		// if crash fd cannot be set, panic on fault to at least
		// capture faults (as panics) via core.DontPanic.
		debug.SetPanicOnFault(!ok)
	}()

	if len(fp) > 0 {
		f, err := os.OpenFile(filepath.Clean(fp), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		defer core.CloseFile(f)

		if err == nil {
			var zz debug.CrashOptions
			err = debug.SetCrashOutput(f, zz)
		}
		note := log.I
		if err != nil {
			note = log.E
		}
		note("tun: crash file %s, err? %v", fp, err)
		return err == nil
	}
	return false
}
