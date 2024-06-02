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
	"runtime/debug"

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
func LogLevel(level int) {
	dlvl := log.WARN
	switch l := log.LogLevel(level); l {
	case log.VVERBOSE:
		dlvl = log.VVERBOSE
	case log.VERBOSE:
		dlvl = log.VERBOSE
	case log.DEBUG:
		dlvl = log.DEBUG
	case log.INFO:
		dlvl = log.INFO
	case log.WARN:
		dlvl = log.WARN
	case log.ERROR:
		dlvl = log.ERROR
	default:
		log.W("tun: unknown log-level(%d), using warn", l)
	}
	log.SetLevel(dlvl)
	settings.Debug = dlvl < log.INFO
	if settings.Debug {
		debug.SetTraceback(usr.s())
	} else {
		debug.SetTraceback(one.s())
	}
	log.I("tun: new log-level %d; debug? %t", dlvl, settings.Debug)
}

// SetConsole sets external console to redirect log output to.
func SetConsole(c Console) {
	log.SetConsole(c)
}

// LowMem triggers Go's garbage collection cycle.
func LowMem() {
	go debug.FreeOSMemory()
}

// Build returns the build information.
func Build() string {
	if buildinfo != nil {
		return buildinfo.String()
	}
	return "unknown"
}

// SetCrashFd sets the file descriptor to write crash reports to.
func SetCrashFd(f string) {
	if len(f) > 0 {
		debug.SetPanicOnFault(false)
	}
	// TODO: Go1.23: debug.SetCrashFD(f)
}
