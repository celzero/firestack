// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"os"
	_ "unsafe" // for go:linkname

	"github.com/celzero/firestack/intra/log"
)

// pushing / pulling symbols work provided
// -ldflags="checklinkname=0"

//go:linkname secureMode runtime.secureMode
var secureMode bool

func init() {
	// github.com/golang/go/issues/69868
	// Unfortunately, Android apps have AT_SECURE set
	// (read bytes in /proc/self/auxv on non-rooted Androids).
	// This means, on Go runtime fatal / throws and a few kinds of panics,
	// only one line is output to logcat (Android's stderr) which makes it
	// hard to tell just what went wrong. Android, does use unwinder for
	// native apps, and the Android RunTime has its own unwinder;
	// both of which traceback seemingly oblivious to AT_SECURE.
	// Perhaps, there's security benefits to the Go runtime being this rigid
	// about GOTRACEBACK, but for goos.IsAndroid (and for apps with uid > 10000),
	// using AT_SECURE to determine "setuid-like" protections appears pointless.
	secureMode = false
}

func SecureMode(new bool) (prev bool) {
	prev = secureMode
	secureMode = new
	return prev
}

// RuntimeSecureMode reports whether the Go runtime is in secure mode.
// github.com/golang/go/blob/e2fef50def98/src/runtime/os_linux.go#L296
func RuntimeSecureMode() (them, us bool) {
	return runtime_isSecureMode(), secureMode
}

// RuntimeGotraceback returns the current GOTRACEBACK settings.
// github.com/golang/go/blob/e2fef50def98/src/runtime/runtime1.go#L38
func RuntimeGotraceback() (l int32, all, crash bool) {
	return runtime_gotraceback()
}

// RuntimeFinishDebugVarsSetup resets internal runtime debug variables
// by re-reading GODEBUG & GOTRACEBACK env vars.
// github.com/golang/go/blob/e2fef50def98/src/runtime/runtime1.go#L462
func RuntimeFinishDebugVarsSetup() {
	runtime_finishDebugVarsSetup()
}

// RuntimeEnviron returns the Go runtime's cached environment vars.
// github.com/golang/go/blob/e2fef50def98/src/runtime/runtime1.go#L98
func RuntimeEnviron() []string {
	return runtime_environ()
}

// SetRuntimeEnviron sets / adds a key-value pair in the Go runtime's
// cached environment vars.
func SetRuntimeEnviron(key, val string) (didSet, overwrote bool, err error) {
	envs := runtime_environ()
	kv := key + "="
	for i, e := range envs {
		if len(e) >= len(kv) && e[:len(kv)] == kv {
			envs[i] = kv + val
			err = os.Setenv(key, val)
			didSet = true
			break
		}
	}
	// override both key and val from last index
	if !didSet {
		for i := len(envs) - 1; i >= 0; i-- {
			log.W("core: SetRuntimeEnviron: key %s not found; overriding %s; val %s", key, envs[i], val)
			envs[i] = kv + val
			err = os.Setenv(key, val)
			overwrote = true
			break
		}
	}
	return
}

// GetRuntimeEnviron gets a value from the Go runtime's cached
// environment vars.
func GetRuntimeEnviron(key string) (val string, found bool) {
	envs := runtime_environ()
	kv := key + "="
	for _, e := range envs {
		if len(e) >= len(kv) && e[:len(kv)] == kv {
			return e[len(kv):], true
		}
	}
	return
}

// RuntimeWtf uses runtime.writeHeader and emits s to logd.
// github.com/golang/go/blob/e2fef50def98/src/runtime/write_err_android.go#L39
func RuntimeWtf(s string) {
	runtime_wtf([]byte(s))
}

//go:linkname runtime_environ runtime.environ
func runtime_environ() []string

//go:linkname runtime_finishDebugVarsSetup runtime.finishDebugVarsSetup
func runtime_finishDebugVarsSetup()

//go:linkname runtime_isSecureMode runtime.isSecureMode
func runtime_isSecureMode() bool

//go:linkname runtime_gotraceback runtime.gotraceback
func runtime_gotraceback() (int32, bool, bool)

//go:linkname runtime_wtf runtime.writeErr
func runtime_wtf(b []byte)

// ld.lld: error: relocation R_X86_64_PC32 cannot be used against symbol 'runtime.time_now'; recompile with -fPIC
// runtime.time_now => time.now
// ref: github.com/ulule/limiter/blob/f0ada6cb8fa4dc55a734de737c7b4a3f35c86ae1/internal/fasttime/fasttime.go#L12
