// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"encoding/binary"
	"os"
	_ "runtime" // for go:linkname
	"syscall"
	_ "unsafe" // for go:linkname
)

var pid int

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

	// github.com/golang/go/blob/e2fef50def98/src/runtime/write_err_android.go#L13
	// actual writeHeader = []byte{6 /* ANDROID_LOG_ERROR */, 'G', 'o', 0}
	// Change level to assert in the hope that Android's DropBoxManager picks it up.
	// github.com/golang/go/issues/25035 / developer.android.com/reference/kotlin/android/util/Log#ASSERT:kotlin.Int
	writeHeader = []byte{7 /* ANDROID_LOG_ASSERT */, 'G', 'o', 'E', 'r', 'r', 0}

	pid = syscall.Getpid()
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
func SetRuntimeEnviron(key, val string) (didSet bool, err error) {
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

//go:linkname runtime_timenow runtime.time_now
func runtime_timenow() (sec int64, nsec int32, mono int64)

// pushing func symbols does not work on go1.24+?

// writeLogdHeader prints crash logs to main buffer; the change here
// redirects it to crash buffer instead, which among other things, is
// retained for longer & gets picked up by Android Vitals (via DropBoxManager).
// github.com/golang/go/blob/e2fef50def98/src/runtime/write_err_android.go#L19

//go:linkname runtime.writeLogdHeader
func writeLogdHeader() int {
	hdr := writeBuf[:11]

	// The first 11 bytes of the header corresponds to android_log_header_t
	// as defined in system/core/include/private/android_logger.h
	//   hdr[0] log type id (unsigned char), defined in <log/log.h>
	//   hdr[1:2] tid (uint16_t)
	//   hdr[3:11] log_time defined in <log/log_read.h>
	//      hdr[3:7] sec unsigned uint32, little endian.
	//      hdr[7:11] nsec unsigned uint32, little endian.
	// cs.android.com/android/platform/superproject/main/+/main:system/logging/liblog/include/android/log.h;drc=90ddfb0bd41fbb41d045f04e02476ddce200d535;l=163
	hdr[0] = 4 // LOG_ID_CRASH
	sec, nsec, _ := runtime_timenow()
	binary.LittleEndian.PutUint32(hdr[3:7], uint32(sec))
	binary.LittleEndian.PutUint32(hdr[7:11], uint32(nsec))
	// gettid is not signal safe; use pid (mainthread) instead
	// man7.org/linux/man-pages/man7/signal-safety.7.html
	binary.LittleEndian.PutUint16(hdr[1:2], uint16(pid))

	return 11 + len(writeHeader)
}

// but pushing vars apparently still works provided
// -ldflags="checklinkname=0"

//go:linkname secureMode runtime.secureMode
var secureMode bool

//go:linkname writeHeader runtime.writeHeader
var writeHeader []byte

//go:linkname writeBuf runtime.writeBuf
var writeBuf [1024]byte
