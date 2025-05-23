// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

// ref: github.com/xjasonlyu/tun2socks/blob/bf745d0e0e5d/internal/version/version.go#L1
import (
	"fmt"
	"runtime"
	"runtime/debug"
)

var buildinfo, _ = debug.ReadBuildInfo()

var (
	// Commit set at link time by git rev-parse --short HEAD
	Commit string
	// Date set at link time by date -u +'%Y%m%d%H%M%S'
	Date string
)

func Version() string {
	return fmt.Sprintf("%s (%s/%s@%s)", stamp(), runtime.GOOS, runtime.GOARCH, runtime.Version())
}

func stamp() string {
	if buildinfo != nil {
		// github.com/golang/go/issues/50603
		return buildinfo.Main.Path + "@v" + buildinfo.Main.Version
	}
	return "v" + Date + "-" + Commit
}

func BuildInfo() string {
	if buildinfo == nil {
		return "unknown"
	}
	return buildinfo.String()
}
