// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sync"
	"time"

	"github.com/celzero/firestack/intra/log"
)

// profmu ensures only one profile (cpu or mem) is active at a time.
var profmu sync.Mutex

const (
	minCPUProfileSecs = 10
	maxCPUProfileSecs = 120
)

// arbitary wait time for GC to complete
var memProfWaitForGC = 100 * time.Millisecond

// CPUProfile starts a program-wide CPU profiler for durationSecs seconds
// (clamped to [10, 120]). The CPU profile is written to outproffile, and the
// flight recorder trace is written to outflightrecorder. The CPU sampling rate
// is hardcoded to 100 Hz by runtime/pprof.StartCPUProfile.
//
// If the flight recorder is not already running, it is started on-demand and
// stopped after the profile completes; otherwise, the existing recording is used.
//
// Returns the actual number of seconds profiled.
// Only one profile (cpu or mem) can be active at a time.
func CPUProfile(outproffile, outflightrecorder string, durationSecs int32) (ranSecs int32, err error) {
	if !profmu.TryLock() {
		return 0, errors.New("core: profiler: busy; another profile in progress")
	}
	defer profmu.Unlock()

	durationSecs = min(max(durationSecs, minCPUProfileSecs), maxCPUProfileSecs)

	if !neverrecord {
		// manage flight recorder: start on-demand if not already running
		wasRecording := Recording()
		if !wasRecording {
			if _, err = Record(true); err == nil {
				log.W("core: profiler: started flight recorder %s", outflightrecorder)
			}
			defer Record(false) // stop only if we started it
		}
	}

	// open cpu profile output file
	f, err := os.Create(filepath.Clean(outproffile))
	if err != nil {
		return 0, err
	}
	defer CloseFile(f)

	start := time.Now()
	// startcpu profile; rate is hardcoded to 100 Hz by pprof.StartCPUProfile
	if err = pprof.StartCPUProfile(f); err != nil {
		return 0, err
	}

	time.Sleep(time.Duration(durationSecs) * time.Second)

	pprof.StopCPUProfile()

	ranSecs = int32(time.Since(start).Seconds())

	n, terr := maybeWriteTrace(outflightrecorder)

	log.I("core: profiler: cpu done; ran %ds; prof? %s; fr? (%s / %d / err? %v)",
		ranSecs, outproffile, outflightrecorder, n, terr)
	return ranSecs, nil
}

// MemProfile triggers GC and writes a heap profile to outprofile.
// rate controls the memory profiling granularity: 1 is most detailed,
// 0 disables profiling entirely. The previous MemProfileRate is restored
// after the profile completes (default is 512*1024).
//
// If the flight recorder is not already running, it is started on-demand and
// stopped after the profile completes; otherwise, the existing recording is used.
//
// Only one profile (cpu or mem) can be active at a time.
func MemProfile(rate int32, outprofile string) error {
	if !profmu.TryLock() {
		return fmt.Errorf("core: profiler: busy; another profile in progress")
	}
	defer profmu.Unlock()

	f, err := os.Create(filepath.Clean(outprofile))
	if err != nil {
		return fmt.Errorf("core: profiler: mem create %s: %w", outprofile, err)
	}
	defer CloseFile(f)

	// set memory profiling rate; revert to previous value after
	prevRate := runtime.MemProfileRate
	if rate < 0 {
		rate = 0
	}
	runtime.MemProfileRate = int(rate)
	defer func() { runtime.MemProfileRate = prevRate }()

	// trigger GC for up-to-date statistics
	runtime.GC()

	time.Sleep(memProfWaitForGC) // ensure GC completes before profiling

	if err = pprof.WriteHeapProfile(f); err != nil {
		return log.EE("core: profiler: mem write %s: %w", outprofile, err)
	}

	runtime.KeepAlive(f)

	log.I("core: profiler: mem done; rate %d; prof? %s", rate, outprofile)
	return nil
}

// maybeWriteTrace writes flight recorder data directly to a file at fp.
func maybeWriteTrace(fp string) (n int64, err error) {
	if !neverrecord {
		return 0, errors.ErrUnsupported
	}
	if len(fp) <= 0 {
		return 0, os.ErrInvalid
	}
	f, err := os.Create(filepath.Clean(fp))
	if err != nil {
		return 0, err
	}
	defer CloseFile(f)

	n, err = WriteRecordingTo(f)

	runtime.KeepAlive(f)
	return
}
