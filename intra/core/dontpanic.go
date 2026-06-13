// Copyright (c) 2024 RethinkDNS and its authors.
// Copyright (c) HashiCorp, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/trace"
	"sync"
	"sync/atomic"
	"time"

	"github.com/celzero/firestack/intra/log"
)

// from: github.com/hashicorp/terraform/blob/325d18262e/internal/logging/panic.go#L36-L64

type Finally func()

type Callback = Finally

type ExitCode int

func (e ExitCode) int() int {
	return int(e)
}

// An exit code of 11 keeps us out of the way of the detailed exitcodes
// from plan, and also happens to be the same code as SIGSEGV which is
// roughly the same type of condition that causes most panics.
const Exit11 ExitCode = 11

// DontExit is a special code that can be passed to Recover to indicate that
// the process should not exit after recovering from a panic.
const DontExit ExitCode = 0

// In case multiple goroutines panic concurrently, ensure only one of them
// is able to print the panic message and exit the process.
var _pmu sync.RWMutex

// protects recorder.WriteTo.
var _rmu sync.Mutex

var parentCallerDepthAt = 1

var recorderperma atomic.Bool
var recorderfile *os.File
var recorder *trace.FlightRecorder

const neverrecord = true

func init() {
	if !neverrecord { // recording seems expensive; enable explicitly
		// TODO: MaxBytes must stay within GOMEMLIMIT if set
		recorder = trace.NewFlightRecorder(trace.FlightRecorderConfig{
			MinAge:   maxCPUProfileSecs * time.Second,
			MaxBytes: 50 * 1024 * 1024, // 50 MiB
		})
	}
}

// fn is called in a separate goroutine, if a panic is recovered.
// RecoverFn must be called as a defered function, and must be the first
// defer called at the start of a new goroutine.
func RecoverFn(aux string, fn Finally) (didpanic bool) {
	recovered := recover()
	didpanic = recovered != nil
	if !didpanic { // nothing to recover from
		return false
	}

	defer Gif(didpanic, "fin."+aux, Callback(fn))

	msg := fmt.Sprintf("%s [%d] %v", aux, DontExit, recovered)
	log.E2(parentCallerDepthAt+1, msg)

	captureRecorderOutput(DontExit)
	applog(DontExit, msg)
	return didpanic
}

func SupportsRecording() bool {
	return !neverrecord
}

func Recording() bool {
	return recorder != nil && recorder.Enabled()
}

func RecordForever(y bool) (recording bool, err error) {
	recorderperma.Store(y)
	return Record(y)
}

func Record(start bool) (recording bool, err error) {
	if recorder == nil {
		return false, errors.ErrUnsupported
	}
	recording = recorder.Enabled()
	neverstop := recorderperma.Load()
	if neverstop || start {
		if !recording {
			err = recorder.Start()
			recording = err == nil
		}
	} else {
		if recording {
			go recorder.Stop()
			recording = false
		}
	}
	return
}

func captureRecorderOutput(code ExitCode) bool {
	if code == DontExit {
		return false
	}
	if recorder == nil {
		return false
	}

	_pmu.Lock()
	defer _pmu.Unlock()

	// Skip if no output file configured
	if recorderfile == nil {
		log.W("core: flightrecorder: no output file configured; skipping capture")
		return false
	}

	n, err := WriteRecordingTo(recorderfile)
	if err == nil {
		recorderfile.Sync()
	}

	logev(err)("core: flightrecorder: wrote %d bytes to file %s; err? %v", n, fname(recorderfile), err)

	return n > 0
}

// WriteRecordingTo writes flight recorder data directly to w, avoiding
// intermediate copies. Returns the number of bytes written and any error.
// Thread-safe; holds the recorder lock for the duration of the write.
func WriteRecordingTo(w io.Writer) (n int64, err error) {
	if recorder == nil || !recorder.Enabled() {
		return 0, errors.ErrUnsupported
	}

	_rmu.Lock()
	defer _rmu.Unlock()

	return recorder.WriteTo(w)
}

// Recover must be called as a defered function, and must be the first
// defer called at the start of a new goroutine.
func Recover(code ExitCode, aux any) (didpanic bool) {
	recovered := recover()
	didpanic = recovered != nil
	if !didpanic { // nothing to recover from
		return false
	}

	msg := fmt.Sprintf("%s [%d] %v [%s]", aux, code, recovered, stamp())
	log.E2(parentCallerDepthAt, msg)

	captureRecorderOutput(code)
	applog(code, msg)
	return didpanic
}

func applog(code ExitCode, msg string) {
	// have all managed goroutines checkin here, and prevent them from exiting
	// if there's a panic in progress. While this can't lock the entire runtime
	// to block progress, we can prevent some cases where firestack may return
	// early before the panic has been printed out.
	if code == DontExit {
		// many "dontexit" goroutines can safely run concurrently.
		_pmu.RLock()
		defer _pmu.RUnlock()
	} else {
		defer os.Exit(Exit11.int())
		// upto one goroutine panicking should exit the process.
		_pmu.Lock()
		defer _pmu.Unlock()
	}

	bptr := LOB()
	b := *bptr
	b = b[:cap(b)]
	defer func() {
		*bptr = b
		Recycle(bptr)
	}()
	log.C(msg, b)
}

func SetFlightRecordOutput(fp string) (string, error) {
	if !neverrecord || recorder == nil {
		return "", errors.ErrUnsupported
	}

	fout, err := os.OpenFile(filepath.Clean(fp), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)

	_pmu.Lock()
	defer _pmu.Unlock()

	prevfile := recorderfile
	prevfname := fname(prevfile)

	logev(err)("core: flightrecorder: newfd %d, prevfd %d; err? %v", fname(fout), prevfname, err)

	if err != nil {
		return prevfname, err
	}

	if prevfile != nil {
		CloseFile(prevfile)
	}

	recorderfile = fout
	return prevfname, nil
}

func fname(f *os.File) string {
	if f == nil {
		return "<nil file>"
	}
	return f.Name()
}
