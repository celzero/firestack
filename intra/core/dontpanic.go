// Copyright (c) 2024 RethinkDNS and its authors.
// Copyright (c) HashiCorp, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"fmt"
	"os"
	"sync"

	"github.com/celzero/firestack/intra/log"
)

// from: github.com/hashicorp/terraform/blob/325d18262e/internal/logging/panic.go#L36-L64

type Finally func()

// An exit code of 11 keeps us out of the way of the detailed exitcodes
// from plan, and also happens to be the same code as SIGSEGV which is
// roughly the same type of condition that causes most panics.
const Exit11 = 11

// DontExit is a special code that can be passed to Recover to indicate that
// the process should not exit after recovering from a panic.
const DontExit = 0

// In case multiple goroutines panic concurrently, ensure only one of them
// is able to print the panic message and exit the process.
var _pmu sync.RWMutex

var parentCallerDepthAt = log.LogFnCallerDepth + 1

// fn is called in a separate goroutine, iff a panic is recovered.
// RecoverFn must be called as a defered function, and must be the first
// defer called at the start of a new goroutine.
func RecoverFn(aux string, fn Finally) (didpanic bool) {
	defer Gif(didpanic, "fin."+aux, fn)

	return Recover(DontExit, aux)
}

// Recover must be called as a defered function, and must be the first
// defer called at the start of a new goroutine.
func Recover(code int, aux string) (didpanic bool) {
	recovered := recover()
	didpanic = recovered != nil
	if !didpanic { // nothing to recover from
		return false
	}

	// Have all managed goroutines checkin here, and prevent them from exiting
	// if there's a panic in progress. While this can't lock the entire runtime
	// to block progress, we can prevent some cases where firestack may return
	// early before the panic has been printed out.
	if code == DontExit {
		// many "dontexit" goroutines can safely run concurrently.
		_pmu.RLock()
		defer _pmu.RUnlock()
	} else {
		defer os.Exit(Exit11)
		// upto one goroutine panicking should exit the process.
		_pmu.Lock()
		defer _pmu.Unlock()
	}

	// fixme: what about locks above if log.[E2|C], fmt.Sprintf panic?
	msg := fmt.Sprintf("%s %d, %v\n", aux, code, recovered)
	log.E2(parentCallerDepthAt, msg)

	bptr := AllocRegion(BMAX)
	b := *bptr
	b = b[:cap(b)]
	defer func() {
		*bptr = b
		Recycle(bptr)
	}()
	log.C(msg, b)

	return didpanic
}
