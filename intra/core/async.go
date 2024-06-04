// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

// Go runs f in a goroutine and recovers from any panics.
func Go(who string, f func()) {
	go func() {
		defer Recover(DontExit, who)

		f()
	}()
}

// Go2 runs f(arg0,arg1) in a goroutine and recovers from any panics.
func Go2[T0 any, T1 any](who string, f func(T0, T1), a0 T0, a1 T1) {
	go func() {
		defer Recover(DontExit, who)

		f(a0, a1)
	}()
}

// Gx runs f in a goroutine and exits the process if f panics.
func Gx(who string, f func()) {
	go func() {
		defer Recover(Exit11, who)

		f()
	}()
}
