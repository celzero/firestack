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

// Go1 runs f(arg) in a goroutine and recovers from any panics.
func Go1[T any](who string, f func(T), arg T) {
	go func() {
		defer Recover(DontExit, who)

		f(arg)
	}()
}

// Go2 runs f(arg0,arg1) in a goroutine and recovers from any panics.
func Go2[T0 any, T1 any](who string, f func(T0, T1), a0 T0, a1 T1) {
	go func() {
		defer Recover(DontExit, who)

		f(a0, a1)
	}()
}

// Gg runs f in a goroutine, recovers from any panics if any;
// then calls cb in a separate goroutine, and recovers from any panics.
func Gg(who string, f func(), cb func()) {
	go func() {
		defer RecoverFn(who, cb)

		f()
	}()
}

// Gx runs f in a goroutine and exits the process if f panics.
func Gx(who string, f func()) {
	go func() {
		defer Recover(Exit11, who)

		f()
	}()
}

func Gif(cond bool, who string, f func()) {
	if cond {
		Go(who, f)
	}
}
