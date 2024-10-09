// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"errors"
	"strconv"
	"time"
)

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

func Grx[T any](who string, f func() T, d time.Duration) (zz T, completed bool) {
	ch := make(chan T)

	done := make(chan struct{})
	defer close(done)

	timer := time.NewTicker(d)
	defer timer.Stop()

	// go.dev/play/p/VtWYJrxhXz6
	go func() {
		defer Recover(Exit11, who)
		defer close(ch)

		select {
		case ch <- f():
		case <-done:
		}
	}()

	select {
	case out := <-ch:
		return out, true
	case <-timer.C:
	}
	return zz, false
}

// errPanic returns an error indicating that the function at index i panicked.
func errPanic(who string) error {
	return errors.New(who + "fn panicked")
}

// Race runs all the functions in fs concurrently and returns the first non-error result.
// Returned values are the result, the index of the function that returned the result, and any errors.
// If all functions return an error, the accumulation of it is returned.
// Panicking functions are considered as returning an error.
// If the timeout is reached, errTimeout is returned.
// Note that, zero value result could be returned if at least one function returns that without any error.
func Race[T any](who string, timeout time.Duration, fs ...func() (T, error)) (zz T, fidx int, errs error) {
	type res struct {
		t   T
		err error
		i   int
	}

	ch := make(chan *res, len(fs))
	defer close(ch)
	done := make(chan struct{}) // always unbuffered
	defer close(done)

	for i, f := range fs {
		i, f := i, f
		fid := who + ".race." + strconv.Itoa(i)
		Gg(fid, func() {
			out, err := f()
			select {
			case <-done:
			case ch <- &res{out, err, i}:
			}

		}, func() {
			select {
			case <-done:
			case ch <- &res{zz, errPanic(fid), i}:
			}
		})
	}

outer:
	for {
		select {
		case r := <-ch:
			if r.err != nil {
				errs = errors.Join(errs, r.err)
			} else {
				return r.t, r.i, r.err
			}
		case <-time.After(timeout):
			errs = errors.Join(errs, errTimeout)
			break outer
		}
	}
	return // zz
}
