// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"strconv"
	"time"
)

// ActiveWorkers returns a snapshot of all goroutines currently running
// inside async.go helpers (Go, Gx, Gg, Grx, etc.).
func ActiveWorkers() []WorkersState {
	var out []WorkersState
	workmap.Range(func(k, v any) bool {
		e := v.(roent)
		out = append(out, WorkersState{Typ: e.typ, ID: k.(string), Since: time.Since(e.dob)})
		return true
	})
	return out
}

// Go runs f in a goroutine and recovers from any panics.
func Go(who string, f Finally) {
	go func() {
		debug.SetPanicOnFault(true)
		defer Recover(DontExit, who)
		untrack := trackwork(who, "go")
		defer untrack()

		f()
	}()
}

// Go1 runs f(arg) in a goroutine and recovers from any panics.
func Go1[T any](who string, f func(T), arg T) {
	go func() {
		debug.SetPanicOnFault(true)
		defer Recover(DontExit, who)
		untrack := trackwork(who, "go1")
		defer untrack()

		f(arg)
	}()
}

// Go2 runs f(arg0,arg1) in a goroutine and recovers from any panics.
func Go2[T0 any, T1 any](who string, f func(T0, T1), a0 T0, a1 T1) {
	go func() {
		debug.SetPanicOnFault(true)
		defer Recover(DontExit, who)
		untrack := trackwork(who, "go2")
		defer untrack()

		f(a0, a1)
	}()
}

// Gg runs f in a goroutine, recovers from any panics if any;
// then calls cb in a separate goroutine, and recovers from any panics.
func Gg(who string, f Callback, cb Finally) {
	go func() {
		debug.SetPanicOnFault(true)
		defer RecoverFn(who, cb)
		untrack := trackwork(who, "gg")
		defer untrack()

		f()
	}()
}

// Gx runs f in a goroutine and exits the process if f panics.
func Gx(who string, f Callback) {
	go func() {
		debug.SetPanicOnFault(true)
		defer Recover(Exit11, who)
		untrack := trackwork(who, "gx")
		defer untrack()

		f()
	}()
}

// Gx1 runs f in a goroutine and exits the process if f panics.
func Gx1[T any](who string, f func(T), arg T) {
	go func() {
		debug.SetPanicOnFault(true)
		defer Recover(Exit11, who)
		untrack := trackwork(who, "gx1")
		defer untrack()

		f(arg)
	}()
}

// Gif runs f in a goroutine if cond is true.
func Gif(cond bool, who string, f Callback) {
	if cond {
		Go(who, f)
	}
}

// Grx runs work function f in a goroutine, blocking until it returns or timesout.
func Grx[T any](who string, f WorkCtx[T], d time.Duration) (zz T, completed bool) {
	ch := make(chan T, 1) // non-blocking

	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()

	// go.dev/play/p/VtWYJrxhXz6
	go func() {
		debug.SetPanicOnFault(true)
		defer Recover(Exit11, who)
		defer close(ch)
		untrack := trackwork(who, "grx")
		defer untrack()

		out, _ := f(ctx) // TODO: log error?
		ch <- out
	}()

	select {
	case out := <-ch:
		return out, true
	case <-ctx.Done(): // timeout
	}
	return zz, false
}

// Gre runs work function f in a goroutine, blocking until it returns or ctx is done.
func Gre[T any](who string, f Work[T], ctx context.Context) (zz T, err error, completed bool) {
	type res struct {
		t   T
		err error
	}
	ch := make(chan *res, 1) // non-blocking

	// go.dev/play/p/VtWYJrxhXz6
	go func() {
		debug.SetPanicOnFault(true)
		defer Recover(Exit11, who)
		defer close(ch)
		untrack := trackwork(who, "grx2")
		defer untrack()

		t, err := f() // TODO: log error?
		ch <- &res{t, err}
	}()

	select {
	case out := <-ch:
		return out.t, out.err, true
	case <-ctx.Done(): // timeout or cancellation
		return zz, ctx.Err(), false
	}
}

// Gxe runs f in a goroutine, ignores returned error, and exits on panics.
func Gxe(who string, f func() error) {
	go func() {
		debug.SetPanicOnFault(true)
		defer Recover(Exit11, who)
		untrack := trackwork(who, "gxe")
		defer untrack()

		_ = f()
	}()
}

// errPanic returns an error indicating that the function at index i panicked.
func errPanic(who string) error {
	return fmt.Errorf("%w: %s fn panicked", errPanicked, who)
}

var errPanicked = errors.New("async: function panicked")

// Race runs all the functions in fs concurrently and returns the first non-error result.
// Returned values are the result, the index of the function that returned the result, and any errors.
// If all functions return an error, the accumulation of it is returned.
// Panicking functions are considered as returning an error.
// If the timeout is reached, errTimeout is returned.
// Note that, zero value result could be returned if at least one function returns that without any error.
// go.dev/play/p/GVW-dXcZORr
func Race[T any](who string, timeout time.Duration, fs ...WorkCtx[T]) (zz T, fidx int, errs error) {
	type res struct {
		t   T
		err error
		i   int
	}

	ch := make(chan *res, len(fs))

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for i, f := range fs {
		fid := who + ".race." + strconv.Itoa(i)
		Gg(fid, func() {
			out, err := f(ctx)
			select {
			case <-ctx.Done(): // discard out, err
			case ch <- &res{out, err, i}:
			}
		}, func() {
			select {
			case <-ctx.Done(): // discard out, err
			case ch <- &res{zz, errPanic(fid), i}:
			}
		})
	}

loop:
	for range fs {
		select {
		case r := <-ch:
			if r.err != nil {
				errs = JoinErr(errs, r.err)
			} else {
				return r.t, r.i, r.err
			}
		case <-ctx.Done():
			// if one of WorkCtx functions times out, it
			// means the rest have also lost the race.
			// break out of the loop and return errTimeout.
			errs = JoinErr(errs, errTimeout)
			break loop
		}
	}
	return // zz
}

func First[T any](who string, overallTimeout time.Duration, tester func(T) bool, fs ...WorkCtx[T]) (zz T, idx int) {
	timeoutPerFn := overallTimeout / time.Duration(len(fs))
	for i, f := range fs {
		// unneeded in go1.23+ i, f := i, f
		fid := who + ".all." + strconv.Itoa(i)
		if x, ok := Grx(fid, f, timeoutPerFn); ok {
			return x, i
		}
	}
	return zz, -1
}

func All[T any](who string, timeout time.Duration, fs ...WorkCtx[T]) ([]T, []error) {
	type res struct {
		fidx int // index of the function in fs
		t    T
		err  error
	}

	ch := make(chan *res, len(fs))

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for i, f := range fs {
		//unneeded in go1.23+ i, f := i, f
		fid := who + ".all." + strconv.Itoa(i)
		Gg(fid, func() {
			out, err := f(ctx)
			select {
			case <-ctx.Done(): // timeout
				ch <- &res{fidx: i, err: errTimeout}
			case ch <- &res{i, out, err}:
			}
		}, func() {
			select {
			case <-ctx.Done(): // timeout
				ch <- &res{fidx: i, err: errTimeout}
			case ch <- &res{fidx: i, err: errPanic(fid)}:
			}
		})
	}

	results := make([]T, len(fs))
	errs := make([]error, len(fs))

	for range len(fs) {
		r := <-ch
		results[r.fidx] = r.t
		errs[r.fidx] = r.err
	}
	return results, errs
}

func Periodic(id string, pctx context.Context, d time.Duration, f func()) context.Context {
	ctx, done := context.WithCancel(pctx)
	Go("periodic."+id, func() {
		t := time.NewTicker(d)
		defer t.Stop()
		defer done()

		for {
			select {
			case <-pctx.Done():
				return
			case <-t.C:
				f()
			}
		}
	})
	return ctx
}

// SigFin runs f in a goroutine and returns a channel that is closed when f returns.
func SigFin(id string, f func()) <-chan struct{} {
	done := make(chan struct{})
	Go("sigfin."+id, func() {
		defer close(done)
		f()
	})
	return done
}

func Await(f func(), until time.Duration) (awaited bool) {
	done := make(chan struct{})
	Go("await", func() {
		defer close(done)
		f()
	})

	select {
	case <-time.After(until):
		return false
	case <-done:
		return true
	}
}

func Await1[T any](f func() T, until time.Duration) (v T, gotV bool) {
	done := make(chan struct{})
	Go("await", func() {
		defer close(done)
		v = f()
	})

	select {
	case <-time.After(until):
		return v, false
	case <-done:
		return v, true
	}
}

func EitherOr(either <-chan struct{}, or Callback, until time.Duration) (esc bool) {
	select {
	case <-time.After(until):
		if or != nil {
			or()
		}
		return false
	case <-either:
		return true
	}
}
