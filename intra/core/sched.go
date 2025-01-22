// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"context"
	"errors"
	"sync"
	"time"
)

var errNewJob = errors.New("sched: replaced by newer job")
var errClearJob = errors.New("sched: job cleared")

type CheckIn func(t time.Time)
type Job func() error
type JobShift func(next CheckIn) error

type ctl struct {
	who    context.Context
	cancel context.CancelCauseFunc
}

type Scheduler struct {
	ctx context.Context

	mu     sync.Mutex
	jobctl map[string]*ctl
}

func NewScheduler(ctx context.Context) *Scheduler {
	return &Scheduler{
		ctx:    ctx,
		jobctl: make(map[string]*ctl),
	}
}

// Retry runs f at time t, retries times on errs, with retryCount*period between retries.
func (s *Scheduler) Retry(id string, t time.Time, f Job, retries uint16, multiplier time.Duration) context.Context {
	retrierCtx, retrierDone := context.WithCancelCause(s.ctx)

	Go("retrier."+id, func() {
		var errs error

		defer func() {
			retrierDone(errs)
		}()

		for i := uint16(0); i < retries; i++ {
			select {
			case <-retrierCtx.Done():
				errs = JoinErr(errs, context.Cause(retrierCtx))
				return // cancelled
			default:
			}

			ctx := s.At(id, t, f) // do f at t

			<-ctx.Done() // await f

			next := time.Duration(i+1) * multiplier
			t = time.Now().Add(next)

			if err := context.Cause(ctx); err == nil {
				errs = nil
				return // ok
			} else if errors.Is(err, errNewJob) {
				errs = JoinErr(errs, err)
				return // new job replaced this one
			} else if errors.Is(err, errClearJob) {
				errs = JoinErr(errs, err)
				return // job cleared
			} else {
				errs = JoinErr(errs, err)
				continue // retry
			}
		}
	})

	return retrierCtx
}

// Clear cancels the job with id.
func (s *Scheduler) Clear(ids ...string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := 0
	if len(ids) <= 0 { // clear all
		for _, c := range s.jobctl {
			if c != nil {
				n++
				c.cancel(errClearJob)
			}
		}
		clear(s.jobctl)
	} else {
		for _, id := range ids {
			if c := s.jobctl[id]; c != nil {
				n++
				c.cancel(errClearJob)
				delete(s.jobctl, id)
			}
		}
	}
	return n
}

func (s *Scheduler) Shift(id string, t time.Time, f JobShift) context.Context {
	return s.At(id, t, func() error {
		return f(func(at time.Time) {
			s.Shift(id, at, f)
		})
	})
}

// At runs f at time t; accepts a Context to cancel it.
func (s *Scheduler) At(id string, t time.Time, f Job) context.Context {
	s.mu.Lock()
	ctx, done := context.WithCancelCause(s.ctx)
	if c := s.jobctl[id]; c != nil {
		c.cancel(errNewJob) // dispose existing job
	}
	s.jobctl[id] = &ctl{who: ctx, cancel: done}
	s.mu.Unlock()

	Go("at."+id, func() {
		var cause error

		defer func() {
			s.mu.Lock()
			if c := s.jobctl[id]; c != nil && c.who == ctx {
				delete(s.jobctl, id)
				cause = JoinErr(cause, errNewJob)
			}
			s.mu.Unlock()
			done(cause)
		}()

		select {
		case <-s.ctx.Done():
			cause = context.Cause(s.ctx)
			return
		case <-time.After(time.Until(t)):
			cause = f()
			return
		}
	})
	return ctx
}
