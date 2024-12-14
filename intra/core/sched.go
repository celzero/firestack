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

type Job func() error

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
			done(cause)
			s.mu.Lock()
			if c := s.jobctl[id]; c != nil && c.who == ctx {
				delete(s.jobctl, id)
			}
			s.mu.Unlock()
		}()

		select {
		case <-s.ctx.Done():
			cause = s.ctx.Err()
			return
		case <-time.After(time.Until(t)):
			cause = f()
			return
		}
	})
	return ctx
}
