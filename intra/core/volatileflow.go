// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package core

import (
	"context"
	"slices"
	"sync"
	"time"
)

type FlowFunc[T any] func(v T)

type FlowOn[T any] struct {
	ctx context.Context
	f   *FlowFunc[T]
}

func (f FlowOn[T]) flow(v T) (flowed bool) {
	on := f.f
	if on == nil {
		return false
	}
	select {
	case <-f.ctx.Done():
	default:
		(*on)(v)
		return true
	}
	return false
}

func (f FlowOn[T]) obsolete() bool {
	select {
	case <-f.ctx.Done():
		return true
	default:
	}
	return false
}

type Flow[T any] struct {
	ctx context.Context

	v *Volatile[T]
	c chan T

	fmu sync.RWMutex
	o   []FlowOn[T]
}

func NewForeverFlow[T any](v T) *Flow[T] {
	return NewFlowFor(context.Background(), NewVolatile(v))
}

func NewFlowFor[T any](ctx context.Context, v *Volatile[T]) *Flow[T] {
	if v == nil || ctx == nil {
		return nil
	}

	f := &Flow[T]{
		v:   v,
		o:   make([]FlowOn[T], 0),
		c:   make(chan T),
		ctx: ctx,
	}
	Gx("core.flow", f.stream)
	return f
}

func (f *Flow[T]) stream() {
	// TODO: defer close(f.c); see pub()
	for {
		select {
		case <-f.ctx.Done():
			return
		case v := <-f.c:
			Gx("flow.stream", func() {
				notflowing := make(map[FlowOn[T]]struct{}, 0)
				for _, o := range f.observers() {
					if ok := o.flow(v); !ok {
						notflowing[o] = struct{}{}
					}
				}
				f.removeFinallys(notflowing)
			})
		case <-time.Tick(3 * time.Hour):
			Gx("flow.stream.tick", func() {
				notflowing := make(map[FlowOn[T]]struct{})
				for _, o := range f.observers() {
					if o.obsolete() {
						notflowing[o] = struct{}{}
					}
				}
				f.removeFinallys(notflowing)
			})
		}
	}
}

func (f *Flow[T]) removeFinallys(obsolete map[FlowOn[T]]struct{}) {
	obssz := len(obsolete)
	if obssz <= 0 {
		return
	}

	f.fmu.Lock()
	defer f.fmu.Unlock()

	cursz := len(f.o)
	if cursz <= 0 {
		return
	}

	flowing := make([]FlowOn[T], 0, cursz)
	for _, o := range f.o {
		if _, ok := obsolete[o]; ok {
			continue
		}
		flowing = append(flowing, o)
	}
	f.o = flowing
}

func (f *Flow[T]) observers() []FlowOn[T] {
	f.fmu.RLock()
	defer f.fmu.RUnlock()
	return slices.Clone(f.o)
}

func (f *Flow[T]) pub(v T) {
	select {
	case <-f.ctx.Done():
		return
	default:
		select {
		case <-f.ctx.Done():
			return
		case f.c <- v: // f.c never closed
		}
	}
}

// On (is a hot flow) which immediately calls o (in a separate goroutine)
// and later calls o on changes to the underlying Volatile variable.
func (f *Flow[T]) On(until context.Context, o FlowFunc[T]) {
	f.fmu.Lock()
	defer f.fmu.Unlock()
	on := FlowOn[T]{until, &o}
	f.o = append(f.o, on)
	Gx("flow.on", func() { on.flow(f.v.Load()) })
}

func (f *Flow[T]) Store(v T) {
	defer f.pub(v)
	f.v.Store(v)
}

func (f *Flow[T]) Load() T {
	return f.v.Load()
}

func (f *Flow[T]) Swap(new T) (old T) {
	defer f.pub(new)
	return f.v.Swap(new)
}

func (f *Flow[T]) Tango(new T) (old T) {
	defer func() {
		if !LocEq(new, old) {
			f.pub(new)
		}
	}()

	return f.v.Tango(new)
}

func (f *Flow[T]) CompareAndSwap(old, new T) bool {
	return f.Cas(old, new)
}

func (f *Flow[T]) Cas(old, new T) (success bool) {
	defer func() {
		if success {
			f.pub(new)
		}
	}()

	return f.v.Cas(old, new)
}
