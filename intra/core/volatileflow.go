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
)

type FlowOn struct {
	ctx context.Context
	f   *Finally
}

func (f FlowOn) flow() (flowed bool) {
	on := f.f
	if on == nil {
		return false
	}
	select {
	case <-f.ctx.Done():
	default:
		(*on)()
		return true
	}
	return false
}

type Flow[T any] struct {
	ctx context.Context

	v *Volatile[T]
	c chan struct{}

	fmu sync.RWMutex
	o   []FlowOn
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
		o:   make([]FlowOn, 0),
		c:   make(chan struct{}),
		ctx: ctx,
	}
	go f.stream()
	return f
}

func (f *Flow[T]) stream() {
	// TODO: defer close(f.c); see pub()
	for {
		select {
		case <-f.ctx.Done():
			return
		default:
			select {
			case <-f.ctx.Done():
				return
			case <-f.c:
				notflowing := make(map[FlowOn]struct{}, 0)
				for _, o := range f.observers() {
					if ok := o.flow(); !ok {
						notflowing[o] = struct{}{}
					}
				}
				go f.removeFinallys(notflowing)
			}
		}
	}
}

func (f *Flow[T]) removeFinallys(obsolete map[FlowOn]struct{}) {
	if len(obsolete) <= 0 {
		return
	}

	f.fmu.Lock()
	defer f.fmu.Unlock()
	flowing := make([]FlowOn, 0, len(f.o)-len(obsolete))
	for _, o := range f.o {
		if _, ok := obsolete[o]; ok {
			continue
		}
		flowing = append(flowing, o)
	}
	f.o = flowing

}

func (f *Flow[T]) observers() []FlowOn {
	f.fmu.RLock()
	defer f.fmu.RUnlock()
	return slices.Clone(f.o)
}

func (f *Flow[T]) pub() {
	select {
	case <-f.ctx.Done():
		return
	case f.c <- struct{}{}: // f.c never closed
	}
}

// On (is a hot flow) which immediately calls o (in the same goroutine)
// and later calls o on changes to the underlying Volatile variable.
func (f *Flow[T]) On(until context.Context, o Finally) {
	f.fmu.Lock()
	defer f.fmu.Unlock()
	on := FlowOn{until, &o}
	f.o = append(f.o, on)
	on.flow()
}

func (f *Flow[T]) Store(v T) {
	defer f.pub()
	f.v.Store(v)
}

func (f *Flow[T]) Load() T {
	defer f.pub()
	return f.v.Load()
}

func (f *Flow[T]) Swap(new T) (old T) {
	defer f.pub()
	return f.v.Swap(new)
}

func (f *Flow[T]) Tango(new T) (old T) {
	defer f.pub()
	return f.v.Tango(new)
}

func (f *Flow[T]) CompareAndSwap(old, new T) bool {
	defer f.pub()
	return f.v.Cas(old, new)
}

func (f *Flow[T]) Cas(old, new T) bool {
	defer f.pub()
	return f.v.Cas(old, new)
}
