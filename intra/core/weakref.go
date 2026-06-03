// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"errors"
	"sync"
	"weak"
)

var errNoCreat = errors.New("weak: create fn nil")

type vfactory[V any] func() (new *V)
type vtest[V any] func(*V) (ok bool)

func refpass[V any](_ *V) bool { return true }

type WeakRef[V any] struct {
	mu    sync.RWMutex
	weak  weak.Pointer[V]
	creat vfactory[V]
	test  vtest[V]
}

// unsafe type conversion: github.com/golang/go/issues/71583
func NewWeakRef[V any](creat vfactory[V], test vtest[V]) (*WeakRef[V], error) {
	if creat == nil {
		return nil, errNoCreat
	}
	if test == nil {
		test = refpass
	}

	return &WeakRef[V]{
		creat: creat,
		test:  test,
	}, nil
}

func (w *WeakRef[V]) load() (v *V, valid bool) {
	defer func() { // test without lock held
		valid = v != nil && w.test(v)
	}()

	w.mu.RLock()
	defer w.mu.RUnlock()
	v = w.weak.Value()
	return
}

func (w *WeakRef[V]) storeLocked() (v *V) {
	v = w.creat()
	w.weak = weak.Make(v)
	return
}

func (w *WeakRef[V]) loadOrStore() (v *V, valid bool) {
	if v, valid = w.load(); valid {
		return
	}

	defer func() { // test without lock held
		valid = v != nil && w.test(v)
	}()

	w.mu.Lock()
	defer w.mu.Unlock()
	if v = w.weak.Value(); v == nil { // gc won
		v = w.storeLocked() // new v
	} // else: use existing v
	return
}

func (w *WeakRef[V]) Ref() (v *V, valid bool) {
	return w.loadOrStore()
}

func (w *WeakRef[V]) Get() (zz V, valid bool) {
	v, valid := w.loadOrStore()
	if v == nil || IsNil(v) {
		return zz, false
	}
	return *v, valid
}

func (w *WeakRef[V]) Load() (v V) {
	v, _ = w.Get()
	return
}
