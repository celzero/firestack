// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"errors"
	"unique"
)

var errNoCreat = errors.New("weak: create fn nil")

type reffactory[V any] func() *V
type reftest[V any] func(*V) bool

func refpass[V any](_ *V) bool { return true }

// WeakRef is a weak reference to a value of type V.
type WeakRef[V any] struct {
	// unique.Handle holds a weak reference to *V.
	weak  unique.Handle[*V]
	creat reffactory[V]
	test  reftest[V]
}

func NewWeakRef[V any](creat reffactory[V], test reftest[V]) (*WeakRef[V], error) {
	if creat == nil {
		return nil, errNoCreat
	}
	if test == nil {
		test = refpass
	}

	return &WeakRef[V]{
		weak:  unique.Make[*V](nil), // initially nil
		creat: creat,
		test:  test,
	}, nil
}

func (w *WeakRef[V]) load() (v *V, valid bool) {
	v = w.weak.Value()
	valid = v != nil && w.test(v)
	return
}

func (w *WeakRef[V]) store() (v *V, valid bool) {
	v = w.creat()
	w.weak = unique.Make(v)
	valid = v != nil && w.test(v)
	return
}

func (w *WeakRef[V]) loadOrStore() (v *V, valid bool) {
	if v, valid = w.load(); valid {
		return
	}
	return w.store() // new v
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
