// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"hash/maphash"
	"math/rand/v2"
	"reflect"
	"strconv"

	_ "go4.org/unsafe/assume-no-moving-gc"
)

// locxor is a per-process random constant XOR'd into every address returned
// by Loc / LocStr so that raw heap pointers are not exposed to callers.
var locxor = rand.Uint64()

var loc2seed = maphash.MakeSeed()

func loc(x any) uint64 {
	if x == nil {
		return 0
	}
	v := reflect.ValueOf(x)
	k := v.Kind()
	switch k {
	// [Chan], [Func], [Map], [Pointer], [Slice], [String] or [UnsafePointer]
	case reflect.Pointer, reflect.UnsafePointer, reflect.String, reflect.Chan, reflect.Func, reflect.Map, reflect.Slice:
		return uint64(v.Pointer()) ^ locxor
	}
	return 0
}

// Rand64 returns a random 64-bit hex string (16 chars long).
func Rand64() string {
	return strconv.FormatUint(rand.Uint64(), 16)
}

// go.dev/play/p/jjI4XJZud4i
func Loc[T comparable](x T) uint64 {
	// maphash will be compatible with moving gc
	// and is compatible with moving goroutine stacks
	// github.com/golang/go/issues/54670#issuecomment-2025642730
	return maphash.Comparable(loc2seed, x)
}

func LocStr[T comparable](x T) string {
	return strconv.FormatUint(Loc(x), 16)
}

func HashStr(s string) uint64 {
	return maphash.String(loc2seed, s)
}

// may panic or return false if x is not addressable
func IsNotNil(x any) bool {
	return !IsNil(x)
}

// IsNil reports whether x is nil if its Chan, Func, Map,
// Pointer, UnsafePointer, Interface, and Slice;
// may panic or return false if x is not addressable
func IsNil(x any) bool {
	// from: stackoverflow.com/a/76595928
	if x == nil {
		return true
	}
	v := reflect.ValueOf(x)
	k := v.Kind()
	switch k {
	case reflect.Pointer, reflect.UnsafePointer, reflect.Interface, reflect.Chan, reflect.Func, reflect.Map, reflect.Slice:
		return v.IsNil()
	}
	return false
}

func TypeEq(a, b any) bool {
	if IsNil(a) {
		return false
	} else if IsNil(b) {
		return false
	}
	return reflect.TypeOf(a) == reflect.TypeOf(b)
}

func loceq(a, b any) bool {
	loca := loc(a)
	locb := loc(b)
	return loca > 0 && locb > 0 && loca == locb
}

func LocEq[T comparable](a, b T) bool {
	return Loc(a) == Loc(b)
}

func PtrEq(a, b any) bool {
	return loc(a) == loc(b)
}

func IsZero(x any) bool {
	if IsNil(x) {
		return true
	}
	v := reflect.ValueOf(x)
	// panics if x == nil: go.dev/play/p/jcJzdHF0JCq
	return v.IsZero()
}
