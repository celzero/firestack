// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"fmt"
	"reflect"
)

func Loc(x any) uintptr {
	if x == nil {
		return 0
	}
	v := reflect.ValueOf(x)
	k := v.Kind()
	switch k {
	// [Chan], [Func], [Map], [Pointer], [Slice], [String] or [UnsafePointer]
	case reflect.Pointer, reflect.UnsafePointer, reflect.String, reflect.Chan, reflect.Func, reflect.Map, reflect.Slice:
		return v.Pointer()
	}
	return 0
}

func LocStr(x any) string {
	return fmt.Sprintf("%x", Loc(x))
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

func LocEq(a, b any) bool {
	loca := Loc(a)
	locb := Loc(b)
	return loca > 0 && locb > 0 && loca == locb
}

func IsZero(x any) bool {
	if IsNil(x) {
		return true
	}
	v := reflect.ValueOf(x)
	// panics if x == nil: go.dev/play/p/jcJzdHF0JCq
	return v.IsZero()
}
