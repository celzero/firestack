// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"math/rand"
	"slices"
)

// flattens and returns a (stable) copy with dups removed, if any.
// go.dev/play/p/OzJs4s6XvQe
func CopyUniq[T comparable](a ...[]T) (out []T) {
	out = make([]T, 0)
	if len(a) <= 0 {
		return
	}
	acc := make(map[T]struct{}, 0)
	for _, x := range a {
		for _, xx := range x {
			if _, ok := acc[xx]; ok {
				continue
			}
			// maintain incoming order
			out = append(out, xx)
			acc[xx] = struct{}{}
		}
	}
	return
}

type TestFn[T any] func(T) bool

func FilterLeft[T any](arr []T, test TestFn[T]) (out []T) {
	out = make([]T, 0)
	for _, x := range arr {
		if test(x) {
			out = append(out, x)
		}
	}
	return out
}

func ShuffleInPlace[T any](c []T) []T {
	if len(c) <= 1 {
		return c
	}
	rand.Shuffle(len(c), func(i, j int) {
		c[i], c[j] = c[j], c[i]
	})
	return c
}

func Sort[T any](arr []T, less func(a, b T) int) []T {
	slices.SortFunc(arr, less)
	return arr
}

func Map[T, U any](arr []T, transform func(T) U) (out []U) {
	out = make([]U, 0)
	for _, x := range arr {
		out = append(out, transform(x))
	}
	return out
}

// WithoutElem returns arr (may be a copy) removing all occurrences of elem.
func WithoutElem[T comparable](arr []T, elem T) (out []T) {
	if !slices.Contains(arr, elem) {
		return arr
	}

	out = make([]T, 0)
	for _, x := range arr {
		if x == elem {
			continue
		}
		out = append(out, x)
	}
	return out
}

// WithElem returns arr with elem added to it.
func WithElem[T comparable](s []T, add T) []T {
	if len(s) <= 0 {
		return []T{add}
	}
	if slices.Contains(s, add) {
		return s
	}
	return append(s, add)
}

func WithoutNils[T any](arr []T) (out []T) {
	for _, x := range arr {
		if IsNil(x) {
			continue
		}
		out = append(out, x)
	}
	return out
}
