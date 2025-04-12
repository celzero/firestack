// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

// flattens (not stable) and returns a copy with dups removed, if any.
// go.dev/play/p/WJXpAa-nmep
func CopyUniq[T comparable](a ...[]T) (out []T) {
	out = make([]T, 0)
	if len(a) <= 0 {
		return
	}
	if len(a) == 1 {
		out = append(out, a[0]...)
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
