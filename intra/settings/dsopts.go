// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package settings

// msb to lsb: ipv6, ipv4, lwip(1) or netstack(0)
const (
	Ns4  = 0b010 // 2
	Ns46 = 0b110 // 6
	Ns6  = 0b100 // 4
)

// IP4, IP46, IP6 are string'd repr of Ns4, Ns46, Ns6
const (
	IP4  = "4"
	IP46 = "46"
	IP6  = "6"
)

// L3 returns the string'd repr of engine.
func L3(engine int) string {
	switch engine {
	case Ns46:
		return IP46
	case Ns6:
		return IP6
	default:
		return IP4
	}
}

// Engine returns the engine constant for given l3 string.
func Engine(l3 string) int {
	switch l3 {
	case IP46:
		return Ns46
	case IP6:
		return Ns6
	default:
		return Ns4
	}
}
