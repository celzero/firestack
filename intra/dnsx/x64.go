// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

// ref: datatracker.ietf.org/doc/html/rfc8880
const Rfc7050WKN = "ipv4only.arpa."
const UnderlayResolver = "__underlay"
const OverlayResolver = "__overlay"
const Local464Resolver = "__local464"

type NatPt interface {
	DNS64
	NAT64
}

type DNS64 interface {
	// Add64 registers DNS64 resolver f to id.
	Add64(id string, f Transport) bool
	// Remove64 deregisters any current resolver from id.
	Remove64(id string) bool
	// ResetNat64Prefix sets the NAT64 prefix for transport id to ip6prefix.
	ResetNat64Prefix(ip6prefix string) bool
	// D64 synthesizes ans64 (AAAA) from ans6 if required, using resolver f.
	// Returned ans64 is nil if no DNS64 synthesis is needed (not AAAA).
	// Returned ans64 is ans6 if it already has AAAA records.
	D64(id string, ans6 []byte, f Transport) []byte
}

type NAT64 interface {
	// Returns true if ip is a NAT64 address from transport id.
	IsNat64(id string, ip []byte) bool
	// Translates ip to IPv4 using the NAT64 prefix for transport id.
	// As a special case, ip is zero addr, output is always IPv4 zero addr.
	X64(id string, ip []byte) []byte
}
