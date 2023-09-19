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
	AddResolver(id string, f Transport) bool
	ResetNat64Prefix(ip6prefix string) bool
	D64(id string, ans6 []byte, f Transport) []byte
}

type NAT64 interface {
	IsNat64(id string, ip []byte) bool
	X64(id string, ip []byte) []byte
}
