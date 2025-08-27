// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package backend

const ( // see protect/protect.go
	UidSelf   = "rethink"
	UidSystem = "system"
	Localhost = "localhost"
)

type Console interface {
	Log(int32, *Gostr)
}

// Controller provides a way to bind and protect socket file descriptors.
type Controller interface {
	// Bind4 binds fd to any internet-capable IPv4 interface.
	Bind4(who, addrport string, fd int)
	// Bind6 binds fd to any internet-capable IPv6 interface.
	// also: github.com/lwip-tcpip/lwip/blob/239918c/src/core/ipv6/ip6.c#L68
	Bind6(who, addrport string, fd int)
	// Protect marks fd as protected.
	Protect(who string, fd int)
}

type Protector interface {
	// UIP returns ip (network-order byte) to bind given a local/remote ipp (ip:port).
	// (unused)
	UIP(ipp string) []byte
}
