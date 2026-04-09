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
	Log(int32, string)
	LogFD(readAfterDup int) bool
	CrashFD(readUntilEOF int) bool
	// LogMemFD hands off the shared-memory and that back the double-buffered log data.
	// fd1 and fd2 can be mapped; but must be dup(2)'d before use.
	// size is the max length (in bytes) of each region the receiver should mmap.
	// Return a LogConsumer if the implementation will consume the data from these regions.
	// nil causes fallback to LogFD or the synchronous Console adapter.
	LogMemFD(fd1, fd2, size int) LogConsumer
}

type LogConsumer interface {
	// fd is shared memory; start and end are the byte offsets [start, end)
	// of the valid data within the mapped memory. Return the number
	// of bytes consumed.
	Drain(fd, start, end int) int
	// Close is called when the Writer is wrapping things up. The client
	// code can delay returning from this callback to stall the Writer a bit.
	OnClose() (closed bool)
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
