// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package backend

const ( // see protect/protect.go
	Selfhost   = "rethink"
	Systemhost = "system"
	Localhost  = "localhost"
)

type Console interface {
	Log(int32, string)
	LogFD(readAfterDup int) bool
	// LogMemFD hands off the shared-memory and that back the double-buffered log data.
	// fd1 and fd2 can be mapped; but must be dup(2)'d before use.
	// size is the max length (in bytes) of each region the receiver should mmap.
	// slotsize is the size of each slot/line within the shared-memory region.
	// Return a LogConsumer if the implementation will consume the data from these regions.
	// nil causes fallback to LogFD or the synchronous Console adapter.
	LogMemFD(fd1, fd2, size, slotsize int) LogConsumer
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
	// Bind4 binds fd to any IPv4 interface that will route addrport.
	Bind4(who, addrport string, fd int)
	// Bind6 binds fd to any IPv6 interface that will route addrport.
	// also: github.com/lwip-tcpip/lwip/blob/239918c/src/core/ipv6/ip6.c#L68
	Bind6(who, addrport string, fd int)
	// Protect marks fd as protected from routing loops, if any.
	// On Android, this means calling VpnService.protect(fd) to exempt it from fwmarks
	// that route it back into the TUN device operated by firestack.
	Protect(who string, fd int)
}

type Protector interface {
	// UIP returns ip (network-order byte) to bind given a local/remote ipp (ip:port).
	// (unused)
	UIP(ipp string) []byte
}
