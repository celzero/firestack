// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     Copyright 2019 The Outline Authors
//
//     Licensed under the Apache License, Version 2.0 (the "License");
//     you may not use this file except in compliance with the License.
//     You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
//     Unless required by applicable law or agreed to in writing, software
//     distributed under the License is distributed on an "AS IS" BASIS,
//     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//     See the License for the specific language governing permissions and
//     limitations under the License.

package protect

import (
	"net"
	"net/netip"
	"syscall"

	"github.com/celzero/firestack/intra/log"
)

const UidSelf = "rethink"

// Controller provides answers to filter network traffic.
type Controller interface {
	// Bind4 binds fd to any internet-capable IPv4 interface.
	Bind4(who string, fd int)
	// Bind6 binds fd to any internet-capable IPv6 interface.
	// also: github.com/lwip-tcpip/lwip/blob/239918c/src/core/ipv6/ip6.c#L68
	Bind6(who string, fd int)
	// Protect marks fd as protected.
	Protect(who string, fd int)
}

type Protector interface {
	// Returns ip to bind given a network, n
	UIP(n string) []byte
}

// returns true if addr is a global unicast address; and yn on error.
func maybeGlobalUnicast(addr string, yn bool) bool {
	if ipport, err := netip.ParseAddrPort(addr); err == nil {
		return ipport.Addr().IsGlobalUnicast()
	} else if ip, err := netip.ParseAddr(addr); err == nil {
		return ip.IsGlobalUnicast()
	} // ignore addr; it may be a wildcard or just hostname
	return yn
}

// Binds a socket to a particular network interface.
func ifbind(who string, ctl Controller) func(string, string, syscall.RawConn) error {
	return func(network, addr string, c syscall.RawConn) (err error) {
		// addr may be a wildcard aka ":<port>", in which case dst is a zero address.
		log.D("control: netbinder: %s: %s(%s); err? %v", who, network, addr, err)
		return c.Control(func(fd uintptr) {
			sock := int(fd)
			if !maybeGlobalUnicast(addr, true) {
				ctl.Protect(who, sock)
				return
			}
			switch network {
			case "tcp6", "udp6":
				ctl.Bind6(who, sock)
			case "tcp4", "udp4":
				ctl.Bind4(who, sock)
			case "tcp", "udp": // unexpected dual-stack socket
				fallthrough // Control usually qualifies protocol family for the fd
			default:
				ctl.Protect(who, sock)
			}
		})
	}
}

// unused: Binds a socket to a local ip.
func ipbind(p Protector) func(string, string, syscall.RawConn) error {
	return func(network, addr string, c syscall.RawConn) (err error) {
		src := p.UIP(network)
		ipaddr, _ := netip.AddrFromSlice(src)
		origaddr, perr := netip.ParseAddrPort(addr)
		log.D("control: ipbinder: %s(%s/%w), bindto(%s); err? %v", network, addr, origaddr, ipaddr, perr)

		if !maybeGlobalUnicast(addr, true) {
			// todo: protect fd?
			return nil
		}

		bind6 := func(fd uintptr) error {
			sc := &syscall.SockaddrInet6{Addr: ipaddr.As16()}
			return syscall.Bind(int(fd), sc)
		}
		bind4 := func(fd uintptr) error {
			sc := &syscall.SockaddrInet4{Addr: ipaddr.As4()}
			return syscall.Bind(int(fd), sc)
		}

		return c.Control(func(fd uintptr) {
			switch network {
			case "tcp6", "udp6":
				// TODO: zone := origaddr.Addr().Zone()
				err = bind6(fd)
			case "tcp4", "udp4":
				err = bind4(fd)
			case "tcp", "udp": // unexpected dual-stack socket?
				fallthrough // see: networkBinder
			default:
				// no-op
				// protect fd?
			}
			if err != nil {
				log.E("protect: fail to bind ip(%s) to socket %v", ipaddr, err)
			}
		})
	}
}

// unused: Creates a dialer that binds to a particular ip.
func MakeDialer(p Protector) *net.Dialer {
	if p == nil {
		return netdialer()
	}
	d := &net.Dialer{
		Control: ipbind(p),
	}
	return d
}

// unused: Creates a listener that binds to a particular ip.
func MakeListenConfig(p Protector) *net.ListenConfig {
	if p == nil {
		return netlistener()
	}
	return &net.ListenConfig{
		Control: ipbind(p),
	}
}

// Creates a net.Dialer that can bind to any active interface.
func MakeNsDialer(who string, c Controller) *net.Dialer {
	if c == nil {
		return netdialer()
	}
	d := &net.Dialer{
		Control: ifbind(who, c),
	}
	return d
}

// Creates a RDial that can bind to any active interface.
func MakeNsRDial(who string, c Controller) *RDial {
	return &RDial{
		Dialer: MakeNsDialer(who, c),
	}
}

// Creates a listener that can bind to any active interface.
func MakeNsListenConfig(who string, c Controller) *net.ListenConfig {
	if c == nil {
		return netlistener()
	}
	return &net.ListenConfig{
		Control: ifbind(who, c),
	}
}

// Creates a plain old dialer
func netdialer() *net.Dialer {
	return &net.Dialer{}
}

// Creates a plain old listener
func netlistener() *net.ListenConfig {
	return &net.ListenConfig{}
}
