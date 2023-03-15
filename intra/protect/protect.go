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
	"github.com/txthinking/x"
)

// Blocker provides answers to filter network traffic.
type Blocker interface {
	// Block is called on a new connection setup; return true to block the connection;
	// false otherwise.
	// source and target are string'd representation of net.TCPAddr and net.UDPAddr
	// depending on the protocol. Note: IPv4 and IPv6 have very different string
	// representations: stackoverflow.com/a/48519490
	// uid is -1 in case owner-uid of the connection couldn't be determined
	// todo: returns a string "rdnsblockstamp,proxyid" instead of bool
	// where, rdnsblockstamp can be "", or "1:b64-blockstamp"
	// and, proxyid can be "allow", "block", or "proxyid"
	Block(protocol int32, uid int, source string, target string) bool
	// BlockAlg is called on a new ALG connection setup; return true to block the connection;
	// false otherwise.
	BlockAlg(p int32, uid int, src string, dst string, realips, domains, blocklists string) bool
	// Flow is called on a new connection setup; return "proxyid,connid" to forward the connection
	// to a pre-registered proxy; "Base" to allow the connection; "Block" to block the connection.
	// "connid" is used to uniquely identify a connection across all proxies, and a summary of the
	// connection is sent back to a pre-registered listener.
	// protocol is 6 for TCP, 17 for UDP, 1 for ICMP.
	// uid is -1 in case owner-uid of the connection couldn't be determined.
	// src and dst are string'd representation of net.TCPAddr and net.UDPAddr.
	// origdsts is a comma-separated list of original source IPs, this may be same as dst.
	// domains is a comma-separated list of domain names associated with origsrcs, if any.
	// blocklists is a comma-separated list of blocklist names, if any.
	Flow(protocol int32, uid int, src string, dst string, origdsts, domains, blocklists string) string
	// Calls in to javaland asking it to bind fd to any internet-capable IPv4 interface.
	Bind4(fd int)
	// Calls in to javaland asking it to bind fd to any internet-capable IPv6 interface.
	// also: github.com/lwip-tcpip/lwip/blob/239918c/src/core/ipv6/ip6.c#L68
	Bind6(fd int)
}

type Protector interface {
	// Returns ip to bind given a network, n
	UIP(n string) []byte
}

func networkBinder(b Blocker) func(string, string, syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) (err error) {
		return c.Control(func(fd uintptr) {
			sock := int(fd)
			switch network {
			case "tcp6":
				fallthrough
			case "udp6":
				b.Bind6(sock)
			case "tcp4":
				fallthrough
			case "udp4":
				fallthrough
			case "tcp":
				fallthrough
			case "udp":
				b.Bind4(sock)
			default:
				// no-op
			}
		})
	}
}

func ipBinder(p Protector) func(string, string, syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) (err error) {
		src := p.UIP(network)
		ipaddr, _ := netip.AddrFromSlice(src)
		origaddr, err := netip.ParseAddrPort(address)
		log.W("control: net(%s), orig(%s/%w), bind(%s)", network, origaddr, err, ipaddr)
		if err != nil {
			return err
		}
		return c.Control(func(fd uintptr) {
			if origaddr.Addr().IsUnspecified() {
				return
			}
			port := int(origaddr.Port())
			switch network {
			case "tcp6":
				fallthrough
			case "udp6":
				// TODO: zone := origaddr.Addr().Zone()
				bind6 := &syscall.SockaddrInet6{Addr: ipaddr.As16(), Port: port}
				err = syscall.Bind(int(fd), bind6)
			default:
				bind4 := &syscall.SockaddrInet4{Addr: ipaddr.As4(), Port: port}
				err = syscall.Bind(int(fd), bind4)
			}
			if err != nil {
				log.E("protect: fail to bind ip(%s) to socket %v", ipaddr, err)
			}
		})
	}
}

// Creates a dialer that binds to a particular ip.
func MakeDialer(p Protector) *net.Dialer {
	if p == nil {
		return MakeDefaultDialer()
	}
	d := &net.Dialer{
		Control: ipBinder(p),
	}
	return d
}

// Creates a listener that binds to a particular ip.
func MakeListenConfig(p Protector) *net.ListenConfig {
	if p == nil {
		return MakeDefaultListenConfig()
	}
	return &net.ListenConfig{
		Control: ipBinder(p),
	}
}

// Creates a dialer that can bind to any active interface.
func MakeNsDialer(b Blocker) *net.Dialer {
	if b == nil {
		return MakeDefaultDialer()
	}
	d := &net.Dialer{
		Control: networkBinder(b),
	}
	return d
}

// Creates a XDial that can bind to any active interface.
func MakeNsXDial(b Blocker) x.Dialer {
	if b != nil {
		d := &net.Dialer{
			Control: networkBinder(b),
		}
		return &XDial{
			Dialer: d,
		}
	} else {
		return &XDial{
			Dialer: MakeDefaultDialer(),
		}
	}
}

// Creates a listener that can bind to any active interface.
func MakeListenConfig2(b Blocker) *net.ListenConfig {
	if b == nil {
		return MakeDefaultListenConfig()
	}
	return &net.ListenConfig{
		Control: networkBinder(b),
	}
}

// Creates a plain old dialer
func MakeDefaultDialer() *net.Dialer {
	return &net.Dialer{}
}

// Creates a plain old listener
func MakeDefaultListenConfig() *net.ListenConfig {
	return &net.ListenConfig{}
}
