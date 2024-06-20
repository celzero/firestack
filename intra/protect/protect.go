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

	b "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
)

// See: ipmap.LookupNetIP; UidSelf -> dnsx.Default; UidSystem -> dnsx.System
const (
	UidSelf   = b.UidSelf
	UidSystem = b.UidSystem
	Localhost = b.Localhost
)

// never resolve system/default resolver; expected to have seeded ips
func NeverResolve(hostname string) bool {
	return hostname == UidSelf || hostname == UidSystem
}

type Controller = b.Controller
type Protector = b.Protector

type ControlFn func(network, addr string, c syscall.RawConn) (err error)

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
				ctl.Bind6(who, addr, sock)
			case "tcp4", "udp4":
				ctl.Bind4(who, addr, sock)
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
	x := netdialer()
	if p != nil && core.IsNotNil(p) {
		x.Control = ipbind(p)
	}
	return x
}

// unused: Creates a listener that binds to a particular ip.
func MakeListenConfig(p Protector) *net.ListenConfig {
	x := netlistener()
	if p != nil && core.IsNotNil(p) {
		x.Control = ipbind(p)
	}
	return x
}

// Creates a net.Dialer that can bind to any active interface.
func MakeNsDialer(who string, c Controller) *net.Dialer {
	x := netdialer()
	if c != nil && core.IsNotNil(c) {
		x.Control = ifbind(who, c)
	}
	return x
}

// Creates a RDial that can bind to any active interface.
func MakeNsRDial(who string, c Controller) *RDial {
	return &RDial{
		Owner:  who,
		Dialer: MakeNsDialer(who, c),
		Listen: MakeNsListener(who, c),
	}
}

// Creates a listener that can bind to any active interface.
func MakeNsListener(who string, c Controller) *net.ListenConfig {
	x := netlistener()
	if c != nil && core.IsNotNil(c) {
		x.Control = ifbind(who, c)
	}
	return x
}

// Creates a listener that can bind to any active interface, with additional control fns.
func MakeNsListenConfigExt(who string, ctl Controller, ext []ControlFn) *net.ListenConfig {
	x := netlistener()
	x.Control = func(network, address string, c syscall.RawConn) error {
		for _, fn := range ext { // must do prior to ctl.bind
			if err := fn(network, address, c); err != nil {
				return err
			}
		}
		if ctl != nil && core.IsNotNil(ctl) {
			if err := ifbind(who, ctl)(network, address, c); err != nil {
				return err
			}
		}
		return nil
	}
	return x
}

// Creates a plain old dialer
func netdialer() *net.Dialer {
	return &net.Dialer{}
}

// Creates a plain old listener
func netlistener() *net.ListenConfig {
	return &net.ListenConfig{}
}
