// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package wg

import (
	"net/netip"
	"strings"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/split"
)

// Multihost is a list of hostnames and/or ip addresses for one endpoint.
type Multihost struct {
	names []string
	addrs []netip.Addr
}

func (h *Multihost) Names() []string {
	return h.names
}

func (h *Multihost) Addrs() []netip.Addr {
	return h.addrs
}

func (h *Multihost) Len() int {
	// names may exist without addrs and vice versa
	return max(len(h.addrs), len(h.names))
}

func (h *Multihost) addrlen() int {
	return len(h.addrs)
}

func (h *Multihost) Refresh() int {
	h.With(h.names)
	return h.Len()
}

func (h *Multihost) With(domainsOrIps []string) {
	h.names = make([]string, 0)
	h.addrs = make([]netip.Addr, 0)
	for _, dip := range domainsOrIps {
		dip = strings.TrimSpace(dip)                     // hostname or ip
		if ip, err := netip.ParseAddr(dip); err != nil { // may be hostname
			h.names = append(h.names, dip) // add hostname regardless of resolution
			if resolvedips := split.For(dip); len(resolvedips) > 0 {
				h.addrs = append(h.addrs, resolvedips...)
			} else {
				log.W("proxy: wg: multihost: no ips for %q", dip)
			}
		} else { // may be ip
			h.addrs = append(h.addrs, ip)
		}
	}
}

func (h *Multihost) EqualAddrs(other *Multihost) bool {
	if (other == nil) || (h.addrlen() != other.addrlen()) {
		return false
	}
	for _, me := range h.addrs {
		var ok bool
		for _, them := range other.addrs {
			if me.Compare(them) == 0 {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}
