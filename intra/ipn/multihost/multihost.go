// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package multihost

import (
	"net/netip"
	"strings"

	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/log"
)

// nooplock is a no-op lock.
type nooplock struct{}

// MH is a list of hostnames and/or ip addresses for one endpoint.
type MH struct {
	nooplock // todo: replace with sync.RWMutex
	names    []string
	addrs    []netip.Addr
}

func (nooplock) Lock()    {}
func (nooplock) Unlock()  {}
func (nooplock) RLock()   {}
func (nooplock) RUnlock() {}

func (h *MH) String() string {
	return strings.Join(h.straddrs(), ",")
}

func (h *MH) straddrs() []string {
	a := make([]string, len(h.addrs))
	for _, ip := range h.addrs {
		a = append(a, ip.String())
	}
	return a
}

func (h *MH) Names() []string {
	return h.names
}

func (h *MH) Addrs() []netip.Addr {
	return h.addrs
}

func (h *MH) Len() int {
	// names may exist without addrs and vice versa
	return max(len(h.addrs), len(h.names))
}

func (h *MH) addrlen() int {
	return len(h.addrs)
}

func (h *MH) Refresh() int {
	totips := 0
	if len(h.names) > 0 { // resolve ip from domain names
		h.With(h.names)
		totips = len(h.addrs)
	}
	if totips <= 0 { // re-add existing ips, if any
		h.With(h.straddrs())
	}
	return len(h.addrs)
}

// Add appends the list of IPs, hostnames, and hostname's IPs as resolved.
func (h *MH) Add(domainsOrIps []string) int {
	if len(domainsOrIps) <= 0 {
		return 0
	}

	h.Lock()
	if h.names == nil {
		h.names = make([]string, 0)
	}
	if h.addrs == nil {
		h.addrs = make([]netip.Addr, 0)
	}
	for _, dip := range domainsOrIps {
		if len(dip) <= 0 {
			continue
		}
		dip = strings.TrimSpace(dip)                     // hostname or ip
		if ip, err := netip.ParseAddr(dip); err != nil { // may be hostname
			h.names = append(h.names, dip) // add hostname regardless of resolution
			if resolvedips := dialers.For(dip); len(resolvedips) > 0 {
				h.addrs = append(h.addrs, resolvedips...)
			} else {
				log.W("multihost: no ips for %q", dip)
			}
		} else { // may be ip
			h.addrs = append(h.addrs, ip)
		}
	}
	h.Unlock()

	log.D("multihost: with %s => %s", h.names, h.addrs)
	return h.Len()
}

// With sets the list of IPs, hostnames, and hostname's IPs as resolved.
func (h *MH) With(domainsOrIps []string) int {
	h.Lock()
	h.names = make([]string, 0)
	h.addrs = make([]netip.Addr, 0)
	h.Unlock()
	return h.Add(domainsOrIps)
}

func (h *MH) EqualAddrs(other *MH) bool {
	if (other == nil) || (h.addrlen() != other.addrlen()) {
		return false
	}

	h.RLock()
	defer h.RUnlock()
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
