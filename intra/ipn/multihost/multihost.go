// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package multihost

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/log"
)

var errNoIps error = errors.New("multihost: no ips")

var zeroaddr = netip.AddrPort{}

// MH is a list of hostnames and/or ip addresses for one endpoint.
type MH struct {
	sync.RWMutex // protects names and addrs
	id           string
	names        []string         // host:port
	addrs        []netip.AddrPort // ip:port
}

// New returns a new multihost with the given id.
func New(id string) *MH {
	return &MH{
		id:    id,
		names: make([]string, 0),
		addrs: make([]netip.AddrPort, 0),
	}
}

func (h *MH) String() string {
	return h.id + ":" + strings.Join(h.straddrs(), ",")
}

func (h *MH) straddrs() []string {
	a := make([]string, 0)
	for _, ip := range h.Addrs() {
		if ip.Addr().IsUnspecified() || !ip.IsValid() {
			continue
		}
		a = append(a, ip.String())
	}
	return a
}

// Names returns the list of hostnames or host:ports.
func (h *MH) Names() []string {
	h.Lock()
	defer h.Unlock()

	return h.names // todo: return a copy
}

// Returns ip:port, where ports may be 0.
func (h *MH) Addrs() []netip.AddrPort {
	h.RLock()
	defer h.RUnlock()

	return h.addrs // todo: return a copy
}

func (h *MH) splitFamily() (out4, out6, og []netip.AddrPort) {
	out4 = make([]netip.AddrPort, 0)
	out6 = make([]netip.AddrPort, 0)
	og = h.Addrs()

	for _, ip := range og {
		if ip.Addr().IsUnspecified() || !ip.IsValid() {
			continue
		}
		if ip.Addr().Is4() {
			out4 = append(out4, ip)
		} else if ip.Addr().Is6() {
			out6 = append(out6, ip)
		}
	}
	return
}

// PreferredAddrs returns the list of IPs per the dialer's preference.
func (h *MH) PreferredAddrs() []netip.AddrPort {
	out4, out6, og := h.splitFamily()

	out := make([]netip.AddrPort, 0)
	if dialers.Use4() {
		out = append(out, out4...)
	}
	if dialers.Use6() { // ipv4 addrs followed by ipv6
		out = append(out, out6...)
	}
	if len(out) <= 0 { // fail open
		return append(out, og...)
	}
	return out
}

// prefers v4; see: github.com/WireGuard/wireguard-android/blob/4ba87947a/tunnel/src/main/java/com/wireguard/config/InetEndpoint.java#L97
func (h *MH) PreferredAddr() netip.AddrPort {
	out6 := zeroaddr
	has4Or46 := dialers.Use4()
	has6Or46 := dialers.Use6()
	hasOnly6 := has6Or46 && !has4Or46

	for _, ip := range h.Addrs() {
		if ip.Addr().IsUnspecified() || !ip.IsValid() {
			continue
		}
		if ip.Addr().Is4() && has4Or46 {
			return ip // the first v4 addr
		}
		if ip.Addr().Is6() {
			if hasOnly6 {
				return ip // the first v6 addr
			}
			if has6Or46 && !out6.IsValid() {
				out6 = ip // note the first valid v6 addr
			}
		}
	}
	return out6 // may be zero addr or unspecified
}

func (h *MH) Len() int {
	if h == nil {
		return 0
	}

	h.RLock()
	defer h.RUnlock()
	// names may exist without addrs and vice versa
	return max(len(h.addrs), len(h.names))
}

func (h *MH) addrlen() int {
	h.RLock()
	defer h.RUnlock()

	return len(h.addrs)
}

// Refresh re-adds the list of IPs, hostnames, and re-resolves the hostname.
// It returns the total number of IPs.
func (h *MH) Refresh() int {
	if h == nil {
		log.W("multihost: refresh: nil")
		return 0
	}
	// resolve ip from domain names (auto removes dups)
	return h.Add(h.Names())
}

// Add appends the list of IPs, hostnames, and hostname's IPs as resolved.
// It returns the total number of IPs.
// Removes duplicates.
func (h *MH) Add(domainsOrIps []string) int {
	id := h.id
	if len(domainsOrIps) <= 0 {
		log.D("multihost: %s add: no domains or ips; existing n? %d", id, h.Len())
		return 0
	}

	names, addrs := resolv(id, domainsOrIps)

	h.Lock()
	defer h.Unlock()
	h.names = append(h.names, names...)
	h.addrs = append(h.addrs, addrs...)
	// remove dups from h.addrs and h.names
	h.uniqIPLocked()
	h.uniqAddrsLocked()
	log.D("multihost: %s with %s => %s", h.id, h.names, h.addrs)
	return len(h.addrs)
}

func resolv(id string, domainsOrIps []string) ([]string, []netip.AddrPort) {
	names := make([]string, 0)
	addrs := make([]netip.AddrPort, 0)
	for _, ep := range domainsOrIps {
		// ep is host or ip or host:port or ip:port
		dip, port := normalize(ep) // port may be 0
		if len(dip) <= 0 {
			log.D("multihost: %s add, skipping: %s:%d", id, dip, port)
			continue
		}
		if ip, err := netip.ParseAddr(dip); err != nil { // may be hostname
			names = append(names, ep) // add hostname regardless of resolution
			log.D("multihost: %s resolving: %q", id, ep)
			if resolvedips, err := dialers.Resolve(dip); err == nil && len(resolvedips) > 0 {
				eps := addrport(port, resolvedips...)
				addrs = append(addrs, eps...)
				log.V("multihost: %s resolved: %q => %s", id, dip, eps)
			} else {
				if err == nil { // err may be nil even on zero answers
					err = errNoIps
				}
				log.W("multihost: %s no ips for %q; err? %v", id, dip, err)
			}
		} else { // may be ip
			addrs = append(addrs, addrport(port, ip)...)
		}
	}
	return names, addrs
}

// dip can be host or ip or host:port or ip:port
func normalize(dip string) (string, uint16) {
	dip = strings.TrimSpace(dip)
	if hostOrIP, portstr, err := net.SplitHostPort(dip); err == nil {
		port, err := strconv.Atoi(portstr)
		if err != nil {
			log.D("multihost: normalize(%s), no port; err: %v", dip, err)
			port = 0
		}
		return hostOrIP, uint16(port)
	}
	return dip, 0
}

// 0 port is valid
func addrport(port uint16, ips ...netip.Addr) []netip.AddrPort {
	a := make([]netip.AddrPort, 0, len(ips))
	for _, ip := range ips {
		a = append(a, netip.AddrPortFrom(ip, port))
	}
	return a
}

func (h *MH) EqualAddrs(other *MH) bool {
	const eq = true
	const noteq = false
	if h == nil && other == nil {
		return eq
	}
	if h == nil || other == nil {
		return noteq
	}

	us := h.Addrs()
	them := other.Addrs()
	if len(us) != len(them) {
		return noteq
	}

	for _, me := range us {
		var found bool
		for _, you := range them {
			if me.Compare(you) == 0 {
				found = true
				break
			}
		}
		if !found {
			return noteq
		}
	}
	return eq
}

func (h *MH) uniqAddrsLocked() {
	h.names = removeDups(h.names)
}

func (h *MH) uniqIPLocked() {
	h.addrs = removeDups(h.addrs)
}

// go.dev/play/p/WJXpAa-nmep
func removeDups[T comparable](a []T) []T {
	if len(a) <= 0 {
		return a
	}
	acc := make(map[T]struct{}, len(a))
	for _, s := range a {
		acc[s] = struct{}{}
	}
	uniq := make([]T, 0, len(acc))
	for s := range acc {
		uniq = append(uniq, s)
	}
	return uniq
}
