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
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/log"
)

const refreshInterval time.Duration = 2 * time.Minute

var (
	errNoIps      = errors.New("multihost: no ips")
	errMhNotFound = errors.New("multihost: not found")
)

var zeroaddr = netip.AddrPort{}

type MHAddOp int

const (
	// Reset replaces the existing IPs with the new IPs.
	Reset MHAddOp = iota
	// Append appends the new IPs to the existing IPs.
	Append
)

func (op MHAddOp) String() string {
	switch op {
	case Reset:
		return "reset"
	case Append:
		return "append"
	default:
		return "unknown"
	}
}

// MH is a list of hostnames and/or ip addresses for one endpoint.
type MH struct {
	sync.RWMutex // protects names and addrs

	o           string           // owner tag
	names       []string         // host:port
	addrs       []netip.AddrPort // ip:port
	preresolved []netip.AddrPort // ip:port; pre-resolved
	mtime       time.Time        // modified time
}

// New returns a new multihost with the given id.
func New(id string) *MH {
	return &MH{
		o:           id,
		names:       make([]string, 0),
		addrs:       make([]netip.AddrPort, 0),
		preresolved: make([]netip.AddrPort, 0),
		mtime:       time.Now(),
	}
}

func (h *MH) String() string {
	if h == nil {
		return "<nil>"
	}
	return h.o + ":" + strings.Join(h.straddrs(), ",")
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
	// copying h.names is not required as strings are immutable
	return h.names
}

// Returns ip:port, where ports may be 0.
func (h *MH) Addrs() []netip.AddrPort {
	h.RLock()
	defer h.RUnlock()

	return slices.Concat(h.addrs, h.preresolved)
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
	fallback4 := zeroaddr
	fallback6 := zeroaddr
	has4Or46 := dialers.Use4()
	has6Or46 := dialers.Use6()
	hasOnly6 := has6Or46 && !has4Or46

	for _, ip := range h.Addrs() {
		if ip.Addr().IsUnspecified() || !ip.IsValid() {
			continue
		}
		if ip.Addr().Is4() && has4Or46 {
			return ip // the first v4 addr
		} else if !fallback4.IsValid() {
			fallback4 = ip // note the first valid addr
		}
		if ip.Addr().Is6() {
			if hasOnly6 {
				return ip // the first v6 addr
			}
			if has6Or46 && !out6.IsValid() {
				out6 = ip // note the first valid v6 addr
			} else if !fallback6.IsValid() {
				fallback6 = ip // note the first valid addr
			}
		}
	}

	if out6.IsValid() {
		return out6
	}

	log.W("multihost: %s: no preferred; v4(use? %t, fallback? %s), v6(use? %t, fallback? %s)",
		h.o, has4Or46, fallback4, has6Or46, fallback6)
	if fallback4.IsValid() {
		return fallback4
	}
	return fallback6 // may be zero addr or unspecified
}

func (h *MH) Len() int {
	if h == nil {
		return 0
	}

	h.RLock()
	defer h.RUnlock()
	// names may exist without addrs and vice versa
	return max(len(h.addrs)+len(h.preresolved), len(h.names))
}

// Refresh resets the list of IPs, hostnames, and re-resolves the hostname.
// It returns the total number of IPs.
func (h *MH) Refresh() int {
	if h == nil {
		log.W("multihost: refresh: nil")
		return -1
	}
	if names := h.Names(); len(names) > 0 {
		// reset all ips; resolve from names
		return h.Set(names)
	} // nothing to refresh
	return h.Len()
}

// SoftRefresh appends to the list of IPs, hostnames by re-resolving the hostname.
// It returns the total number of IPs.
func (h *MH) SoftRefresh() int {
	if h == nil {
		log.W("multihost: refresh: nil")
		return -1
	}

	if names, stale := h.stale(); len(names) > 0 && stale {
		// resolve ip from domain names (auto removes dups); then append
		return h.Add(names)
	}
	return h.Len()
}

func (h *MH) stale() ([]string, bool) {
	h.RLock()
	thres := h.mtime.Add(refreshInterval)
	names := h.names
	h.RUnlock()
	return names, time.Since(thres) > 0
}

// Add appends to the existing list of IPs, hostnames, and hostname's IPs if resolved.
func (h *MH) Add(domainsOrIps []string) int {
	return h.add(domainsOrIps, Append)
}

// Set replaces the existing list of IPs, hostnames, and hostname's IPs if resolved.
func (h *MH) Set(domainsOrIps []string) int {
	return h.add(domainsOrIps, Reset)
}

// Add appends the list of de-duplicated IPs, hostnames, and hostname's IPs as resolved.
// It returns the total number of IPs.
func (h *MH) add(domainsOrIps []string, op MHAddOp) int {
	id := h.o
	if len(domainsOrIps) <= 0 {
		log.D("multihost: %s add: no domains or ips; existing n? %d", id, h.Len())
		return 0
	}

	names, pre, addrs := resolv(id, domainsOrIps)

	h.Lock()
	defer h.Unlock()

	if op == Reset { // reset whatever is non-empty
		if len(names) > 0 {
			h.names = names
		}
		if len(addrs) > 0 {
			h.addrs = addrs
		}
		if len(pre) > 0 {
			h.preresolved = pre
		}
	} else if op == Append {
		h.names = append(h.names, names...)
		h.addrs = append(h.addrs, addrs...)
		h.preresolved = append(h.preresolved, pre...)
	} else {
		log.E("multihost: %s add: %v => %v [+ %v]; unknown op %d", id, names, addrs, pre, op)
		return 0
	}

	h.mtime = time.Now()
	// remove dups from h.addrs and h.names
	h.uniqAddrsLocked()
	h.uniqPreLocked()
	h.uniqNamesLocked()
	log.D("multihost: %s add: op %s; names: %v (new: %v) => resolved: %v (new: %v) + pre: %v (new: %v)",
		h.o, op, h.names, names, h.addrs, addrs, h.preresolved, pre)
	return len(h.addrs) + len(h.preresolved)
}

func resolv(id string, domainsOrIps []string) (names []string, pre []netip.AddrPort, addrs []netip.AddrPort) {
	names = make([]string, 0)
	pre = make([]netip.AddrPort, 0) // pre-resolved
	addrs = make([]netip.AddrPort, 0)
	for _, ep := range domainsOrIps {
		// ep is host or ip or host:port or ip:port
		dip, port := normalize(ep) // port may be 0
		if len(dip) <= 0 {
			log.D("multihost: %s add, skipping: %s:%d", id, dip, port)
			continue
		}
		if ip, err := netip.ParseAddr(dip); err != nil { // may be hostname
			names = append(names, ep) // add hostname regardless of resolution success
			log.D("multihost: %s resolving: %q", id, ep)
			if resolvedips, err := dialers.Resolve(dip); err == nil && len(resolvedips) > 0 {
				reps := addrport(port, resolvedips...)
				addrs = append(addrs, reps...)
				log.V("multihost: %s resolved: %q => %s", id, dip, reps)
			} else {
				// err may be nil even on zero answers
				err = core.OneErr(err, errNoIps)
				log.W("multihost: %s no ips for %q; err? %v", id, dip, err)
			}
		} else { // may be ip
			pre = append(pre, addrport(port, ip)...)
		}
	}
	return
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

func (h *MH) uniqNamesLocked() {
	h.names = core.CopyUniq(h.names)

}

func (h *MH) uniqAddrsLocked() {
	h.addrs = core.CopyUniq(h.addrs)
}

func (h *MH) uniqPreLocked() {
	h.preresolved = core.CopyUniq(h.preresolved)
}

func logeif(cond bool) log.LogFn {
	if cond {
		return log.E
	}
	return log.D
}
