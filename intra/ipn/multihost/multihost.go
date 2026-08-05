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
	errNoIps       = errors.New("multihost: no ips")
	errMhNotFound  = errors.New("multihost: not found")
	errInvalidPort = errors.New("multihost: invalid port")
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
	sync.RWMutex // protects names, addrs, and mtime

	o           string           // owner tag
	names       []string         // host:port
	addrs       []netip.AddrPort // ip:port; resolved from hostnames
	preresolved []netip.AddrPort // ip:port; pre-resolved
	mtime       time.Time        // modified time

	resolvMu sync.Mutex // serializes all name resolutions (sync and background)
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
	return h.o + "[" + strings.Join(h.Names(), ",") +
		" | " + strings.Join(h.straddrs(), ",") + "]" +
		" @ " + core.FmtTimeAsPeriod(h.Mtime())
}

func (h *MH) Mtime() time.Time {
	if h == nil {
		return time.Time{}
	}
	h.RLock()
	defer h.RUnlock()
	return h.mtime
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

// Names returns a copy of the list of hostnames or host:ports.
func (h *MH) Names() []string {
	if h == nil {
		return nil
	}
	h.RLock()
	defer h.RUnlock()
	// Return a copy to prevent external modification
	return slices.Clone(h.names)
}

// Returns ip:port, where ports may be 0.
func (h *MH) Addrs() []netip.AddrPort {
	if h == nil {
		return nil
	}
	h.RLock()
	defer h.RUnlock()

	return slices.Concat(h.addrs, h.preresolved)
}

// Has returns true if the given ip matches any address in this multihost.
func (h *MH) Has(ip string) bool {
	if h == nil {
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return h.HasAddr(addr)
}

// HasAddr returns true if the given addr matches any address in this multihost.
func (h *MH) HasAddr(addr netip.Addr) bool {
	if h == nil || !addr.IsValid() {
		return false
	}
	h.RLock()
	defer h.RUnlock()
	for _, a := range h.addrs {
		if a.Addr() == addr {
			return true
		}
	}
	for _, a := range h.preresolved {
		if a.Addr() == addr {
			return true
		}
	}
	return false
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
		// Note: IsLoopback, IsLinkLocalUnicast, etc. addresses are still included
		// Consider if these should be filtered based on use case
	}
	return
}

// PreferredAddrs returns the list of IPs per the dialer's preference.
func (h *MH) PreferredAddrs() []netip.AddrPort {
	if h == nil {
		return nil
	}

	out4, out6, og := h.splitFamily()

	out := make([]netip.AddrPort, 0, len(og))
	if dialers.Use4() {
		out = append(out, out4...)
	}
	if dialers.Use6() { // ipv4 addrs followed by ipv6
		out = append(out, out6...)
	}
	if len(out) <= 0 { // fail open
		return slices.Clone(og) // Return copy to prevent modification
	}
	return out
}

// PreferredAddrs returns the list of IPs per the dialer's preference.
func (h *MH) PreferredAddr2() (ip4, ip6 netip.AddrPort) {
	if h == nil {
		return zeroaddr, zeroaddr
	}

	out4, out6, _ := h.splitFamily()
	if len(out4) > 0 {
		ip4 = out4[0]
	}
	if len(out6) > 0 {
		ip6 = out6[0]
	}
	return
}

// prefers v4; see: github.com/WireGuard/wireguard-android/blob/4ba87947a/tunnel/src/main/java/com/wireguard/config/InetEndpoint.java#L97
func (h *MH) PreferredAddr() netip.AddrPort {
	if h == nil {
		log.W("multihost: PreferredAddr: nil multihost")
		return zeroaddr
	}

	addrs := h.Addrs()
	if len(addrs) == 0 {
		log.W("multihost: %s: no addresses available", h.o)
		return zeroaddr
	}

	out6 := zeroaddr
	fallback4 := zeroaddr
	fallback6 := zeroaddr
	has4Or46 := dialers.Use4()
	has6Or46 := dialers.Use6()
	hasOnly6 := has6Or46 && !has4Or46

	for _, ip := range addrs {
		if ip.Addr().IsUnspecified() || !ip.IsValid() {
			continue
		}
		if ip.Addr().Is4() && has4Or46 {
			return ip // the first v4 addr
		} else if ip.Addr().Is4() && !fallback4.IsValid() {
			fallback4 = ip // note the first valid v4 addr
		}
		if ip.Addr().Is6() {
			if hasOnly6 {
				return ip // the first v6 addr
			}
			if has6Or46 && !out6.IsValid() {
				out6 = ip // note the first valid v6 addr
			} else if !fallback6.IsValid() {
				fallback6 = ip // note the first valid v6 addr
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

// Build triggers resolution of hostnames to IPs.
// If addresses already exist for this multihost, hostnames are resolved in the
// background (non-blocking) and the current number of addresses is returned.
// Otherwise, hostnames are resolved synchronously so that the caller gets
// usable addresses, and the new number of addresses is returned.
func (h *MH) Build() int {
	if h == nil {
		log.W("multihost: build: nil")
		return -1
	}

	h.Lock()
	names := h.names
	pre := h.preresolved
	addrs := h.addrs
	h.Unlock()

	if len(names) <= 0 {
		return h.Len() // nothing to resolve
	}

	if len(addrs) > 0 || len(pre) > 0 {
		// addrs already exist: resolve in the background
		h.resolveAsync(names)
		return len(addrs) + len(pre)
	}
	return h.addAndResolve(names, Append) // no addrs: resolve synchronously
}

// resolveAsync resolves the given names in a background goroutine, appending
// the resolved ip:ports. At most one resolution runs at a time: resolutions
// are serialized on resolvMu (see addInternal), so a newer resolution waits
// for any in-flight one to finish instead of being dropped.
func (h *MH) resolveAsync(names []string) {
	if h == nil || len(names) <= 0 {
		return
	}
	core.Go("mh.resolve."+h.o, func() {
		h.addAndResolve(names, Append) // addInternal logs the outcome
	})
}

// Refresh resets the list of IPs and re-resolves the hostnames synchronously.
// It returns the total number of IPs, or -1 on error.
func (h *MH) Refresh() int {
	if h == nil {
		log.W("multihost: refresh: nil")
		return -1
	}
	if names := h.Names(); len(names) > 0 {
		// reset all ips; resolve from names
		return h.addAndResolve(names, Reset)
	} // nothing to refreshPP
	return h.Len()
}

// SoftRefresh appends to the list of IPs by re-resolving the hostnames in the
// background (non-blocking), but only if they are stale. It returns the total
// number of IPs, or -1 on error.
func (h *MH) SoftRefresh() int {
	if h == nil {
		log.W("multihost: soft refresh: nil")
		return -1
	}

	if names, stale := h.stale(); len(names) > 0 && stale {
		// resolve ip from domain names in the background (auto removes dups)
		h.resolveAsync(names)
	}
	return h.Len()
}

func (h *MH) stale() ([]string, bool) {
	if h == nil {
		return nil, false
	}
	h.RLock()
	thres := h.mtime.Add(refreshInterval)
	names := slices.Clone(h.names) // Return copy
	h.RUnlock()
	return names, time.Since(thres) > 0
}

// Add parses and appends the given domains or ips to the existing list of
// hostnames and pre-resolved IPs. Hostnames are not resolved; use Build,
// Refresh, or SoftRefresh to trigger resolution.
func (h *MH) Add(domainsOrIps []string) int {
	return h.add(domainsOrIps, Append)
}

// Set parses and replaces the existing list of hostnames and pre-resolved IPs
// with the given domains or ips. Hostnames are not resolved; use Build,
// Refresh, or SoftRefresh to trigger resolution.
func (h *MH) Set(domainsOrIps []string) int {
	return h.add(domainsOrIps, Reset)
}

// add parses and stores the given domains or ips (Append or Reset) without
// resolving any hostnames; it returns the total number of addresses.
func (h *MH) add(domainsOrIps []string, op MHAddOp) int {
	return h.addInternal(domainsOrIps, op, false /*doResolve*/)
}

// addAndResolve parses, stores, and synchronously resolves the given domains
// or ips (Append or Reset); it returns the total number of addresses.
// All name resolutions, synchronous (Build, Refresh) and background
// (resolveAsync), are serialized on resolvMu (taken in addInternal), so that
// a reset never interleaves with a background append and duplicate concurrent
// lookups are avoided.
func (h *MH) addAndResolve(domainsOrIps []string, op MHAddOp) int {
	return h.addInternal(domainsOrIps, op, true /*doResolve*/)
}

// addInternal parses the given domains or ips, stores them (Append or Reset),
// and resolves hostnames if doResolve is true; it returns the total number of
// addresses. If doResolve is false, hostnames are only stored as names.
// When doResolve is true, resolution and the store phase are serialized on
// resolvMu.
func (h *MH) addInternal(domainsOrIps []string, op MHAddOp, doResolve bool) int {
	if h == nil {
		log.E("multihost: add: nil multihost")
		return -1
	}

	id := h.o
	if len(domainsOrIps) <= 0 {
		log.D("multihost: %s add: no domains or ips; existing n? %d", id, h.Len())
		return 0
	}

	names, pre, err := parse(id, domainsOrIps)
	if err != nil { // errs are okay
		log.W("multihost: %s add: parse errs: %v", id, err)
	}

	var addrs []netip.AddrPort
	if doResolve && len(names) > 0 {
		// hold resolvMu until the store phase below completes, so that a
		// reset (Refresh) never interleaves with a background append
		// (resolveAsync); parse-only Add/Set never reach here
		h.resolvMu.Lock()
		defer h.resolvMu.Unlock()
		if addrs, err = resolvNames(id, names); err != nil { // errs are okay
			log.W("multihost: %s add: resolution errs: %v", id, err)
		}
	}

	h.Lock()
	defer h.Unlock()

	if op == Reset {
		if doResolve {
			// re-resolve (refresh): preserve non-empty components;
			// fail-open: keep old addrs if re-resolution yields none
			if len(names) > 0 {
				h.names = names
			}
			if len(addrs) > 0 {
				h.addrs = addrs
			}
			if len(pre) > 0 {
				h.preresolved = pre
			}
		} else {
			// parse-only reset (set): replace the whole endpoint list;
			// previously resolved addrs belong to the old names; drop them
			h.names = names
			h.preresolved = pre
			h.addrs = h.addrs[:0]
		}
	} else if op == Append {
		h.names = append(h.names, names...)
		h.addrs = append(h.addrs, addrs...)
		h.preresolved = append(h.preresolved, pre...)
	} else {
		log.E("multihost: %s add: %v => %v [+ %v]; unknown op %d", id, names, addrs, pre, op)
		return -1
	}

	h.mtime = time.Now()
	// remove dups from h.addrs, h.preresolved, and h.names
	h.uniqAddrsLocked()
	h.uniqPreLocked()
	h.uniqNamesLocked()
	log.D("multihost: %s add: op %s; names: %v (new: %v) => resolved: %v (new: %v) + pre: %v (new: %v)",
		h.o, op, h.names, names, h.addrs, addrs, h.preresolved, pre)
	return len(h.addrs) + len(h.preresolved)
}

// parse parses the given domains or ips and returns the hostnames (as-is) and
// the pre-resolved ip:ports. It performs no network resolution. Callers may
// ignore err if they are okay with some domains or ips being unusable.
func parse(id string, domainsOrIps []string) (names []string, pre []netip.AddrPort, err error) {
	names = make([]string, 0, len(domainsOrIps))
	pre = make([]netip.AddrPort, 0)
	var errs []error

	for _, ep := range domainsOrIps {
		// ep is host or ip or host:port or ip:port
		dip, port, parseErr := normalize(ep) // port may be 0
		if parseErr != nil {
			log.W("multihost: %s failed to parse endpoint %s: %v", id, ep, parseErr)
			errs = append(errs, parseErr)
			continue
		}
		if len(dip) <= 0 {
			log.D("multihost: %s add, skipping empty host: %s:%d", id, dip, port)
			continue
		}
		if ip, parseIPErr := netip.ParseAddr(dip); parseIPErr != nil { // may be hostname
			names = append(names, ep) // add hostname regardless of resolution success
		} else if !ip.IsValid() { // may be ip; validate before adding
			log.W("multihost: %s invalid IP: %s", id, dip)
			errs = append(errs, core.OneErr(errInvalidPort, nil))
		} else {
			pre = append(pre, addrport(port, ip)...)
		}
	}

	err = core.JoinErr(errs...)
	return
}

// resolvNames resolves the given hostnames (host or host:port) to ip:ports.
// Ports from the input, which may be 0, are carried over to the ip:ports.
// Callers may ignore err if they are okay with some hostnames not resolving.
func resolvNames(id string, names []string) (addrs []netip.AddrPort, err error) {
	addrs = make([]netip.AddrPort, 0)
	var errs []error

	for _, ep := range names {
		// ep is host or host:port
		dip, port, parseErr := normalize(ep) // port may be 0
		if parseErr != nil {
			log.W("multihost: %s failed to parse endpoint %s: %v", id, ep, parseErr)
			errs = append(errs, parseErr)
			continue
		}
		if len(dip) <= 0 {
			continue
		}
		if ip, parseIPErr := netip.ParseAddr(dip); parseIPErr == nil { // already an ip
			if ip.IsValid() {
				addrs = append(addrs, addrport(port, ip)...)
			}
			continue
		}
		log.D("multihost: %s resolving: %q", id, ep)
		// TODO: use dialers.Resolve(dip, tid) with tid set to via, if any
		if resolvedips, resolveErr := dialers.Resolve(dip); resolveErr == nil && len(resolvedips) > 0 {
			reps := addrport(port, resolvedips...)
			addrs = append(addrs, reps...)
			log.V("multihost: %s resolved: %q => %s", id, dip, reps)
		} else {
			// err may be nil even on zero answers
			resolveErr = core.OneErr(resolveErr, errNoIps)
			log.W("multihost: %s no ips for %q; err? %v", id, dip, resolveErr)
			errs = append(errs, resolveErr)
		}
	}

	err = core.JoinErr(errs...)
	return
}

// dip can be host or ip or host:port or ip:port
func normalize(dip string) (string, uint16, error) {
	dip = strings.TrimSpace(dip)
	if len(dip) <= 0 {
		return "", 0, errNoIps
	}
	if hostOrIP, portstr, err := net.SplitHostPort(dip); err == nil {
		port, err := strconv.ParseUint(portstr, 10, 16)
		if err != nil {
			log.D("multihost: normalize(%s), invalid port; err: %v", dip, err)
			return "", 0, core.OneErr(errInvalidPort, err)
		}
		if port > 65535 {
			return "", 0, errInvalidPort
		}
		return hostOrIP, uint16(port), nil
	}
	return dip, 0, nil
}

// 0 port is valid
func addrport(port uint16, ips ...netip.Addr) []netip.AddrPort {
	if len(ips) == 0 {
		return nil
	}
	a := make([]netip.AddrPort, 0, len(ips))
	for _, ip := range ips {
		if !ip.IsValid() {
			log.D("multihost: addrport: skipping invalid IP: %s", ip)
			continue
		}
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

	// when addrs (resolved from hostnames) are empty on either side, compare
	// hostnames and pre-resolved ips instead, so that equality is meaningful
	// even before resolution
	if !h.hasResolved() || !other.hasResolved() {
		return h.equalNamesAndPreresolved(other)
	}

	netipCmpFn := func(a, b netip.AddrPort) int {
		return a.Compare(b)
	}

	us := core.CopyUniq(h.Addrs())
	them := core.Sort(core.CopyUniq(other.Addrs()), netipCmpFn)

	if len(us) != len(them) {
		return noteq
	}

	for _, u := range us {
		_, found := slices.BinarySearchFunc(them, u, netipCmpFn)
		if !found {
			log.D("multihost: %s != %s; missing %s", h.o, other.o, u)
			return noteq
		}
	}
	log.V("multihost: %s == %s", h.o, other.o)
	return eq
}

// hasResolved returns true if any addr has been resolved from a hostname.
func (h *MH) hasResolved() bool {
	h.RLock()
	defer h.RUnlock()
	return len(h.addrs) > 0
}

// equalNamesAndPreresolved returns true if both have the same set of hostnames and
// pre-resolved ip:ports; used when addrs are not yet resolved.
func (h *MH) equalNamesAndPreresolved(other *MH) bool {
	const eq = true
	const noteq = false
	if h == nil && other == nil {
		return eq
	}
	if h == nil || other == nil {
		return noteq
	}

	hNames, hPre := h.cloneNamesAndPresolved()
	oNames, oPre := other.cloneNamesAndPresolved()

	// names and pre-resolved ips are deduped per-MH; sort the copies so that
	// order-sensitive slices.Equal implements set equality
	slices.Sort(hNames)
	slices.Sort(oNames)
	if !slices.Equal(hNames, oNames) {
		log.D("multihost: %s != %s; names differ; %v != %v", h.o, other.o, hNames, oNames)
		return noteq
	}

	netipCmpFn := func(a, b netip.AddrPort) int {
		return a.Compare(b)
	}
	hPre = core.Sort(core.CopyUniq(hPre), netipCmpFn)
	oPre = core.Sort(core.CopyUniq(oPre), netipCmpFn)
	if !slices.Equal(hPre, oPre) {
		log.D("multihost: %s != %s; pre-resolved differ; %v != %v", h.o, other.o, hPre, oPre)
		return noteq
	}
	log.V("multihost: %s == %s", h.o, other.o)
	return eq
}

// cloneNamesAndPresolved returns copies of the hostnames and pre-resolved ip:ports.
func (h *MH) cloneNamesAndPresolved() ([]string, []netip.AddrPort) {
	h.RLock()
	defer h.RUnlock()
	return slices.Clone(h.names), slices.Clone(h.preresolved)
}

func (h *MH) uniqNamesLocked() {
	if h == nil {
		return
	}
	h.names = core.CopyUniq(h.names)
}

func (h *MH) uniqAddrsLocked() {
	if h == nil {
		return
	}
	h.addrs = core.CopyUniq(h.addrs)
}

func (h *MH) uniqPreLocked() {
	if h == nil {
		return
	}
	h.preresolved = core.CopyUniq(h.preresolved)
}

func logeif(cond bool) log.LogFn {
	if cond {
		return log.E
	}
	return log.D
}
