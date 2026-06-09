// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Code relicensed from opensnitch with permissions from evilsocket.
package netstat

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
)

const (
	crlftabspace = "\r\n\t "
	cachettl     = 30000 // millis
)

var (
	parser = regexp.MustCompile(`(?i)` +
		`\d+:\s+` + // sl
		// source
		`([a-f0-9]{8,32}):([a-f0-9]{4})\s+` +
		// destination
		`([a-f0-9]{8,32}):([a-f0-9]{4})\s+` +
		`[a-f0-9]{2}\s+` + // st
		// transfer queue, receive queue
		`[a-f0-9]{8}:[a-f0-9]{8}\s+` +
		// tr tm->when
		`[a-f0-9]{2}:[a-f0-9]{8}\s+` +
		// retrnsmt
		`[a-f0-9]{8}\s+` +
		// uid
		`(\d+)\s+` +
		// timeout
		`\d+\s+` +
		// inode
		`(\d+)\s+` +
		// the rest...
		`.+`)

	cache = NewProcNetCache()

	zeroip4  = netip.IPv4Unspecified()
	zeroip6  = netip.IPv6Unspecified()
	zeroPort = 0
)

// ProcNetEntry represents a single line as fetched from /proc/net/*
type ProcNetEntry struct {
	Protocol string
	SrcIP    netip.Addr
	SrcPort  int
	DstIP    netip.Addr
	DstPort  int
	UserID   int
	INode    int
	ctime    time.Time
}

type ProcNetCache struct {
	pool        *sync.Map     // hash(ProcNetEntry.String()), *ProcNetEntry{}
	lastcleanup *atomic.Int64 // unix millis, accessed atomically
}

func NewProcNetCache() ProcNetCache {
	c := &atomic.Int64{}
	c.Store(time.Now().UnixMilli())
	return ProcNetCache{
		pool:        new(sync.Map),
		lastcleanup: c,
	}
}

// NewProcNetEntry creates an Entry
func NewProcNetEntry(protocol string, srcIP netip.Addr, srcPort int, dstIP netip.Addr, dstPort int, userID int, iNode int) ProcNetEntry {
	return ProcNetEntry{
		Protocol: protocol,
		SrcIP:    srcIP,
		SrcPort:  srcPort,
		DstIP:    dstIP,
		DstPort:  dstPort,
		UserID:   userID,
		INode:    iNode,
		ctime:    time.Now(),
	}
}

func (p *ProcNetEntry) String() string {
	return p.Protocol + p.SrcIP.String() + strconv.Itoa(p.SrcPort) + p.DstIP.String() + strconv.Itoa(p.DstPort)
}

// cacheKey returns the key used for pool lookups.
// Note: UID and INode are intentionally excluded because lookups
// are performed by 5-tuple (protocol, src, sport, dst, dport) —
// the whole purpose is to discover UID/INode from the 5-tuple.
// When two /proc/net entries share the same 5-tuple (e.g. SO_REUSEPORT
// UDP sockets), the first entry parsed wins.
func (p *ProcNetEntry) cacheKey() uint64 {
	return core.HashStr(p.String())
}

func (p *ProcNetEntry) Same(q *ProcNetEntry) bool {
	if p == nil || q == nil {
		return false
	}

	if p.Protocol != q.Protocol {
		return false
	}

	// unmap: github.com/golang/go/issues/53607
	src1 := p.SrcIP.Unmap()
	src2 := q.SrcIP.Unmap()
	dst1 := p.DstIP.Unmap()
	dst2 := q.DstIP.Unmap()

	if src1.Is6() != src2.Is6() {
		return false
	}
	if dst1.Is6() != dst2.Is6() {
		return false
	}

	zeroip := zeroip4
	if src1.Is6() {
		zeroip = zeroip6
	}

	// Skip IP comparison only if ONE side is unspecified (listening socket).
	// If BOTH are unspecified, they're different listeners and should not match.
	// github.com/M66B/NetGuard/blob/1fe3a04ae/app/src/main/jni/netguard/ip.c#L393
	skipSrcIP := false
	skipDstIP := false
	skipDstPort := false
	src1Zero := zeroip.Compare(src1) == 0
	src2Zero := zeroip.Compare(src2) == 0
	dst1Zero := zeroip.Compare(dst1) == 0
	dst2Zero := zeroip.Compare(dst2) == 0

	if src1Zero != src2Zero {
		// Exactly one is zero (e.g., listening socket vs established connection)
		skipSrcIP = true
	}
	if dst1Zero != dst2Zero {
		skipDstIP = true
	}
	// Skip dst port comparison only if the query has port 0 (wildcard lookup)
	// Don't skip if both have port 0 - that's not a valid match
	if zeroPort == p.DstPort && zeroPort != q.DstPort {
		skipDstPort = true
	} else if zeroPort == q.DstPort && zeroPort != p.DstPort {
		skipDstPort = true
	}

	return (skipSrcIP || src1.Compare(src2) == 0) &&
		p.SrcPort == q.SrcPort &&
		(skipDstIP || dst1.Compare(dst2) == 0) &&
		(skipDstPort || p.DstPort == q.DstPort)
}

func trim(s string) string {
	return strings.Trim(s, crlftabspace)
}

func decToInt(n string) int {
	d, err := strconv.ParseInt(n, 10, 64)
	if err != nil {
		log.E("Error while parsing %s to int: %s", n, err)
	}
	return int(d)
}

func hexToInt(h string) int {
	d, err := strconv.ParseInt(h, 16, 64)
	if err != nil {
		log.E("Error while parsing %s to int: %s", h, err)
	}
	return int(d)
}

// hexToInt4 parses a 32-char hex string (IPv6) into four uint32 values.
// The kernel stores IPv6 as 4 x uint32 in little-endian format.
// Returns (w0, w1, w2, w3) corresponding to bytes 0-3, 4-7, 8-11, 12-15.
func hexToInt4(h string) (w0 uint32, w1 uint32, w2 uint32, w3 uint32) {
	l := len(h)

	if l >= 16 {
		w, err := strconv.ParseUint(h[0:8], 16, 32)
		if err != nil {
			log.E("hexToInt4: w0 parse failed: %v", err)
			return 0, 0, 0, 0
		}
		w0 = uint32(w)
		w, err = strconv.ParseUint(h[8:16], 16, 32)
		if err != nil {
			log.E("hexToInt4: w1 parse failed: %v", err)
			return 0, 0, 0, 0
		}
		w1 = uint32(w)

		if l <= 32 {
			w, err := strconv.ParseUint(h[16:24], 16, 32)
			if err != nil {
				log.E("hexToInt4: w2 parse failed: %v", err)
				return 0, 0, 0, 0
			}
			w2 = uint32(w)
			w, err = strconv.ParseUint(h[24:32], 16, 32)
			if err != nil {
				log.E("hexToInt4: w3 parse failed: %v", err)
				return 0, 0, 0, 0
			}
			w3 = uint32(w)
		}
	}
	return
}

// hexToIP converts a hex string from /proc/net/* to a netip.Addr.
// The kernel stores addresses in little-endian format:
// - IPv4: 8 hex chars (1 uint32)
// - IPv6: 32 hex chars (4 uint32 words)
func hexToIP(h string) netip.Addr {
	if len(h) == 32 {
		// IPv6 address: parse as 4 x uint32
		w0, w1, w2, w3 := hexToInt4(h)
		ip := make(net.IP, 16)
		binary.LittleEndian.PutUint32(ip[0:4], w0)
		binary.LittleEndian.PutUint32(ip[4:8], w1)
		binary.LittleEndian.PutUint32(ip[8:12], w2)
		binary.LittleEndian.PutUint32(ip[12:16], w3)
		return toUnmappedAddr(ip)
	}
	// IPv4 address
	v, err := strconv.ParseUint(h, 16, 32)
	if err != nil {
		log.E("hexToIP: IPv4 parse failed: %v", err)
		return netip.Addr{}
	}
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, uint32(v))
	return toUnmappedAddr(ip)
}

func toUnmappedAddr(ip net.IP) netip.Addr {
	ipp, _ := netip.AddrFromSlice(ip[:])
	return ipp.Unmap()
}

// ParseProcNet scans /proc/net/* returns a list of entries, one entry per line scanned
func ParseProcNet(protocol string) ([]ProcNetEntry, error) {
	filename := filepath.Clean(fmt.Sprintf("/proc/net/%s", protocol))
	fd, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer core.CloseFile(fd)

	entries := make([]ProcNetEntry, 0)
	scanner := bufio.NewScanner(fd)
	for lineno := 0; scanner.Scan(); lineno++ {
		// skip column names
		if lineno == 0 {
			continue
		}

		line := trim(scanner.Text())
		m := parser.FindStringSubmatch(line)
		if m == nil {
			log.W("Could not parse netstat line from %s: %s", filename, line)
			continue
		}

		entries = append(entries, NewProcNetEntry(
			protocol,
			hexToIP(m[1]),
			hexToInt(m[2]),
			hexToIP(m[3]),
			hexToInt(m[4]),
			decToInt(m[5]),
			decToInt(m[6]),
		))
	}

	go cleanupPool()

	return entries, nil
}

// cleanupPool removes entries from the pool that are older than cachettl.
// Must be called from a goroutine.
func cleanupPool() {
	defer core.Recover(core.Exit11, "procfs.cleanupPool")

	lastCleanupMs := cache.lastcleanup.Load()
	nowMs := time.Now().UnixMilli()
	if nowMs-lastCleanupMs <= cachettl {
		return
	}
	cache.lastcleanup.Store(nowMs)

	cache.pool.Range(func(k, v any) bool {
		if e, ok := v.(*ProcNetEntry); ok {
			if invalidProcNetEntry(e) {
				deleteProcNetEntryFromPool(e)
			}
		}
		return true
	})
}

func invalidProcNetEntry(p *ProcNetEntry) bool {
	if p == nil {
		return true
	}

	e := getProcNetEntryFromPool(p)
	if e == nil {
		return true
	}

	return time.Since(e.ctime).Milliseconds() > cachettl
}

func deleteProcNetEntryFromPool(p *ProcNetEntry) {
	if p == nil {
		return
	}

	cache.pool.Delete(p.cacheKey())
}

func addProcNetEntryToPool(p *ProcNetEntry) {
	if p == nil {
		return
	}

	cache.pool.Store(p.cacheKey(), p)
}

func getProcNetEntryFromPool(p *ProcNetEntry) *ProcNetEntry {
	if p == nil {
		return nil
	}

	if v, ok := cache.pool.Load(p.cacheKey()); !ok {
		return nil
	} else if e, ok := v.(*ProcNetEntry); !ok {
		return nil
	} else {
		return e
	}
}

// findProcNetEntryForProtocol parses /proc/net/* and return the line matching the argument five-tuple
// (protocol, source, sport, destination, dport) as NewProcNetEntry.
func findProcNetEntryForProtocol(protocol string, src, dst netip.AddrPort) *ProcNetEntry {

	n := NewProcNetEntry(protocol, src.Addr().Unmap(), int(src.Port()), dst.Addr().Unmap(), int(dst.Port()), 0, 0)
	e := &n // groups.google.com/g/golang-nuts/c/reaIlFdibWU?pli=1

	if f := getProcNetEntryFromPool(e); e.Same(f) {
		if !invalidProcNetEntry(f) {
			return f
		}
		deleteProcNetEntryFromPool(f)
	}

	entries, err := ParseProcNet(protocol)
	if err != nil {
		log.W("Error while searching for %s netstat entry: %s", protocol, err)
		return nil
	}

	for _, ent := range entries {
		ep := &ent // stackoverflow.com/a/68247837
		cached := getProcNetEntryFromPool(ep)
		if invalidProcNetEntry(cached) {
			addProcNetEntryToPool(ep)
		}
		// return on first match since e.Same is pretty lax and deliberately
		// not exact at matching the various procnet entries
		if e.Same(ep) {
			return ep
		}
	}

	return nil
}

// FindProcNetEntry searches for netstat entries in v4 and v6 tables.
func FindProcNetEntry(protocol string, src, dst netip.AddrPort) *ProcNetEntry {
	if entry := findProcNetEntryForProtocol(protocol, src, dst); entry != nil {
		return entry
	}

	ipv6Suffix := "6"
	if !strings.HasSuffix(protocol, ipv6Suffix) {
		otherProtocol := protocol + ipv6Suffix
		return findProcNetEntryForProtocol(otherProtocol, src, dst)
	}

	return nil
}
