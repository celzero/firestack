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
		// transfer queue, recieve queue
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
	pool        *sync.Map // string, *ProcNetEntry{}
	lastcleanup time.Time
}

func NewProcNetCache() ProcNetCache {
	return ProcNetCache{
		pool:        new(sync.Map),
		lastcleanup: time.Now(),
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

	if src1.Is6() && !src2.Is6() {
		return false
	}
	if dst1.Is6() && !dst2.Is6() {
		return false
	}

	zeroip := zeroip4
	if src1.Is6() {
		zeroip = zeroip6
	}

	// github.com/M66B/NetGuard/blob/1fe3a04ae/app/src/main/jni/netguard/ip.c#L393
	skipSrcIP := false
	skipDstIP := false
	skipDstPort := false
	if zeroip.Compare(src1) == 0 || zeroip.Compare(src2) == 0 {
		skipSrcIP = true
	}
	if zeroip.Compare(dst1) == 0 || zeroip.Compare(dst2) == 0 {
		skipDstIP = true
	}
	if zeroPort == p.DstPort || zeroPort == q.DstPort {
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

func hexToInt2(h string) (uint, uint) {
	if len(h) > 16 {
		d, err := strconv.ParseUint(h[:16], 16, 64)
		if err != nil {
			log.E("Error while parsing %s to int: %s", h[:16], err)
		}
		d2, err := strconv.ParseUint(h[16:], 16, 64)
		if err != nil {
			log.E("Error while parsing %s to int: %s", h[16:], err)
		}
		return uint(d), uint(d2)
	}
	d, err := strconv.ParseUint(h, 16, 64)
	if err != nil {
		log.E("Error while parsing %s to int: %s", h[:16], err)
	}
	return uint(d), 0

}

func hexToIP(h string) netip.Addr {
	hi, lo := hexToInt2(h)
	var ip net.IP
	if lo != 0 {
		lomsb := uint32(lo >> 32)
		himsb := uint32(hi >> 32)

		// see: netip.Unmap
		// stackoverflow.com/questions/22751035
		// hi: 0000 0000 0000 0000 0000 0000 0000 0000
		// lo: 0000 0000 0000 0000 wwww xxxx yyyy zzzz
		if hi == 0 && lomsb == 0 {
			ip = make(net.IP, 4) // v4in6
			binary.LittleEndian.PutUint32(ip, uint32(lo))
		} else {
			ip = make(net.IP, 16)
			// ip addresses are stored in network byte order
			binary.LittleEndian.PutUint32(ip, himsb)
			binary.LittleEndian.PutUint32(ip[4:], uint32(hi))
			// if v4in6: github.com/golang/go/blob/2bed2797/src/net/ip.go#L195-L196
			// mark: 0000 0000 0000 0000 1111 1111 1111 1111
			// mark := uint32(0xffff)
			// binary.BigEndian.PutUint32(ip[8:], mark)
			binary.LittleEndian.PutUint32(ip[8:], lomsb)
			binary.LittleEndian.PutUint32(ip[12:], uint32(lo))
		}
	} else {
		ip = make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, uint32(hi))
	}
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

func cleanupPool() {
	if time.Since(cache.lastcleanup).Milliseconds() <= cachettl {
		return
	}
	cache.lastcleanup = time.Now()

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

	cache.pool.Delete(p.String())
}

func addProcNetEntryToPool(p *ProcNetEntry) {
	if p == nil {
		return
	}

	cache.pool.Store(p.String(), p)
}

func getProcNetEntryFromPool(p *ProcNetEntry) *ProcNetEntry {
	if p == nil {
		return nil
	}

	if v, ok := cache.pool.Load(p.String()); !ok {
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
