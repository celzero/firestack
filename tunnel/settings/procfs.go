// relicensed to apache v2 from opensnitch with permissions from evilsocket
package settings

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/eycorsican/go-tun2socks/common/log"
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

	zeroIP = net.ParseIP("::")

	zeroPort = 0
)

// ProcNetEntry represents a single line as fetched from /proc/net/*
type ProcNetEntry struct {
	Protocol string
	SrcIP    net.IP
	SrcPort  int
	DstIP    net.IP
	DstPort  int
	UserID   int
	INode    int
	ctime    time.Time
}

type ProcNetCache struct {
	rw          sync.RWMutex
	pool        map[string]*ProcNetEntry
	lastcleanup time.Time
}

func NewProcNetCache() ProcNetCache {
	return ProcNetCache{
		pool:        map[string]*ProcNetEntry{},
		lastcleanup: time.Now(),
	}
}

// NewProcNetEntry creates an Entry
func NewProcNetEntry(protocol string, srcIP net.IP, srcPort int, dstIP net.IP, dstPort int, userID int, iNode int) ProcNetEntry {
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

	// https://github.com/M66B/NetGuard/blob/1fe3a04ae/app/src/main/jni/netguard/ip.c#L393
	skipSrcIP := false
	skipDstIP := false
	skipDstPort := false
	if zeroIP.Equal(p.SrcIP) || zeroIP.Equal(q.SrcIP) {
		skipSrcIP = true
	}
	if zeroIP.Equal(p.DstIP) || zeroIP.Equal(q.DstIP) {
		skipDstIP = true
	}
	if zeroPort == p.DstPort || zeroPort == q.DstPort {
		skipDstPort = true
	}

	return (skipSrcIP || p.SrcIP.Equal(q.SrcIP)) &&
		p.SrcPort == q.SrcPort &&
		(skipDstIP || p.DstIP.Equal(q.DstIP)) &&
		(skipDstPort || p.DstPort == q.DstPort)
}

func trim(s string) string {
	return strings.Trim(s, crlftabspace)
}

func decToInt(n string) int {
	d, err := strconv.ParseInt(n, 10, 64)
	if err != nil {
		log.Errorf("Error while parsing %s to int: %s", n, err)
	}
	return int(d)
}

func hexToInt(h string) int {
	d, err := strconv.ParseInt(h, 16, 64)
	if err != nil {
		log.Errorf("Error while parsing %s to int: %s", h, err)
	}
	return int(d)
}

func hexToInt2(h string) (uint, uint) {
	if len(h) > 16 {
		d, err := strconv.ParseUint(h[:16], 16, 64)
		if err != nil {
			log.Errorf("Error while parsing %s to int: %s", h[:16], err)
		}
		d2, err := strconv.ParseUint(h[16:], 16, 64)
		if err != nil {
			log.Errorf("Error while parsing %s to int: %s", h[16:], err)
		}
		return uint(d), uint(d2)
	}
	d, err := strconv.ParseUint(h, 16, 64)
	if err != nil {
		log.Errorf("Error while parsing %s to int: %s", h[:16], err)
	}
	return uint(d), 0

}

func hexToIP(h string) net.IP {
	n, m := hexToInt2(h)
	var ip net.IP
	if m != 0 {
		mmsb := uint32(m >> 32)
		v4IPv6 := false
		ip = make(net.IP, 16)

		// https://stackoverflow.com/questions/22751035
		if n == 0 && mmsb == 0 {
			v4IPv6 = true // ipv4 in ipv6
		}
		// TODO: Check if this depends on machine endianness?
		binary.LittleEndian.PutUint32(ip, uint32(n>>32))
		binary.LittleEndian.PutUint32(ip[4:], uint32(n))
		if v4IPv6 {
			// https://github.com/golang/go/blob/2bed2797/src/net/ip.go#L195-L196
			// 0000 0000 0000 0000 1111 1111 1111 1111
			binary.BigEndian.PutUint32(ip[8:], uint32(0xffff))
		} else {
			binary.LittleEndian.PutUint32(ip[8:], mmsb)
		}
		binary.LittleEndian.PutUint32(ip[12:], uint32(m))
	} else {
		ip = make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, uint32(n))
	}
	return ip
}

// ParseProcNet scans /proc/net/* returns a list of entries, one entry per line scanned
func ParseProcNet(protocol string) ([]ProcNetEntry, error) {
	filename := fmt.Sprintf("/proc/net/%s", protocol)
	fd, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

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
			log.Warnf("Could not parse netstat line from %s: %s", filename, line)
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
	// golang locks aren't re-entrant, careful java developers
	cache.rw.Lock()
	if time.Since(cache.lastcleanup).Milliseconds() <= cachettl {
		cache.rw.Unlock()
		return
	}
	cache.lastcleanup = time.Now()
	cache.rw.Unlock()

	for _, v := range cache.pool {
		// slight window of opportunity for a data-race when
		// invalidProcNetEntry says one thing but the state
		// has changed by the time delete does its thing
		if invalidProcNetEntry(v) {
			// delete does its own locking
			deleteProcNetEntryFromPool(v)
		}
	}
}

func invalidProcNetEntry(p *ProcNetEntry) bool {
	if p == nil {
		return true
	}

	cache.rw.RLock()
	defer cache.rw.RUnlock()

	e := cache.pool[p.String()]

	return e == nil || time.Since(e.ctime).Milliseconds() > cachettl
}

func deleteProcNetEntryFromPool(p *ProcNetEntry) {
	if p == nil {
		return
	}

	cache.rw.Lock()
	defer cache.rw.Unlock()

	delete(cache.pool, p.String())
}

func addProcNetEntryToPool(p *ProcNetEntry) {
	if p == nil {
		return
	}

	cache.rw.Lock()
	defer cache.rw.Unlock()

	cache.pool[p.String()] = p
}

func getProcNetEntryFromPool(p *ProcNetEntry) *ProcNetEntry {
	if p == nil {
		return nil
	}

	cache.rw.RLock()
	defer cache.rw.RUnlock()

	return cache.pool[p.String()]
}

// findProcNetEntryForProtocol parses /proc/net/* and return the line matching the argument five-tuple
// (protocol, source, sport, destination, dport) as NewProcNetEntry.
func findProcNetEntryForProtocol(protocol string, srcIP net.IP, srcPort int, dstIP net.IP, dstPort int) *ProcNetEntry {

	n := NewProcNetEntry(protocol, srcIP, srcPort, dstIP, dstPort, 0, 0)
	e := &n // https://groups.google.com/g/golang-nuts/c/reaIlFdibWU?pli=1
	pool := getProcNetEntryFromPool(e)

	if e.Same(pool) {
		if invalidProcNetEntry(pool) == false {
			return pool
		}
		deleteProcNetEntryFromPool(pool)
	}

	entries, err := ParseProcNet(protocol)
	if err != nil {
		log.Warnf("Error while searching for %s netstat entry: %s", protocol, err)
		return nil
	}

	for _, entry := range entries {
		pe := getProcNetEntryFromPool(&entry)
		if invalidProcNetEntry(pe) {
			addProcNetEntryToPool(&entry)
		}
		if e.Same(&entry) {
			return &entry
		}
	}

	return nil
}

// FindProcNetEntry searches for netstat entries in v4 and v6 tables.
func FindProcNetEntry(protocol string, srcIP net.IP, srcPort int, dstIP net.IP, dstPort int) *ProcNetEntry {
	if entry := findProcNetEntryForProtocol(protocol, srcIP, srcPort, dstIP, dstPort); entry != nil {
		return entry
	}

	ipv6Suffix := "6"
	if strings.HasSuffix(protocol, ipv6Suffix) == false {
		otherProtocol := protocol + ipv6Suffix
		return findProcNetEntryForProtocol(otherProtocol, srcIP, srcPort, dstIP, dstPort)
	}

	return nil
}
