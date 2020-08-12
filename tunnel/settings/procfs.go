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

	"github.com/eycorsican/go-tun2socks/common/log"
)

const (
	crlftabspace = "\r\n\t "
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
)

// ProcNetEntry represents a single line as fetched from /proc/net/*
type ProcNetEntry struct {
	Protocol	string
	SrcIP   	net.IP
	SrcPort 	int
	DstIP   	net.IP
	DstPort 	int
	UserID  	int
	INode   	int
}

// NewProcNetEntry creates an Entry
func NewProcNetEntry(protocol string, srcIP net.IP, srcPort int, dstIP net.IP, dstPort int, userID int, iNode int) ProcNetEntry {
	return ProcNetEntry {
		Protocol:	protocol,
		SrcIP:   	srcIP,
		SrcPort: 	srcPort,
		DstIP:   	dstIP,
		DstPort: 	dstPort,
		UserID:  	userID,
		INode:   	iNode,
	}
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


func hexToInt2(h string) (int, int) {
	if len(h) > 16 {
		d, err := strconv.ParseInt(h[:16], 16, 64)
		if err != nil {
			log.Errorf("Error while parsing %s to int: %s", h[16:], err)
		}
		d2, err := strconv.ParseInt(h[16:], 16, 64)
		if err != nil {
			log.Errorf("Error while parsing %s to int: %s", h[16:], err)
		}
		return int(d), int(d2)
	}
	d, err := strconv.ParseInt(h, 16, 64)
	if err != nil {
		log.Errorf("Error while parsing %s to int: %s", h[16:], err)
	}
	return int(d), 0

}

func hexToIP(h string) net.IP {
	n, m := hexToInt2(h)
	var ip net.IP
	if m != 0 {
		ip = make(net.IP, 16)
		// TODO: Check if this depends on machine endianness?
		binary.LittleEndian.PutUint32(ip, uint32(n >> 32))
		binary.LittleEndian.PutUint32(ip[4:], uint32(n))
		binary.LittleEndian.PutUint32(ip[8:], uint32(m >> 32))
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

	return entries, nil
}

// FindProcNetEntry parses /proc/net/* and return the line matching the argument five-tuple
// (protocol, source, sport, destination, dport) as an NewProcNetEntry.
func FindProcNetEntry(protocol string, srcIP net.IP, srcPort int, dstIP net.IP, dstPort int) *ProcNetEntry {
	entries, err := ParseProcNet(protocol)
	if err != nil {
		log.Warnf("Error while searching for %s netstat entry: %s", protocol, err)
		return nil
	}

	for _, entry := range entries {
		if srcIP.Equal(entry.SrcIP) && srcPort == entry.SrcPort && dstIP.Equal(entry.DstIP) && dstPort == entry.DstPort {
			return &entry
		}
	}

	return nil
}