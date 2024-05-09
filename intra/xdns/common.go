// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//    ISC License
//
//    Copyright (c) 2018-2021
//    Frank Denis <j at pureftpd dot org>

package xdns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

type CryptoConstruction uint16

const (
	UndefinedConstruction CryptoConstruction = iota
	XSalsa20Poly1305
	XChacha20Poly1305
)

const (
	ClientMagicLen     = 8
	blocklistHeaderKey = "x-nile-flags" // "x-bl-fl"
)

var (
	CertMagic               = [4]byte{0x44, 0x4e, 0x53, 0x43}
	ServerMagic             = [8]byte{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38}
	MinDNSPacketSize        = 12 + 5
	MaxDNSPacketSize        = 4096
	MaxDNSUDPPacketSize     = 4096
	MaxDNSUDPSafePacketSize = 1252
	BlockTTL                = uint32(5)
	AnsTTL                  = uint32(300)
	MaxMTU                  = 0xffff // 65k, ought to be enough for everybody
)

var (
	ip4zero = net.IPv4zero
	ip6zero = net.IPv6unspecified
	dnsport = uint16(53)
)

const (
	mdnsip4  = "224.0.0.251"
	mdnsip6  = "ff02::fb"
	mdnsPort = 5353

	arpa4suffix = "254.169.in-addr.arpa"
	// "8.e.f.ip6.arpa.", "9.e.f.ip6.arpa.", "a.e.f.ip6.arpa.", and "b.e.f.ip6.arpa."
	arpa6suffix = "e.f.ip6.arpa"
	localsuffix = "local"
)

var (
	MDNSAddr4 = &net.UDPAddr{
		IP:   net.ParseIP(mdnsip4),
		Port: mdnsPort,
	}
	MDNSAddr6 = &net.UDPAddr{
		IP:   net.ParseIP(mdnsip6),
		Port: mdnsPort,
	}
)

var (
	errMassivePkt     = errors.New("packet too large")
	errRdnsUrlMissing = errors.New("url missing")
	errNoAns          = errors.New("no answer record")
	errNoDns          = errors.New("nil dns msg")
	errNotAscii       = errors.New("name not ASCII string")
)

// Net2ProxyID splits network string into proto and pid;
// proto is the network protocol and pid is the proxy ID.
// May return empty strings.
func Net2ProxyID(network string) (proto, pid string) {
	x := strings.Split(network, ":")
	if len(x) <= 0 {
		return // empty
	}
	if len(x) >= 1 {
		proto = x[0]
	}
	if len(x) >= 2 {
		pid = x[1]
	}
	return
}

// NetAndProxyID joins proto and pid into a network string.
// proto is the network protocol and pid is the proxy ID.
// May return just the separator ":", if both proto, pid are empty.
func NetAndProxyID(proto, pid string) string {
	return fmt.Sprintf("%s:%s", proto, pid)
}

func PrefixWithSize(packet []byte) ([]byte, error) {
	packetLen := len(packet)
	if packetLen > MaxMTU {
		return packet, errMassivePkt
	}
	packet = append(append(packet, 0), 0)
	copy(packet[2:], packet[:len(packet)-2])
	binary.BigEndian.PutUint16(packet[0:2], uint16(len(packet)-2))
	return packet, nil
}

func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func StringReverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// returns unique strings in n not in s as new array
func FindUnique(s []string, n []string) (u []string) {
	if len(s) == 0 {
		return n
	}
	if len(n) == 0 {
		return u
	}

	for _, e := range n {
		uniq := true
		for _, x := range s {
			if e == x {
				uniq = false
				break
			}
		}
		if uniq {
			u = append(u, e)
		}
	}

	return
}

// remove removes elements at indices r from a ascii string slice s
// and returns a slice
func RemoveOverlap(s []string, r []string) []string {
	// TODO: check if the max(r...) is within len(s)
	// FIXME: s shouldn't contain empty string
	var j int = 0
	for _, x := range s {
		var skip bool = false
		for _, y := range r {
			if x == y {
				skip = true
				break
			}
		}
		if !skip {
			s[j] = x
			j++
		}
	}
	// slice out the bottom-half to be removed
	return s[:j]
}

// TODO: merge this with doh.Accept
func ReadPrefixed(conn *net.Conn) ([]byte, error) {
	buf := make([]byte, 2+MaxDNSPacketSize)
	packetLength, pos := -1, 0
	for {
		readnb, err := (*conn).Read(buf[pos:])
		if err != nil {
			return buf, err
		}
		pos += readnb
		if pos >= 2 && packetLength < 0 {
			packetLength = int(binary.BigEndian.Uint16(buf[0:2]))
			if packetLength > MaxDNSPacketSize-1 {
				return buf, errors.New("resp packet too large")
			}
			if packetLength < MinDNSPacketSize {
				return buf, fmt.Errorf("resp packet too short %d", packetLength)
			}
		}
		if packetLength >= 0 && pos >= 2+packetLength {
			return buf[2 : 2+packetLength], nil
		}
	}
}

// TODO: Move to dnsx?
func GetBlocklistStampFromURL(rawurl string) (string, error) {
	if len(rawurl) <= 0 {
		return "", errRdnsUrlMissing
	}
	// TODO: validate if the domain is bravedns.com/rethinkdns.com?
	u, err := url.Parse(rawurl)
	if err != nil {
		return "", err
	}
	// p://url.tld or p://url.tld/
	if len(u.Path) <= 1 {
		return "", errors.New("no path")
	}
	s := strings.TrimLeft(u.Path, "/")
	i := strings.Index(s, ":") // stamps with ":" are versioned
	if i == -1 {
		return url.QueryEscape(s), nil
	} else { // versioned stamps use path-escape
		return url.PathEscape(s), nil
	}
	// url => path => split:
	// url/p/q/r => /p/q/r/ => [' ', 'p', 'q', 'r', ' ']
	// url/ => / => [' ', ' ']
	// url/a/ => /a/ => [' ', 'a', ' ']
	// url => "" => ['']
	/*
	   FIXME: breaks when encoded("/") is in u.Path as split matches it too
	   ex:74CA77%2B%2F77%2B%2F77%2B%2F77CA -> splits-to -> [74CA77+ 77+ 77+ 77CA]
	   since %2F is a "/"
	   p := strings.Split(u.Path, "/")
	   if (len(p) <= 1) {
	       return "", errors.New("empty path")
	   } else if (p[1] != "dns-query" && len(p[1]) > 0) {
	       return p[1], nil // TODO: validate stamp?
	   } else if (len(p) >= 3 && len(p[2]) > 0) {
	       return p[2], nil // validate?
	   }
	   return "", errors.New("first two path positions missing stamp")
	*/
}

func DnsIPPort(s string) (ipp netip.AddrPort, err error) {
	var ip netip.Addr
	if ipp, err = netip.ParseAddrPort(s); err != nil {
		if ip, err = netip.ParseAddr(s); err == nil {
			ipp = netip.AddrPortFrom(ip, dnsport)
		}
	}
	return
}
