// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package settings

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/celzero/firestack/intra/log"
)

var errDnsOptArg = errors.New("dnsopt: invalid arg")

// DNSOptions define https or socks5 proxy options
type DNSOptions struct {
	idOrHostportOrIpport string // host:port or ip:port; may be empty
	hostips              string // ips only, comma separated; may be empty
	port                 uint16 // port only; 53 if not set
}

func (d *DNSOptions) String() string {
	if d == nil {
		return "<nil>"
	}
	return d.AddrPort()
}

// AddrPort returns the ip:port or host:port; may return empty string.
func (d *DNSOptions) AddrPort() string {
	if len(d.idOrHostportOrIpport) > 0 {
		return d.idOrHostportOrIpport
	}
	return ""
}

func (d *DNSOptions) Port() uint16 {
	return d.port
}

func (d *DNSOptions) ResolvedAddrs() string {
	return d.hostips // TODO: may be ip:port
}

// NewDNSOptions returns a new DNSOpitons object.
func NewDNSOptions(ipport string) (*DNSOptions, error) {
	var ipp netip.AddrPort
	var err error
	ip, port, err := net.SplitHostPort(ipport)
	if err != nil {
		return nil, err
	}
	if ipp, err = addrport(ip, port); err == nil {
		return &DNSOptions{
			idOrHostportOrIpport: ipp.String(),
			port:                 ipp.Port(),
		}, nil
	}
	log.D("dnsopt(%s:%s); err(%v)", ip, port, err)
	return nil, err
}

func NewDNSOptionsFromNetIp(ipp netip.AddrPort) (*DNSOptions, error) {
	if !ipp.IsValid() {
		return nil, errors.New("dnsopt: empty ipport")
	}
	return &DNSOptions{
		idOrHostportOrIpport: ipp.String(),
		port:                 ipp.Port(),
	}, nil
}

func NewDNSOptionsFromHostname(idOrHostOrHostPort, ipOrIPPortCsv string) (*DNSOptions, error) {
	if len(idOrHostOrHostPort) <= 0 {
		return nil, errDnsOptArg
	}

	idOrDomain, port, _ := net.SplitHostPort(idOrHostOrHostPort)

	if len(idOrDomain) <= 0 {
		idOrDomain = idOrHostOrHostPort
	}

	portFromHostPort := len(port) > 0
	portu16 := uint16(53)
	if portFromHostPort {
		if u64, _ := strconv.ParseUint(port, 10, 16); u64 > 0 {
			portu16 = uint16(u64)
		} else {
			port = "53"
			portFromHostPort = false // as if len(port) == 0
		}
	}

	ips := make([]string, 0)
	ports := make([]uint16, 0)
	for ipp := range strings.SplitSeq(ipOrIPPortCsv, ",") {
		if addr, err := netip.ParseAddrPort(ipp); err == nil {
			ips = append(ips, addr.Addr().String())
			if port := addr.Port(); port > 0 {
				ports = append(ports, port)
			}
		} else if addr, err := netip.ParseAddr(ipp); err == nil {
			ips = append(ips, addr.String())
		} else {
			log.W("dnsopt: invalid ip/ipport for %s; ipp(%s); err(%v)", idOrHostOrHostPort, ipp, err)
		}
	}

	portFromIPPort := len(ports) > 0
	if portFromHostPort {
		// skip other checks
	} else if portFromIPPort {
		// TODO: support multiple ports?
		port = strconv.Itoa(int(ports[0]))
		portu16 = ports[0]
	} else {
		// default port
		port = "53"
		portu16 = 53
	}

	log.I("dnsopt: for %s; len(ips) = %d; port = %s; portFromHostPort? %t; portFromIPPort? %t",
		idOrHostOrHostPort, len(ips), port, portFromHostPort, portFromIPPort)
	return &DNSOptions{
		idOrHostportOrIpport: net.JoinHostPort(idOrDomain, port),
		hostips:              strings.Join(ips, ","), // may be empty
		port:                 portu16,
	}, nil
}

// Parse ip and port; where ip can be either ip:port or ip
func addrport(ip string, port string) (ipp netip.AddrPort, err error) {
	var ipaddr netip.Addr
	var p int
	if ipaddr, err = netip.ParseAddr(ip); err == nil {
		if p, err = strconv.Atoi(port); err == nil {
			ipp = netip.AddrPortFrom(ipaddr.Unmap(), uint16(p))
			return ipp, nil
		}
	} else if ipp, err = netip.ParseAddrPort(ip); err == nil {
		return ipp, nil
	}
	return ipp, err
}

const (
	// Use among encrypted dns transports wrapped by dnsx.Plus
	PlusFilterSafest = iota
	// Use dns transports randomly wrapped by dnsx.Plus
	PlusOrderRandom
	// Prefer faster (p50 latency) dns transports wrapped by dnsx.Plus
	PlusOrderFastest
	// Prefer working dns transports wrapped by dnsx.Plus
	PlusOrderRobust
)

var PlusStrat = atomic.Int32{}

// SetPlusStrategy returns the order strategy for Plus DNS transports.
func SetPlusStrategy(new int) bool {
	if new < PlusFilterSafest || new > PlusOrderRobust {
		log.W("dnsopt: invalid plus order strategy %d", new)
		return false
	}
	old := PlusStrat.Swap(int32(new))
	log.I("dnsopt: set plus order strategy to %d <= %d", new, old)
	return true
}
