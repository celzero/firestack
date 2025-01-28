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

	"github.com/celzero/firestack/intra/log"
)

var errDnsOptArg = errors.New("dnsopt: invalid arg")

// DNSOptions define https or socks5 proxy options
type DNSOptions struct {
	ipp      string
	hostport string
	hostips  string
	port     uint16
}

func (d *DNSOptions) String() string {
	if (d == nil) || (len(d.ipp) <= 0) {
		return "<nil>"
	}
	return d.AddrPort()
}

// AddrPort returns the ip:port or host:port.
func (d *DNSOptions) AddrPort() string {
	if len(d.ipp) > 0 {
		return d.ipp
	}
	if len(d.hostport) > 0 {
		return d.hostport
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
			ipp:  ipp.String(),
			port: ipp.Port(),
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
		ipp:  ipp.String(),
		port: ipp.Port(),
	}, nil
}

func NewDNSOptionsFromHostname(hostOrHostPort, ipcsv string) (*DNSOptions, error) {
	if len(hostOrHostPort) <= 0 {
		return nil, errDnsOptArg
	}

	domain, port, _ := net.SplitHostPort(hostOrHostPort)

	if len(domain) <= 0 {
		domain = hostOrHostPort
	}
	portu16 := uint16(53)
	if len(port) == 0 {
		port = "53"
	} else {
		if u64, _ := strconv.ParseUint(port, 10, 16); u64 > 0 {
			portu16 = uint16(u64)
		}
	}

	return &DNSOptions{
		hostport: net.JoinHostPort(domain, port),
		hostips:  ipcsv, // may be empty, and may be ip:port
		port:     portu16,
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
