// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//    SPDX-License-Identifier: MIT
//
//    Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.

// from: github.com/WireGuard/wireguard-go/blob/5819c6af/tun/netstack/tun.go

package ipn

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/celzero/firestack/intra/log"
	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// --------------------------------------------------------------------
// dns dialer
// --------------------------------------------------------------------

var (
	errNoSuchHost                   = errors.New("no such host")
	errLameReferral                 = errors.New("lame referral")
	errCannotUnmarshalDNSMessage    = errors.New("cannot unmarshal DNS message")
	errCannotMarshalDNSMessage      = errors.New("cannot marshal DNS message")
	errServerMisbehaving            = errors.New("server misbehaving")
	errInvalidDNSResponse           = errors.New("invalid DNS response")
	errNoAnswerFromDNSServer        = errors.New("no answer from DNS server")
	errServerTemporarilyMisbehaving = errors.New("server misbehaving")
	errCanceled                     = errors.New("operation was canceled")
	errTimeout                      = errors.New("i/o timeout")
	errNumericPort                  = errors.New("port must be numeric")
	errNoSuitableAddress            = errors.New("no suitable address found")
	errMissingAddress               = errors.New("missing address")
	errMissingWgDNS                 = &net.DNSConfigError{Err: errors.New("no DNS addrs")}
)

const (
	wgdnstimeout = time.Second * 5
	wgbarrierttl = time.Second * 30
)

func (net *wgtun) LookupHost(host string) (addrs []string, err error) {
	return net.LookupContextHost(context.Background(), host)
}

func isDomainName(s string) bool {
	l := len(s)
	if l == 0 || l > 254 || l == 254 && s[l-1] != '.' {
		return false
	}
	last := byte('.')
	nonNumeric := false
	partlen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_':
			nonNumeric = true
			partlen++
		case '0' <= c && c <= '9':
			partlen++
		case c == '-':
			if last == '.' {
				return false
			}
			partlen++
			nonNumeric = true
		case c == '.':
			if last == '.' || last == '-' {
				return false
			}
			if partlen > 63 || partlen == 0 {
				return false
			}
			partlen = 0
		}
		last = c
	}
	if last == '-' || partlen > 63 {
		return false
	}
	return nonNumeric
}

func rand16() uint16 {
	var b [2]byte
	_, err := rand.Read(b[:])
	if err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint16(b[:])
}

func newRequest(q dnsmessage.Question) (id uint16, udpReq, tcpReq []byte, err error) {
	id = rand16()
	b := dnsmessage.NewBuilder(make([]byte, 2, 514), dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return 0, nil, nil, err
	}
	if err := b.Question(q); err != nil {
		return 0, nil, nil, err
	}
	tcpReq, err = b.Finish()
	udpReq = tcpReq[2:]
	l := len(tcpReq) - 2
	tcpReq[0] = byte(l >> 8)
	tcpReq[1] = byte(l)
	return id, udpReq, tcpReq, err
}

func equalASCIIName(x, y dnsmessage.Name) bool {
	if x.Length != y.Length {
		return false
	}
	for i := 0; i < int(x.Length); i++ {
		a := x.Data[i]
		b := y.Data[i]
		if 'A' <= a && a <= 'Z' {
			a += 0x20
		}
		if 'A' <= b && b <= 'Z' {
			b += 0x20
		}
		if a != b {
			return false
		}
	}
	return true
}

func checkResponse(reqID uint16, reqQues dnsmessage.Question, respHdr dnsmessage.Header, respQues dnsmessage.Question) bool {
	if !respHdr.Response {
		return false
	}
	if reqID != respHdr.ID {
		return false
	}
	if reqQues.Type != respQues.Type || reqQues.Class != respQues.Class || !equalASCIIName(reqQues.Name, respQues.Name) {
		return false
	}
	return true
}

func dnsPacketRoundTrip(c net.Conn, id uint16, query dnsmessage.Question, b []byte) (dnsmessage.Parser, dnsmessage.Header, error) {
	if _, err := c.Write(b); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	b = make([]byte, 512)
	for {
		n, err := c.Read(b)
		if err != nil {
			return dnsmessage.Parser{}, dnsmessage.Header{}, err
		}
		var p dnsmessage.Parser
		h, err := p.Start(b[:n])
		if err != nil {
			continue
		}
		q, err := p.Question()
		if err != nil || !checkResponse(id, query, h, q) {
			continue
		}
		return p, h, nil
	}
}

func dnsStreamRoundTrip(c net.Conn, id uint16, query dnsmessage.Question, b []byte) (dnsmessage.Parser, dnsmessage.Header, error) {
	if _, err := c.Write(b); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	b = make([]byte, 1280)
	if _, err := io.ReadFull(c, b[:2]); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	l := int(b[0])<<8 | int(b[1])
	if l > len(b) {
		b = make([]byte, l)
	}
	n, err := io.ReadFull(c, b[:l])
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	var p dnsmessage.Parser
	h, err := p.Start(b[:n])
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errCannotUnmarshalDNSMessage
	}
	q, err := p.Question()
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errCannotUnmarshalDNSMessage
	}
	if !checkResponse(id, query, h, q) {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errInvalidDNSResponse
	}
	return p, h, nil
}

func (tnet *wgtun) exchange(ctx context.Context, server netip.Addr, q dnsmessage.Question, timeout time.Duration) (dnsmessage.Parser, dnsmessage.Header, error) {
	q.Class = dnsmessage.ClassINET
	id, udpReq, tcpReq, err := newRequest(q)
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errCannotMarshalDNSMessage
	}

	for _, useUDP := range []bool{true, false} {
		ctx, cancel := context.WithDeadline(ctx, time.Now().Add(timeout))
		defer cancel()

		var c net.Conn
		var err error
		if useUDP {
			c, err = tnet.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(server, 53))
		} else {
			c, err = tnet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(server, 53))
		}

		if err != nil {
			return dnsmessage.Parser{}, dnsmessage.Header{}, err
		}
		if d, ok := ctx.Deadline(); ok && !d.IsZero() {
			err := c.SetDeadline(d)
			if err != nil {
				return dnsmessage.Parser{}, dnsmessage.Header{}, err
			}
		}
		var p dnsmessage.Parser
		var h dnsmessage.Header
		if useUDP {
			p, h, err = dnsPacketRoundTrip(c, id, q, udpReq)
		} else {
			p, h, err = dnsStreamRoundTrip(c, id, q, tcpReq)
		}
		c.Close()
		if err != nil {
			if err == context.Canceled {
				err = errCanceled
			} else if err == context.DeadlineExceeded {
				err = errTimeout
			}
			return dnsmessage.Parser{}, dnsmessage.Header{}, err
		}
		if err := p.SkipQuestion(); err != dnsmessage.ErrSectionDone {
			return dnsmessage.Parser{}, dnsmessage.Header{}, errInvalidDNSResponse
		}
		if h.Truncated {
			continue
		}
		return p, h, nil
	}
	return dnsmessage.Parser{}, dnsmessage.Header{}, errNoAnswerFromDNSServer
}

func checkHeader(p *dnsmessage.Parser, h dnsmessage.Header) error {
	if h.RCode == dnsmessage.RCodeNameError {
		return errNoSuchHost
	}
	_, err := p.AnswerHeader()
	if err != nil && err != dnsmessage.ErrSectionDone {
		return errCannotUnmarshalDNSMessage
	}
	if h.RCode == dnsmessage.RCodeSuccess && !h.Authoritative && !h.RecursionAvailable && err == dnsmessage.ErrSectionDone {
		return errLameReferral
	}
	if h.RCode != dnsmessage.RCodeSuccess && h.RCode != dnsmessage.RCodeNameError {
		if h.RCode == dnsmessage.RCodeServerFailure {
			return errServerTemporarilyMisbehaving
		}
		return errServerMisbehaving
	}
	return nil
}

func skipToAnswer(p *dnsmessage.Parser, qtype dnsmessage.Type) error {
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			return errNoSuchHost
		}
		if err != nil {
			return errCannotUnmarshalDNSMessage
		}
		if h.Type == qtype {
			return nil
		}
		if err := p.SkipAnswer(); err != nil {
			return errCannotUnmarshalDNSMessage
		}
	}
}

func (tnet *wgtun) tryOneName(ctx context.Context, name string, qtype dnsmessage.Type) (dnsmessage.Parser, string, error) {
	var lastErr error

	dnsaddrs := tnet.dns.Addrs()
	if len(dnsaddrs) == 0 {
		return dnsmessage.Parser{}, "", errMissingWgDNS
	}
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return dnsmessage.Parser{}, "", errCannotMarshalDNSMessage
	}
	q := dnsmessage.Question{
		Name:  n,
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}

	for i := 0; i < 2; i++ {
		for _, server := range dnsaddrs {
			p, h, err := tnet.exchange(ctx, server, q, wgdnstimeout)
			if err != nil {
				dnsErr := &net.DNSError{
					Err:    err.Error(),
					Name:   name,
					Server: server.String(),
				}
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					dnsErr.IsTimeout = true
				}
				if _, ok := err.(*net.OpError); ok {
					dnsErr.IsTemporary = true
				}
				lastErr = dnsErr
				continue
			}

			if err := checkHeader(&p, h); err != nil {
				dnsErr := &net.DNSError{
					Err:    err.Error(),
					Name:   name,
					Server: server.String(),
				}
				if err == errServerTemporarilyMisbehaving {
					dnsErr.IsTemporary = true
				}
				if err == errNoSuchHost {
					dnsErr.IsNotFound = true
					return p, server.String(), dnsErr
				}
				lastErr = dnsErr
				continue
			}

			err = skipToAnswer(&p, qtype)
			if err == nil {
				return p, server.String(), nil
			}
			lastErr = &net.DNSError{
				Err:    err.Error(),
				Name:   name,
				Server: server.String(),
			}
			if err == errNoSuchHost {
				lastErr.(*net.DNSError).IsNotFound = true
				return p, server.String(), lastErr
			}
		}
	}
	return dnsmessage.Parser{}, "", lastErr
}

func (tnet *wgtun) LookupContextHost(ctx context.Context, host string) ([]string, error) {
	if host == "" || (!tnet.hasV6 && !tnet.hasV4) {
		return nil, &net.DNSError{Err: errNoSuchHost.Error(), Name: host, IsNotFound: true}
	}
	zlen := len(host)
	if strings.IndexByte(host, ':') != -1 {
		if zidx := strings.LastIndexByte(host, '%'); zidx != -1 {
			zlen = zidx
		}
	}
	if ip, err := netip.ParseAddr(host[:zlen]); err == nil {
		return []string{ip.String()}, nil
	}

	if !isDomainName(host) {
		return nil, &net.DNSError{Err: errNoSuchHost.Error(), Name: host, IsNotFound: true}
	}
	type result struct {
		p      dnsmessage.Parser
		server string
		error
	}
	var addrsV4, addrsV6 []netip.Addr
	lanes := 0
	if tnet.hasV4 {
		lanes++
	}
	if tnet.hasV6 {
		lanes++
	}
	lane := make(chan result, lanes)
	var lastErr error
	if tnet.hasV4 {
		go func() {
			p, server, err := tnet.tryOneName(ctx, host+".", dnsmessage.TypeA)
			lane <- result{p, server, err}
		}()
	}
	if tnet.hasV6 {
		go func() {
			p, server, err := tnet.tryOneName(ctx, host+".", dnsmessage.TypeAAAA)
			lane <- result{p, server, err}
		}()
	}
	for l := 0; l < lanes; l++ {
		result := <-lane
		if result.error != nil {
			if lastErr == nil {
				lastErr = result.error
			}
			continue
		}

	loop:
		for {
			h, err := result.p.AnswerHeader()
			if err != nil && err != dnsmessage.ErrSectionDone {
				lastErr = &net.DNSError{
					Err:    errCannotMarshalDNSMessage.Error(),
					Name:   host,
					Server: result.server,
				}
			}
			if err != nil {
				break
			}
			switch h.Type {
			case dnsmessage.TypeA:
				a, err := result.p.AResource()
				if err != nil {
					lastErr = &net.DNSError{
						Err:    errCannotMarshalDNSMessage.Error(),
						Name:   host,
						Server: result.server,
					}
					break loop
				}
				addrsV4 = append(addrsV4, netip.AddrFrom4(a.A))

			case dnsmessage.TypeAAAA:
				aaaa, err := result.p.AAAAResource()
				if err != nil {
					lastErr = &net.DNSError{
						Err:    errCannotMarshalDNSMessage.Error(),
						Name:   host,
						Server: result.server,
					}
					break loop
				}
				addrsV6 = append(addrsV6, netip.AddrFrom16(aaaa.AAAA))

			default:
				if err := result.p.SkipAnswer(); err != nil {
					lastErr = &net.DNSError{
						Err:    errCannotMarshalDNSMessage.Error(),
						Name:   host,
						Server: result.server,
					}
					break loop
				}
				continue
			}
		}
	}
	// No RFC6724; instead prioritise v6 addresess first if IPv6 is enabled
	var addrs []netip.Addr
	if tnet.hasV6 {
		addrs = append(addrsV6, addrsV4...)
	} else {
		addrs = append(addrsV4, addrsV6...)
	}

	if len(addrs) == 0 && lastErr != nil {
		return nil, lastErr
	}
	saddrs := make([]string, 0, len(addrs))
	for _, ip := range addrs {
		saddrs = append(saddrs, ip.String())
	}
	return saddrs, nil
}

func partialDeadline(now, deadline time.Time, addrsRemaining int) (time.Time, error) {
	if deadline.IsZero() {
		return deadline, nil
	}
	timeRemaining := deadline.Sub(now)
	if timeRemaining <= 0 {
		return time.Time{}, errTimeout
	}
	timeout := timeRemaining / time.Duration(addrsRemaining)
	const saneMinimum = 2 * time.Second
	if timeout < saneMinimum {
		if timeRemaining < saneMinimum {
			timeout = timeRemaining
		} else {
			timeout = saneMinimum
		}
	}
	return now.Add(timeout), nil
}

// --------------------------------------------------------------------
// generic dialer
// --------------------------------------------------------------------

func (tnet *wgtun) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	var acceptV4, acceptV6 bool
	switch network {
	case "tcp", "udp", "ping":
		acceptV4 = true
		acceptV6 = true
	case "tcp4", "udp4", "ping4":
		acceptV4 = true
	case "tcp6", "udp6", "ping6":
		acceptV6 = true
	default:
		log.W("wg: dail: unknown network %q", network)
		return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError(network)}
	}

	var host string
	var port int
	if network == "ping" || network == "ping4" || network == "ping6" {
		host = address
	} else {
		var sport string
		var err error
		host, sport, err = net.SplitHostPort(address)
		if err != nil {
			log.W("wg: dail: invalid address %q: %v", address, err)
			return nil, &net.OpError{Op: "dial", Err: err}
		}
		port, err = strconv.Atoi(sport)
		if err != nil || port < 0 || port > 65535 {
			log.W("wg: dail: invalid port %q: %v", sport, err)
			return nil, &net.OpError{Op: "dial", Err: errNumericPort}
		}
	}

	rv := tnet.reqbarrier.Do(host, func() (any, error) {
		return tnet.LookupContextHost(ctx, host)
	})
	if rv.Err != nil {
		log.W("wg: dail: lookup failed %q: %v", host, rv.Err)
		return nil, &net.OpError{Op: "dial", Err: rv.Err}
	}
	allAddr, vok := rv.Val.([]string)
	if !vok {
		log.W("wg: dail: cast failed %q for val: %v", host, rv.Val)
		return nil, &net.OpError{Op: "dial", Err: errInvalidDNSResponse}
	}

	var addrs []netip.AddrPort
	for _, addr := range allAddr {
		ip, err := netip.ParseAddr(addr)
		if err == nil && ((ip.Is4() && acceptV4) || (ip.Is6() && acceptV6)) {
			addrs = append(addrs, netip.AddrPortFrom(ip, uint16(port)))
		}
	}
	if len(addrs) == 0 && len(allAddr) != 0 {
		log.W("wg: dail: no suitable address for %q / %v", host, allAddr)
		return nil, &net.OpError{Op: "dial", Err: errNoSuitableAddress}
	}

	var firstErr error
	for i, addr := range addrs {
		select {
		case <-ctx.Done():
			err := ctx.Err()
			if err == context.Canceled {
				err = errCanceled
			} else if err == context.DeadlineExceeded {
				err = errTimeout
			}
			log.W("wg: dail: %v; context done: %v", addr, err)
			return nil, &net.OpError{Op: "dial", Err: err}
		default:
		}

		dialCtx := ctx
		if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
			partialDeadline, err := partialDeadline(time.Now(), deadline, len(addrs)-i)
			if err != nil {
				if firstErr == nil {
					firstErr = &net.OpError{Op: "dial", Err: err}
				}
				break
			}
			if partialDeadline.Before(deadline) {
				var cancel context.CancelFunc
				dialCtx, cancel = context.WithDeadline(ctx, partialDeadline)
				defer cancel()
			}
		}

		var c net.Conn
		var err error
		switch network {
		case "tcp", "tcp4", "tcp6":
			c, err = tnet.DialContextTCPAddrPort(dialCtx, addr)
		case "udp", "udp4", "udp6":
			c, err = tnet.DialUDPAddrPort(netip.AddrPort{}, addr)
		case "ping", "ping4", "ping6":
			c, err = tnet.DialPingAddr(netip.Addr{}, addr.Addr())
		}
		if err == nil {
			return c, nil
		}
		log.I("wg: dial: %s: %v err %v", network, addr, err)
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = &net.OpError{Op: "dial", Err: errMissingAddress}
	}
	log.W("wg: dail: %s: %v failed: %v", network, addrs, firstErr)
	return nil, firstErr
}

// --------------------------------------------------------------------
// tcp and udp dialers
// --------------------------------------------------------------------

func fullAddrFrom(ipport netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	var protoNumber tcpip.NetworkProtocolNumber
	var nsdaddr tcpip.Address
	if ipport.Addr().Is4() {
		protoNumber = ipv4.ProtocolNumber
		nsdaddr = tcpip.AddrFrom4(ipport.Addr().As4())
	} else {
		protoNumber = ipv6.ProtocolNumber
		nsdaddr = tcpip.AddrFrom16(ipport.Addr().As16())
	}
	log.V("wg: dial: translate ipp: %v -> %v", ipport, nsdaddr)
	return tcpip.FullAddress{
		NIC:  wgnic,
		Addr: nsdaddr,
		Port: ipport.Port(),
	}, protoNumber
}

func ipportFrom(addr any) (ipp netip.AddrPort) {
	var err error
	switch addr := addr.(type) {
	case *net.TCPAddr:
		if ip, ok := netip.AddrFromSlice(addr.IP); ok {
			ipp = netip.AddrPortFrom(ip, uint16(addr.Port))
		} else {
			log.W("wg: dial: invalid tcp addr: %v", addr)
		}
	case *net.UDPAddr:
		if ip, ok := netip.AddrFromSlice(addr.IP); ok {
			ipp = netip.AddrPortFrom(ip, uint16(addr.Port))
		} else {
			log.W("wg: dial: invalid udp addr: %v", addr)
		}
	case string:
		// may error if addr is an IP addr without port
		if ipp, err = netip.ParseAddrPort(addr); err != nil {
			if ip, err2 := netip.ParseAddr(addr); err == nil {
				ipp = netip.AddrPortFrom(ip, 0)
			} else {
				log.W("wg: dial: addr: %v; err1: %v / err2: %v", addr, err, err2)
			}
		}
	default:
		log.W("wg: dial: unknown addr type: %T %v", addr, addr)
	}
	log.V("wg: dial: translate addr: %v -> %v", addr, ipp)
	return ipp
}

func (net *wgtun) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (*gonet.TCPConn, error) {
	faddr, protocol := fullAddrFrom(addr)
	return gonet.DialContextTCP(ctx, net.stack, faddr, protocol)
}

func (net *wgtun) DialContextTCP(ctx context.Context, addr *net.TCPAddr) (*gonet.TCPConn, error) {
	if addr == nil {
		return net.DialContextTCPAddrPort(ctx, netip.AddrPort{})
	}

	return net.DialContextTCPAddrPort(ctx, ipportFrom(addr))
}

func (net *wgtun) DialTCPAddrPort(addr netip.AddrPort) (*gonet.TCPConn, error) {
	faddr, protocol := fullAddrFrom(addr)
	return gonet.DialTCP(net.stack, faddr, protocol)
}

func (net *wgtun) DialTCP(addr *net.TCPAddr) (*gonet.TCPConn, error) {
	if addr == nil {
		return net.DialTCPAddrPort(netip.AddrPort{})
	}
	return net.DialTCPAddrPort(ipportFrom(addr))
}

func (net *wgtun) ListenTCPAddrPort(addr netip.AddrPort) (*gonet.TCPListener, error) {
	fa, pn := fullAddrFrom(addr)
	return gonet.ListenTCP(net.stack, fa, pn)
}

func (net *wgtun) ListenTCP(addr *net.TCPAddr) (*gonet.TCPListener, error) {
	if addr == nil {
		return net.ListenTCPAddrPort(netip.AddrPort{})
	}
	return net.ListenTCPAddrPort(ipportFrom(addr))
}

func (net *wgtun) DialUDPAddrPort(laddr, raddr netip.AddrPort) (*gonet.UDPConn, error) {
	var src, dst *tcpip.FullAddress
	var protocol tcpip.NetworkProtocolNumber
	if laddr.IsValid() || laddr.Port() > 0 {
		var addr tcpip.FullAddress
		addr, protocol = fullAddrFrom(laddr)
		src = &addr
	}
	if raddr.IsValid() || raddr.Port() > 0 {
		var addr tcpip.FullAddress
		addr, protocol = fullAddrFrom(raddr)
		dst = &addr
	}

	return gonet.DialUDP(net.stack, src, dst, protocol)
}

func (net *wgtun) ListenUDPAddrPort(laddr netip.AddrPort) (*gonet.UDPConn, error) {
	return net.DialUDPAddrPort(laddr, netip.AddrPort{})
}

func (net *wgtun) DialUDP(laddr, raddr *net.UDPAddr) (*gonet.UDPConn, error) {
	var src, dst netip.AddrPort
	if laddr != nil {
		src = ipportFrom(laddr)
	}
	if raddr != nil {
		dst = ipportFrom(raddr)
	}

	return net.DialUDPAddrPort(src, dst)
}

func (net *wgtun) ListenUDP(laddr *net.UDPAddr) (*gonet.UDPConn, error) {
	return net.DialUDP(laddr, nil)
}

// --------------------------------------------------------------------
// icmp dialer
// --------------------------------------------------------------------

type PingConn struct {
	src      PingAddr
	dst      PingAddr
	wq       waiter.Queue
	ep       tcpip.Endpoint
	deadline *time.Timer
}

type PingAddr struct{ addr netip.Addr }

func (ipp PingAddr) String() string {
	return ipp.addr.String()
}

func (ipp PingAddr) Network() string {
	if ipp.addr.Is4() {
		return "ping4"
	} else if ipp.addr.Is6() {
		return "ping6"
	}
	return "ping"
}

func (ipp PingAddr) Addr() netip.Addr {
	return ipp.addr
}

func PingAddrFromAddr(addr netip.Addr) *PingAddr {
	return &PingAddr{addr}
}

func (net *wgtun) DialPingAddr(laddr, raddr netip.Addr) (*PingConn, error) {
	if !laddr.IsValid() && !raddr.IsValid() {
		return nil, errors.New("ping dial: invalid address")
	}
	v6 := laddr.Is6() || raddr.Is6()
	bind := laddr.IsValid()
	if !bind {
		if v6 {
			laddr = netip.IPv6Unspecified()
		} else {
			laddr = netip.IPv4Unspecified()
		}
	}

	tn := icmp.ProtocolNumber4
	pn := ipv4.ProtocolNumber
	if v6 {
		tn = icmp.ProtocolNumber6
		pn = ipv6.ProtocolNumber
	}

	pc := &PingConn{
		src:      PingAddr{laddr},
		deadline: time.NewTimer(time.Hour << 10),
	}
	pc.deadline.Stop()

	ep, tcpipErr := net.stack.NewEndpoint(tn, pn, &pc.wq)
	if tcpipErr != nil {
		return nil, fmt.Errorf("ping socket: endpoint: %s", tcpipErr)
	}
	pc.ep = ep

	if bind {
		fa, _ := fullAddrFrom(netip.AddrPortFrom(laddr, 0))
		if tcpipErr = pc.ep.Bind(fa); tcpipErr != nil {
			return nil, fmt.Errorf("ping bind: %s", tcpipErr)
		}
	}

	if raddr.IsValid() {
		pc.dst = PingAddr{raddr}
		fa, _ := fullAddrFrom(netip.AddrPortFrom(raddr, 0))
		if tcpipErr = pc.ep.Connect(fa); tcpipErr != nil {
			return nil, fmt.Errorf("ping connect: %s", tcpipErr)
		}
	}

	return pc, nil
}

func (net *wgtun) ListenPingAddr(laddr netip.Addr) (*PingConn, error) {
	return net.DialPingAddr(laddr, netip.Addr{})
}

func (net *wgtun) DialPing(laddr, raddr *PingAddr) (*PingConn, error) {
	var src, dst netip.Addr
	if laddr != nil {
		src = laddr.addr
	}
	if raddr != nil {
		dst = raddr.addr
	}
	return net.DialPingAddr(src, dst)
}

func (net *wgtun) ListenPing(laddr *PingAddr) (*PingConn, error) {
	var src netip.Addr
	if laddr != nil {
		src = laddr.addr
	}
	return net.ListenPingAddr(src)
}

func (pc *PingConn) LocalAddr() net.Addr {
	return pc.src
}

func (pc *PingConn) RemoteAddr() net.Addr {
	return pc.dst
}

func (pc *PingConn) Close() error {
	pc.deadline.Reset(0)
	pc.ep.Close()
	return nil
}

func (pc *PingConn) SetWriteDeadline(t time.Time) error {
	return errors.New("not implemented")
}

func (pc *PingConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	var ip netip.Addr
	switch v := addr.(type) {
	case *PingAddr:
		ip = v.addr
	case *net.IPAddr:
		ip, _ = netip.AddrFromSlice(v.IP)
	default:
		return 0, fmt.Errorf("ping write: wrong net.Addr type")
	}
	if !((ip.Is4() && pc.src.addr.Is4()) || (ip.Is6() && pc.src.addr.Is6())) {
		return 0, fmt.Errorf("ping write: mismatched protocols")
	}

	buf := bytes.NewReader(p)
	remote, _ := fullAddrFrom(netip.AddrPortFrom(ip, 0))
	// won't block, no deadlines
	n64, tcpipErr := pc.ep.Write(buf, tcpip.WriteOptions{
		To: &remote,
	})
	if tcpipErr != nil {
		return int(n64), fmt.Errorf("ping write: %s", tcpipErr)
	}

	return int(n64), nil
}

func (pc *PingConn) Write(p []byte) (n int, err error) {
	return pc.WriteTo(p, &pc.dst)
}

func (pc *PingConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	e, notifyCh := waiter.NewChannelEntry(waiter.EventIn)
	pc.wq.EventRegister(&e)
	defer pc.wq.EventUnregister(&e)

	select {
	case <-pc.deadline.C:
		return 0, nil, os.ErrDeadlineExceeded
	case <-notifyCh:
	}

	w := tcpip.SliceWriter(p)

	res, tcpipErr := pc.ep.Read(&w, tcpip.ReadOptions{
		NeedRemoteAddr: true,
	})
	if tcpipErr != nil {
		return 0, nil, fmt.Errorf("ping read: %s", tcpipErr)
	}

	remoteAddr, _ := netip.AddrFromSlice(res.RemoteAddr.Addr.AsSlice())
	return res.Count, &PingAddr{remoteAddr}, nil
}

func (pc *PingConn) Read(p []byte) (n int, err error) {
	n, _, err = pc.ReadFrom(p)
	return
}

func (pc *PingConn) SetDeadline(t time.Time) error {
	// pc.SetWriteDeadline is unimplemented

	return pc.SetReadDeadline(t)
}

func (pc *PingConn) SetReadDeadline(t time.Time) error {
	pc.deadline.Reset(time.Until(t))
	return nil
}
