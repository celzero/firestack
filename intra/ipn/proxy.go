// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
)

func (pxr *proxifier) NewSocks5Proxy(id, user, pwd, ip, port string) (p *socks5, err error) {
	opts := settings.NewAuthProxyOptions("socks5", user, pwd, ip, port, nil)
	return NewSocks5Proxy(id, pxr.ctl, opts)
}

func (pxr *proxifier) AddProxy(id, txt string) (x.Proxy, error) {
	return pxr.addProxy(id, txt)
}

func (pxr *proxifier) addProxy(id, txt string) (p Proxy, err error) {
	if len(txt) <= 0 {
		return nil, errAddProxy
	}
	// wireguard proxies have IDs starting with "wg"
	if strings.HasPrefix(id, WG) || strings.Compare(id, RpnWg) == 0 {
		if p, _ = pxr.ProxyFor(id); p != nil {
			if wgp, ok := p.(WgProxy); ok && wgp.update(id, txt) {
				log.I("proxy: updating wg %s/%s", id, p.GetAddr())

				ifaddrs, _, _, dnsh, _, mtu, err0 := wgIfConfigOf(id, &txt) // removes wg ifconfig from txt
				if err0 != nil {
					log.W("proxy: err0 updating wg(%s); %v", id, err0)
					return nil, err0
				} else {
					log.V("proxy: updating wg(%s); ifaddrs(%v), dns(%v), mtu(%d)", id, ifaddrs, dnsh, mtu)
				}

				err1 := wgp.IpcSet(txt)
				if err1 != nil {
					log.W("proxy: err1 updating wg(%s); %v", id, err1)
					return nil, err1
				} else {
					// sensitive log: peercfg contains private key
					log.P("proxy: updating wg(%s) len(peercfg(%d))", id, len(txt))
				}

				err2 := wgp.Refresh()
				if err2 != nil {
					log.W("proxy: err2 updating wg(%s); %v", id, err2)
					return nil, err2
				}
				return
			} // else: create anew
		}
		// txt is both wg ifconfig and peercfg
		p, err = NewWgProxy(id, pxr.ctl, pxr.rev, txt)
	} else {
		var strurl string
		var usr string
		var pwd string
		var u *url.URL
		// scheme://usr:pwd@domain.tld:8080/p/a/t/h?q&u=e&r=y
		u, err = url.Parse(txt)
		if err != nil {
			return nil, err
		}

		if u.User != nil {
			usr = u.User.Username()    // usr
			pwd, _ = u.User.Password() // pwd
		}
		strurl = u.Host + u.RequestURI() // domain.tld:8080/p/a/t/h?q&u=e&r=y#f,r
		addrs := strings.Split(u.Fragment, ",")
		// opts may be nil
		opts := settings.NewAuthProxyOptions(u.Scheme, usr, pwd, strurl, u.Port(), addrs)

		p, err = pxr.fromOpts(id, opts) // opts may be nil
	}

	if err != nil {
		log.P("proxy: add %s failed; cfg: %v", id, txt)
		log.W("proxy: add %s failed; err: %v", id, err)
		return nil, err
	} else if p == nil {
		log.P("proxy: add %s nil; cfg: %v", id, txt)
		log.W("proxy: add %s nil; txt: %d", id, len(txt))
		return nil, errAddProxy
	} else if ok := pxr.add(p); !ok {
		return nil, errAddProxy
	}

	log.I("proxy: added %s/%s/%s", p.ID(), p.Type(), p.GetAddr())
	return
}

func (pxr *proxifier) fromOpts(id string, opts *settings.ProxyOptions) (Proxy, error) {
	if opts == nil {
		return nil, errNoOpts
	}

	var p Proxy = nil
	var err error = nil
	switch opts.Scheme {
	case "socks5":
		p, err = NewSocks5Proxy(id, pxr.ctl, opts)
	case "http":
		fallthrough
	case "https":
		p, err = NewHTTPProxy(id, pxr.ctl, opts)
	case "piph2":
		// todo: assert id == RpnH2
		p, err = NewPipProxy(pxr.ctl, opts)
	case "pipws":
		// todo: assert id == RpnWs
		p, err = NewPipWsProxy(pxr.ctl, opts)
	case "wg":
		err = fmt.Errorf("proxy: id must be prefixed with %s in %s for [%s]", WG, id, opts)
	default:
		err = errProxyScheme
	}
	return p, err
}

func Reaches(p Proxy, hostportOrIPPortCsv string) bool {
	if p == nil {
		return false
	}
	if len(hostportOrIPPortCsv) <= 0 {
		return true
	}
	// upstream := dnsx.Default
	// if pdns := p.DNS(); len(pdns) > 0 {
	//	upstream = pdns
	// }
	ipps := make([]netip.AddrPort, 0)
	for _, x := range strings.Split(hostportOrIPPortCsv, ",") {
		host, port, err := net.SplitHostPort(x)
		if err != nil {
			port = "80"
			x = host
		}
		on, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			log.W("wg: %s router: %s port %s; err: %v",
				p.ID(), x, port, err)
			on = 80
		}
		if len(x) > 0 { // x may be ip, host
			ips := dialers.For(x)
			for _, ip := range ips {
				ipp := netip.AddrPortFrom(ip, uint16(on))
				ipps = append(ipps, ipp)
			}
		}
	}
	tests := make([]core.Work[bool], 0)
	for _, ipp := range ipps {
		addr := ipp.String()
		tests = append(tests, func() (bool, error) {
			c, err := p.Dial("tcp", addr)
			defer core.CloseConn(c)

			ok := err == nil
			if syserr := new(os.SyscallError); errors.As(err, &syserr) {
				ok = syserr.Err == syscall.ECONNREFUSED
			}
			log.V("wg: %s router: %s reaches? %t; err? %v", p.ID(), addr, ok, err)
			return ok, err
		})
	}

	if len(tests) <= 0 {
		log.W("wg: %s router: %v; no tests", p.ID(), hostportOrIPPortCsv)
		return false
	}

	ok, who, err := core.Race("reach."+p.ID(), getproxytimeout, tests...)

	log.D("wg: %s router: %v => %v reaches? %t; who: %d, err? %v",
		p.ID(), hostportOrIPPortCsv, ipps, ok, who, err)

	return ok
}

func AnyAddrFor(ipp netip.AddrPort) (proto, anyaddr string) {
	anyaddr = "0.0.0.0:0"
	proto = "udp4"
	if ipp.Addr().Is6() {
		proto = "udp6"
		anyaddr = "[::]:0"
	}
	return
}

func tcpReaches(p Proxy, ippstr string) core.Work[bool] {
	return func() (bool, error) {
		start := time.Now()
		c, err := p.Dial("tcp", ippstr)
		defer core.CloseConn(c)

		rtt := time.Since(start)
		ok := err == nil
		if syserr := new(os.SyscallError); errors.As(err, &syserr) {
			ok = ok || syserr.Err == syscall.ECONNREFUSED
		}

		log.V("proxy: %s reaches: tcp: %s ok? %t, rtt: %s; err: %v",
			p.ID(), ippstr, ok, rtt, err)
		if ok { // wipe out err as it makes core.Race discard "ok"
			err = nil
		}
		return ok, err
	}
}

func icmpReaches(p Proxy, ipp netip.AddrPort) core.Work[bool] {
	return func() (bool, error) {
		proto, anyaddr := AnyAddrFor(ipp)
		c, err := p.Probe(proto, anyaddr)
		defer core.CloseConn(c)

		if c == nil || err != nil {
			if err == nil {
				err = errNotUDPConn
			}
			return false, err
		}

		ok, rtt, err := core.Ping(c, ipp)

		if syserr := new(os.SyscallError); errors.As(err, &syserr) {
			ok = ok || syserr.Err == syscall.ECONNREFUSED
		}

		log.V("proxy: %s reaches: icmp: %s ok? %t, rtt: %v; err: %v",
			p.ID(), ipp, ok, rtt, err)
		if ok { // wipe out err as it makes core.Race discard "ok"
			err = nil
		}
		return ok, err
	}
}
