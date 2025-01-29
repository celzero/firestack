// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
)

func (pxr *proxifier) NewSocks5Proxy(id, user, pwd, ip, port string) (p *socks5, err error) {
	opts := settings.NewAuthProxyOptions("socks5", user, pwd, ip, port, nil)
	return NewSocks5Proxy(id, pxr.ctx, pxr.ctl, opts)
}

// AddProxy implements Proxifier.
func (pxr *proxifier) AddProxy(id, txt string) (x.Proxy, error) {
	defer core.Recover(core.Exit11, "prx.AddProxy."+id)
	return pxr.addProxy(id, txt)
}

func (pxr *proxifier) addProxy(id, txt string) (p Proxy, err error) {
	if len(txt) <= 0 {
		return nil, errAddProxy
	}

	// wireguard proxies have IDs starting with "wg"
	if isWG(id) {
		pxr.Lock()
		reverser := pxr.rev
		lp := pxr.lp
		pxr.Unlock()
		if p, _ = pxr.ProxyFor(id); p != nil {
			if wgp, ok := p.(WgProxy); ok && wgp.update(id, txt) {
				opts, err0 := wgIfConfigOf(id, &txt) // removes wg ifconfig from txt

				logev(err0)("proxy: updating wg(%s); ifaddrs(%v), dns(%v), mtu(%d); err? %v",
					id, opts.ifaddrs, opts.dns, opts.mtu, err)

				if err0 != nil {
					return nil, err0
				}

				err1 := wgp.IpcSet(txt)
				if err1 != nil {
					log.W("proxy: err1 updating wg(%s); %v", id, err1)
					return nil, err1
				} else {
					// sensitive log: peercfg contains private key
					log.P("proxy: updating wg(%s) len(peercfg(%d))", id, len(txt))
				}

				newcfg, readd := wgp.OnProtoChange(lp)
				if readd || len(newcfg) > 0 {
					log.W("proxy: cannot update wg(%s); readd it!", id)
					return nil, errProxyReadd
				}

				log.I("proxy: updated wg %s/%s/%s", id, lp, p.GetAddr())
				return
			} // else: recreate
		} // else: new
		// txt is both wg ifconfig and peercfg
		p, err = NewWgProxy(id, pxr.ctl, lp, reverser, txt)
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
		p, err = NewSocks5Proxy(id, pxr.ctx, pxr.ctl, opts)
	case "http":
		fallthrough
	case "https":
		p, err = NewHTTPProxy(id, pxr.ctx, pxr.ctl, opts)
	case "piph2":
		// todo: assert id == RpnH2
		p, err = NewPipProxy(pxr.ctx, pxr.ctl, opts)
	case "pipws":
		// todo: assert id == RpnWs
		p, err = NewPipWsProxy(pxr.ctx, pxr.ctl, opts)
	case "wg":
		err = fmt.Errorf("proxy: id must be prefixed with %s in %s for [%s]", WG, id, opts)
	default:
		err = errProxyScheme
	}
	return p, err
}

func Reaches(p Proxy, hostportOrIPPortCsv string, protos ...string) bool {
	if p == nil || p.Status() == END {
		return false
	}
	if len(hostportOrIPPortCsv) <= 0 {
		return true
	}

	hastcp := has(protos, "tcp") || has(protos, "tcp4") || has(protos, "tcp6")
	hasudp := has(protos, "udp") || has(protos, "udp4") || has(protos, "udp6")
	hasicmp := has(protos, "icmp") || has(protos, "icmp4") || has(protos, "icmp6")

	if !hastcp && !hasudp && !hasicmp { // fail open
		hastcp = true
		hasudp = true
		hasicmp = true
		protos = []string{"tcp", "udp", "icmp"}
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
		} else {
			x = host
		}
		on, _ := strconv.ParseUint(port, 10, 16)
		if on == 0 {
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
	log.V("proxy: %s reaches: testing for %s", p.ID(), ipps)
	tests := make([]core.WorkCtx[bool], 0)
	for _, ipp := range ipps {
		ippstr := ipp.String()
		if hastcp {
			tests = append(tests, tcpReachesWorkCtx(p, ippstr))
		}
		if hasudp {
			tests = append(tests, udpReachesWorkCtx(p, ippstr))
		}
		if hasicmp {
			tests = append(tests, icmpReachesWorkCtx(p, ipp))
		}
	}

	if len(tests) <= 0 {
		log.W("proxy: %s reaches: %v / %v; no tests for %s",
			p.ID(), hostportOrIPPortCsv, ipps, protos)
		return false
	}

	ok, who, err := core.Race("reach."+p.ID(), getproxytimeout, tests...)

	log.D("proxy: %s reaches: %v => %v ok? %t; who: %d, err? %v",
		p.ID(), hostportOrIPPortCsv, ipps, ok, who, err)

	return ok
}

func AnyAddrForUDP(ipp netip.AddrPort) (proto, anyaddr string) {
	anyaddr = "0.0.0.0:0"
	proto = "udp4"
	if ipp.Addr().Is6() {
		proto = "udp6"
		anyaddr = "[::]:0"
	}
	return
}

func tcpReachesWorkCtx(p Proxy, ippstr string) core.WorkCtx[bool] {
	return func(_ context.Context) (bool, error) {
		return tcpReaches(p, ippstr)
	}
}

func tcpReaches(p Proxy, ippstr string) (bool, error) {
	start := time.Now()
	c, err := p.Dial("tcp", ippstr)
	defer core.CloseConn(c)

	rtt := time.Since(start)
	ok := err == nil
	// net.OpError => os.SyscallError => syscall.Errno
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

func udpReachesWorkCtx(p Proxy, ippstr string) core.WorkCtx[bool] {
	return func(_ context.Context) (bool, error) {
		return udpReaches(p, ippstr)
	}
}

func udpReaches(p Proxy, ippstr string) (bool, error) {
	start := time.Now()
	c, err := p.Dial("udp", ippstr)
	defer core.CloseConn(c)

	rtt := time.Since(start)
	ok := err == nil
	// net.OpError => os.SyscallError => syscall.Errno
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

func icmpReachesWorkCtx(p Proxy, ipp netip.AddrPort) core.WorkCtx[bool] {
	return func(_ context.Context) (bool, error) {
		return IcmpReaches(p, ipp)
	}
}

func IcmpReaches(p Proxy, ipp netip.AddrPort) (bool, error) {
	if !ipp.IsValid() {
		return false, errInvalidAddr
	}

	proto, anyaddr := AnyAddrForUDP(ipp)
	c, err := p.Probe(proto, anyaddr)
	defer core.CloseConn(c)

	if c == nil || err != nil {
		err = core.OneErr(err, errNotUDPConn)
		return false, err
	}

	ok, rtt, err := core.Ping(c, ipp)

	// net.OpError => os.SyscallError => syscall.Errno
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

func hasroute(p Proxy, ipp string) bool {
	if p == nil {
		return false
	}
	return p.Router().Contains(ipp)
}

func healthy(p Proxy) error {
	if p == nil {
		return errProxyNotFound
	}

	pid := p.ID()
	if local(pid) { // fast path for local proxies which are always ok
		return nil
	}

	if p.Status() == END {
		return errProxyStopped
	} // TODO: err on TNT, TKO?

	stat := p.Router().Stat()
	now := now()
	lastOK := stat.LastOK
	lastOKNeverOK := lastOK <= 0
	lastOKBeyondThres := now-lastOK > lastOKThreshold.Milliseconds()
	if lastOKNeverOK || lastOKBeyondThres {
		go p.onNotOK()
		return fmt.Errorf("proxy: %s not ok; lastOK: zz? %t / thres? %t",
			pid, lastOKNeverOK, lastOKBeyondThres)
	} else if now-lastOK > tzzTimeout.Milliseconds() {
		go p.onNotOK()
	}

	return nil // ok
}

func has[T comparable](pids []T, pid T) bool {
	for _, v := range pids {
		if v == pid {
			return true
		}
	}
	return false
}

func Same(a, b Proxy) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Handle() == b.Handle()
}

func ViaID(p Proxy) string {
	const novia = ""
	if p == nil {
		return novia
	}
	if v, _ := p.Router().Via(); v != nil {
		if v.ID() == p.ID() {
			log.W("proxy: %s via %s; loop detected", p.ID(), v.ID())
			return novia
		}
		return v.ID()
	}
	return novia
}
