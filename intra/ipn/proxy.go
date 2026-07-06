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
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
)

// must be kept in sync with rpn's Conf() impls (like in yegor.go)
const anyCountryCode = "**"   // random country
const noCountryForOldMen = "" // zz

func anycc(acc RpnAcc) string {
	cc := anyCountryCode
	if !acc.MultiCountry() {
		cc = noCountryForOldMen
	}
	return cc
}

func (pxr *proxifier) NewSocks5Proxy(id, user, pwd, ip, port string) (p *socks5, err error) {
	opts := settings.NewAuthProxyOptions("socks5", user, pwd, ip, port, nil)
	return NewSocks5Proxy(id, pxr.ctx, pxr.ctl, pxr, opts)
}

func (pxr *proxifier) Underlay(id string, c x.Controller) x.Proxy {
	return newBasicProxy(id, fakeBaseAddr, pxr.ctx, c, pxr)
}

// AddProxy implements Proxifier.
func (pxr *proxifier) AddProxy(id, txt string) (x.Proxy, error) {
	defer core.Recover(core.Exit11, "prx.AddProxy."+id)

	pid := id
	if isRPN(pid) { // must call addRpnProxy instead
		return nil, errAddProxyAsRpn
	}

	return pxr.addProxy(pid, txt)
}

// cc may be a fully qualified ID in case of removing the main proxy.
func (pxr *proxifier) removeRpnProxy(acc RpnAcc, cc string) bool {
	if acc == nil || core.IsNil(acc) {
		return false
	}
	typ := acc.ProviderID()
	if !isRPN(typ) {
		return false
	}
	if !acc.MultiCountry() && cc != noCountryForOldMen {
		log.W("proxy: rpn: remove: %s not multi-country; [%s] ignored", typ, cc)
		cc = noCountryForOldMen
	}

	log.I("proxy: rpn: remove: %s[%s]", typ, cc)

	rpnid := cc // cc itself may be a fully qualified id if removing main proxy
	if !strings.HasPrefix(cc, typ) {
		rpnid = typ + cc
	}

	return pxr.removeProxy(rpnid, true /*force*/)
}

// cc may be a fully qualified ID in case when re-adding the main proxy.
func (pxr *proxifier) addRpnProxy(acc RpnAcc, cc string) (Proxy, *x.RpnServer, error) {
	if acc == nil || core.IsNil(acc) {
		return nil, nil, errNotRpnAcc
	}

	typ := acc.ProviderID()
	if !isRPN(typ) {
		return nil, nil, errNotRpnID
	}

	if !acc.MultiCountry() && cc != noCountryForOldMen {
		log.W("proxy: rpn: add: %s not multi-country; [%s] ignored", typ, cc)
		cc = noCountryForOldMen
	}

	log.I("proxy: rpn: add: %s[%s]", typ, cc)

	// cc may be "typcity;cc" (see var rpnid below)
	// but we need cc to be "city;cc"  (ref struct RpnServer.Key)
	cc, _ = strings.CutPrefix(cc, typ)

	txt, srv, err := acc.Conf(cc)
	if err != nil {
		return nil, nil, err
	}

	rpnid := typ + cc

	// TODO: addProxy may update wg in-place, even if DNS addrs have changed
	p, err := pxr.addProxy(rpnid, txt)
	if p == nil {
		pxr.postAddRpnProxyError(acc) // remove from pxr.rp if exists
		return nil, srv, core.JoinErr(err, errAddProxy)
	}

	proxy, err := pxr.postAddRpnProxy(p, srv, acc)
	return proxy, srv, err
}

// TODO: on add / update a via proxy; refresh all dependent origins
func (pxr *proxifier) addRpnProxy2(p Proxy, acc RpnAcc) (Proxy, error) {
	proxyid := idstr(p)
	providerid := acc.ProviderID()
	if !isRPN(proxyid) || !isRPN(providerid) {
		return nil, errNotRpnProxy
	}

	ok := pxr.add(p)
	if !ok {
		pxr.postAddRpnProxyError(acc) // remove from pxr.rp if exists
		return nil, errAddProxy
	}

	who := "proxy.addrpn2." + proxyid
	// TODO: setup hop from mainCountryCode to forked rpn proxies
	core.Gx(who, func() { pxr.refreshHopOriginsIfAny(p, who) })

	return pxr.postAddRpnProxy(p, nil, acc)
}

func (pxr *proxifier) postAddRpnProxy(p Proxy, srv *x.RpnServer, acc RpnAcc) (_ Proxy, err error) {
	proxyid := idstr(p)
	provider := acc.ProviderID()

	pxr.rpnmu.Lock()
	rp := pxr.rp[provider]
	pxr.rpnmu.Unlock()

	// add rpn proxy iff rpn proxy isn't multicountry (in which case only one
	// instance of it can exist and hence it is being re-added if already present)
	// or, if it is multicountry, add it only if the proxy is the main proxy,
	// as forked children countries only need be added as plain-old proxies
	// which is done before calling this function (ie, a no-op)
	if rp == nil {
		rp, err = asRpnProxy(p, srv, acc, pxr)
		if rp == nil { // should not happen; unexpected!
			defer pxr.removeProxy(proxyid, true /*force*/)
			return nil, core.JoinErr(err, errAddProxyAsRpn)
		}
		// TODO: setup hop from mainCountryCode to forked rpn proxies
		pxr.rpnmu.Lock()
		pxr.rp[provider] = rp // removed on unregister
		pxr.rpnmu.Unlock()
		log.I("proxy: rpn: add: post: registered %s as rpn proxy for %s", proxyid, provider)
	} else if idstr(p) == idstr(rp) {
		log.I("proxy: rpn: add: post: %s already registered for %s; emplacing...", proxyid, provider)
		core.Gx("proxy.rpnemplace."+idstr(p), func() { rp.Emplace(p) }) // may fail
	}

	return p, nil
}

func (pxr *proxifier) postAddRpnProxyError(acc RpnAcc) (removed bool) {
	return pxr.unregisterRpn(acc.ProviderID()) // unregisters if it exists
}

func (pxr *proxifier) forceAddProxy(id, txt string) (p Proxy, err error) {
	return pxr.addOrUpdateProxy(id, txt, true /*force*/)
}

func (pxr *proxifier) addProxy(id, txt string) (p Proxy, err error) {
	return pxr.addOrUpdateProxy(id, txt, false /*force*/)
}

func (pxr *proxifier) addOrUpdateProxy(id, txt string, forceAdd bool) (p Proxy, err error) {
	if len(id) <= 0 {
		return nil, errAddProxy
	}

	defer func() {
		if err != nil {
			core.Gx("proxy.add.refreshHop"+id, func() { pxr.refreshHopOriginsIfAny(p, "addProxy."+id) })
		}
	}()

	// wireguard proxies have IDs starting with "wg"
	if isWG(id) {
		pxr.RLock()
		lp := pxr.lp
		pxr.RUnlock()
		if forceAdd {
			p, err = NewWgProxy(pxr.ctx, id, pxr.ctl, pxr, lp, txt)
		} else if p, _ = pxr.proxyFor(id); p != nil {
			hdl := hdlstr(p)
			// note that rpnp does not implement the WgProxy interface
			if wgp, ok := p.(WgProxy); ok && wgp.update(id, txt) {
				newcfg, readd := wgp.OnProtoChange(lp)
				if readd || len(newcfg) > 0 {
					p = nil
					log.W("proxy: add: cannot update wg(%s@%s); readd it!", id, hdl)
				} else {
					log.I("proxy: add: updated wg %s@%s/%s/%s", id, hdl, lp, p.GetAddr())
					core.Go2("proxy.update", pxr.obs.OnProxyUpdated, id, hdl)
					return
				}
			} else { // else: recreate
				p = nil
				log.W("proxy: add: update not ok for wg(%s@%s); readd...", id, hdl)
			}
		}
		if !forceAdd && p == nil {
			// txt is both wg ifconfig and peercfg
			p, err = NewWgProxy(pxr.ctx, id, pxr.ctl, pxr, lp, txt)
		}
	} else if len(txt) <= 0 {
		p = NewBasicProxy(id, pxr.ctx, pxr.ctl, pxr)
		err = nil
	} else {
		var strurl string
		var usr string
		var pwd string
		var u *url.URL
		// go.dev/play/p/2DTBGO0Wisj
		// scheme://usr:pwd@domain.tld:port/p/a/t/h?q&u=e&r=y#f,r
		u, err = url.Parse(txt)
		if err != nil {
			return nil, err
		}

		if u.User != nil {
			usr = u.User.Username()    // usr
			pwd, _ = u.User.Password() // pwd
		}
		strurl = u.Host + u.RequestURI() // domain.tld:port/p/a/t/h?q&u=e&r=y#f,r
		addrs := strings.Split(u.Fragment, ",")
		// opts may be nil
		opts := settings.NewAuthProxyOptions(u.Scheme, usr, pwd, strurl, u.Port(), addrs)

		p, err = pxr.fromOpts(id, opts) // opts may be nil
	}

	if err != nil {
		log.P("proxy: add: %s failed; cfg: %v", id, txt)
		log.W("proxy: add: %s failed; force? %t; err: %v", id, forceAdd, err)
		return nil, err
	} else if p == nil {
		log.P("proxy: add: %s nil; cfg: %v", id, txt)
		log.W("proxy: add: %s nil; force? %t; txt: %d", id, forceAdd, len(txt))
		return nil, errAddProxy
	} else if ok := pxr.add(p); !ok {
		return nil, errAddProxy
	}

	log.I("proxy: add: force? %t; done %s@%s/%s/%s", forceAdd, idstr(p), hdlstr(p), typstr(p), p.GetAddr())
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
		p, err = NewSocks5Proxy(id, pxr.ctx, pxr.ctl, pxr, opts)
	case "http":
		fallthrough
	case "https":
		p, err = NewHTTPProxy(id, pxr.ctx, pxr.ctl, pxr, opts)
	case "piph2":
		// todo: assert id == RpnH2
		p, err = NewPipProxy(pxr.ctx, pxr.ctl, pxr, opts)
	case "pipws":
		// todo: assert id == RpnWs
		p, err = NewPipWsProxy(pxr.ctx, pxr.ctl, pxr, opts)
	case "wg":
		err = fmt.Errorf("proxy: id must be prefixed with %s in %s for [%s]", WG, id, opts)
	default:
		err = errProxyScheme
	}
	return p, err
}

func Reaches(p Proxy, urlOrHostPortOrIPPortCsv string, protos ...string) bool {
	if p == nil {
		return false
	}
	st := p.Status()
	if err := candial2(st); err != nil {
		log.W("proxy: %s reaches: err %v, status(%s)", idstr(p), err, pxstatus(st))
		return false
	}
	if len(urlOrHostPortOrIPPortCsv) <= 0 {
		return true
	}

	// auto:[ip,http,https]:[v4,v6]
	if strings.HasPrefix(urlOrHostPortOrIPPortCsv, "auto") {
		const autoSize = 5
		prefs := strings.Split(urlOrHostPortOrIPPortCsv, ":")
		scheme := "https"
		if len(prefs) >= 2 {
			scheme = prefs[1]
		}
		ipfrag := ""
		if len(prefs) >= 3 {
			// TODO: change "ipv4", "ipv6", "tcp4", "tcp6", "udp4", "udp6" to "v4", "v6"
			ipfrag = prefs[2] // "v4", "v6", ""
		}

		protos = []string{}
		switch scheme {
		case "http", "https":
			urls := []string{}
			for _, h := range dialers.SampleHosts(autoSize, ipfrag) {
				u := url.URL{
					Scheme:   scheme,
					Host:     h,
					Fragment: ipfrag, // if empty, connectivity over v4+v6 is attempted
				}
				urls = append(urls, u.String())
			}
			log.I("proxy: %s reaches: auto:http for %v urls", idstr(p), urls)
			urlOrHostPortOrIPPortCsv = strings.Join(urls, ",")
		case "ip":
			ips := make([]netip.Addr, 0, autoSize)
			log.I("proxy: %s reaches: auto:ip for %v ips", idstr(p), ips)

			if ipfrag == "v4" {
				protos = append(protos, "tcp4", "udp4")
			} else if ipfrag == "v6" {
				protos = append(protos, "tcp6", "udp6")
			} else {
				protos = append(protos, "tcp", "udp")
			}
			for _, ip := range dialers.SampleIPs(autoSize, ipfrag) {
				if ipfrag == "v4" && ip.Is4() {
					ips = append(ips, ip)
				} else if ipfrag == "v6" && ip.Is6() {
					ips = append(ips, ip)
				} else if ipfrag == "" {
					ips = append(ips, ip) // both v4 and v6
				}

			}
			// default port for ip:port is 80 if left unspecified (see below)
			urlOrHostPortOrIPPortCsv = strings.Join(core.Map(ips, func(ip netip.Addr) string { return ip.String() }), ",")
		default:
			log.E("proxy: %s reaches: auto:%s for %v protos; unsupported scheme", idstr(p), scheme, protos)
			return false
		}
	}

	pid := idstr(p)
	hostportOrIPPort := strings.Split(urlOrHostPortOrIPPortCsv, ",")
	if urls, oth := extractHttpURLs(urlOrHostPortOrIPPortCsv); len(urls) > 0 {
		log.V("proxy: %s reaches: testing for %v", idstr(p), urls)

		hostportOrIPPort = oth
		tests := make([]core.WorkCtx[bool], 0)
		for _, u := range urls {
			tests = append(tests, httpsReachesWorkCtx(p, u))
		}
		threeSecsPerTest := time.Duration(len(tests)) * 3 * time.Second

		ok, who := core.First("reach.http."+pid, threeSecsPerTest, tests...)

		logeif(!ok)("proxy: %s #%d reaches: %v verdict (https): reachable? %t",
			pid, who, urlOrHostPortOrIPPortCsv, ok)

		if !ok || len(oth) <= 0 {
			return ok
		}
	}

	// Original logic for host:port or ip:port
	hastcp := has(protos, "tcp") || has(protos, "tcp4") || has(protos, "tcp6")
	hasudp := has(protos, "udp") || has(protos, "udp4") || has(protos, "udp6")
	hasicmp := has(protos, "icmp") || has(protos, "icmp4") || has(protos, "icmp6")

	if !hastcp && !hasudp && !hasicmp { // fail open
		hastcp = true
		hasudp = true
		hasicmp = false
		protos = []string{"tcp", "udp"}
	}
	// upstream := dnsx.Default
	// if pdns := p.DNS(); len(pdns) > 0 {
	//	upstream = pdns
	// }
	ipps := make([]netip.AddrPort, 0)
	for _, x := range hostportOrIPPort {
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

	n := 0
	log.V("proxy: %s reaches: testing for %s", pid, ipps)
	tests := make([][]core.WorkCtx[bool], 0)
	for _, ipp := range ipps {
		fns := make([]core.WorkCtx[bool], 0)
		ippstr := ipp.String()
		if hastcp {
			fns = append(fns, tcpReachesWorkCtx(p, ippstr))
		}
		if hasudp {
			fns = append(fns, udpReachesWorkCtx(p, ippstr))
		}
		if hasicmp {
			fns = append(fns, icmpReachesWorkCtx(p, ipp))
		}
		tests = append(tests, fns)
		n += len(fns)
	}

	if n <= 0 {
		log.W("proxy: %s reaches: %v / %v; no tests for %s",
			pid, urlOrHostPortOrIPPortCsv, ipps, protos)
		return false
	}

	ok, who, errs := core.Race("reach"+"."+pid, getproxytimeout, every(pid, tests)...)

	logeif(!ok)("proxy: %s #%d reaches: %v => %v verdict (%s): reachable? %t; errs? %v",
		pid, who, urlOrHostPortOrIPPortCsv, ipps, protos, ok, errs)

	return ok
}

func httpclient(p Proxy, url *url.URL) (client *http.Client) {
	v4, v6 := true, true
	switch url.Fragment {
	case "tcp", "udp":
	case "v4", "ipv4", "upd4", "tcp4":
		v6 = false // only v4
	case "v6", "ipv6", "upd6", "tcp6":
		v4 = false // only v6
	default:
	}
	// Lightweight transport for one-time use
	client = &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					if url.Scheme == "https" {
						port = "443"
					} else {
						port = "80"
					}
				} else {
					addr = host
				}
				on, _ := strconv.ParseUint(port, 10, 16)
				if on == 0 {
					if url.Scheme == "https" {
						on = 443
					} else {
						on = 80
					}
				}
				ipps := make([]netip.AddrPort, 0)
				ips := dialers.For(addr)
				for _, ip := range ips {
					if v4 && ip.Is4() || v6 && ip.Is6() {
						ipp := netip.AddrPortFrom(ip, uint16(on))
						ipps = append(ipps, ipp)
					}
				}

				logeif(len(ipps) == 0)("proxy: %s reaches: dial(%s, %s [among %v]) for %s",
					idstr(p), network, addr, ipps, url)

				if len(ipps) <= 0 {
					return nil, errNoSuitableAddress
				}

				n := rand.Intn(len(ipps))

				// filter out the revelant IPs ourselves as dialers pkg does not
				// respect ip-specific network type "tcp4" or "tcp6"
				// see: cdial.go:commondial2()
				return p.Dial(network, ipps[n].String())
			},
			// Disable connection pooling for one-time use
			DisableKeepAlives:   true,
			MaxIdleConns:        -1,
			MaxIdleConnsPerHost: -1,
			// Short timeouts for quick failure detection
			ResponseHeaderTimeout: 3 * time.Second,
			// TODO: Prefer h1 to simplify conn handling?
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: 3 * time.Second,
		},
	}
	return
}

func every(who string, tests [][]core.WorkCtx[bool]) []core.WorkCtx[bool] {
	all := make([]core.WorkCtx[bool], 0, len(tests))
	for _, t := range tests {
		all = append(all, func(ctx context.Context) (bool, error) {
			okays, errs := core.All("reach.all."+who, getproxytimeout, t...)
			// overall is false if any okays is false, or if all errs are not nil
			overall := core.IsAll(errs, func(err error) bool { return err == nil }) &&
				core.IsAll(okays, func(ok bool) bool { return ok })
			return overall, core.JoinErr(errs...)
		})
	}
	return all
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

	log.V("proxy: %s reaches: udp: %s ok? %t, rtt: %s; err: %v",
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

func viaCanListen(network string, hop Proxy) error {
	switch network {
	case "tcp", "tcp4":
		c4, err4 := hop.Accept("udp", net.JoinHostPort(anyaddr4.String(), "0"))
		core.Close(c4)
		if err4 != nil && errors.Is(err4, errAcceptNotSupported) {
			return err4
		}
		return nil
	case "udp", "udp4":
		c4, err4 := hop.Announce("udp", net.JoinHostPort(anyaddr4.String(), "0"))
		core.Close(c4)
		if err4 != nil && errors.Is(err4, errAnnounceNotSupported) {
			return err4
		}
		return nil
	case "tcp6":
		c6, err6 := hop.Accept("tcp", net.JoinHostPort(anyaddr6.String(), "0"))
		core.Close(c6)
		if err6 != nil && errors.Is(err6, errAcceptNotSupported) {
			return err6
		}
		return nil
	case "udp6":
		c6, err6 := hop.Announce("udp", net.JoinHostPort(anyaddr6.String(), "0"))
		core.Close(c6)
		if err6 != nil && errors.Is(err6, errAnnounceNotSupported) {
			return err6
		}
		return nil
	default:
		return fmt.Errorf("unsupported network: %s", network)
	}
}

// viaSupportsIPFamily returns error if hop cannot route same ip families as orig
func viaSupportsIPFamily(orig Proxy, hop Proxy) error {
	pxCan4 := orig.Router().IP4()
	hopCan4 := hop.Router().IP4()
	pxCan6 := orig.Router().IP6()
	hopCan6 := hop.Router().IP6()
	if pxCan4 { // suffices if px's ip4 is routable over hop
		if !hopCan4 {
			return errHop4Gateway
		} // else: do not need to check for ip6 routes
	} else if pxCan6 { // ip6 ok & px does not need ip4
		if !hopCan6 {
			return errHop6Gateway
		} // else: can at least route ip6, which is enough for px
	} else { // unlikely that px cannot do both ip4 & ip6
		return errHopProxyRoutes
	}
	return nil
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

	pid := idstr(p)
	typ := typstr(p)
	if local(pid) || noop(typ) { // fast path for local proxies which are always ok
		return nil
	}

	status := p.Status()
	if err := candial2(status); err != nil {
		return err
	} // TODO: err on TNT, TKO?

	// TODO: via, _ := p.Router().Via()

	stat := p.Router().Stat()
	now := now()
	age := now - stat.LastOpen

	oldEnough := age > ageThreshold.Milliseconds()
	lastOK := stat.LastOK
	lastOKNeverOK := lastOK <= 0
	lastOKBeyondThres := now-lastOK > lastOKThreshold.Milliseconds()
	if (oldEnough && lastOKNeverOK) || lastOKBeyondThres {
		core.Gx("proxy.health.TNT."+pid, func() { p.onNotOK() }) // not ok for too long
		return fmt.Errorf("proxy: %s not ok; age: %s / %s / lastOKNeverOK? %t / lastOKBeyondThres? %t",
			pid, core.FmtMillis(age), pxstatus(status), lastOKNeverOK, lastOKBeyondThres)
	} else if now-lastOK > tzzTimeout.Milliseconds() {
		core.Gx("proxy.health.TZZ."+pid, func() { p.Ping() })
	} else if status != TOK {
		core.Gx("proxy.health.TOK."+pid, func() { p.Ping() })
	}

	return nil // ok
}

func has[T comparable](pids []T, pid T) bool {
	return slices.Contains(pids, pid)
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
	v, _ := p.Router().Via()
	if v == nil {
		return novia
	}
	// TODO: change all equality checks on ID() to use idstr
	vid := idstr(v)
	pid := idstr(p)
	if vid == pid {
		log.W("proxy: %s via %s; loop detected", p.ID(), v.ID())
		return novia
	}
	return vid
}

func candial2(st int32) error {
	if st == END {
		return errProxyStopped
	}
	if st == TPU {
		return errProxyPaused
	}
	return nil
}

func candial(state *atomic.Int32) error {
	return candial2((*state).Load())
}

func canserve2(st int32) error {
	if st == END {
		return errProxyStopped
	}
	return nil
}

func canserve(state *atomic.Int32) error {
	return canserve2(state.Load())
}

// removeElem removes the all occurrences of rmv from s.
func removeElem[T comparable](s []T, rmv T) []T {
	return core.WithoutElem(s, rmv)
}

// addElem adds add to s if it is not already present.
func addElem[T comparable](s []T, add T) []T {
	return core.WithElem(s, add)
}

// extractHttpURLs extracts valid URLs from comma-separated input
func extractHttpURLs(csv string) (urls []*url.URL, oth []string) {
	for x := range strings.SplitSeq(csv, ",") {
		x = strings.TrimSpace(x)
		if len(x) == 0 {
			continue
		}
		// Check if it's a URL (contains scheme)
		if u, err := url.Parse(x); err == nil && strings.Contains(u.Scheme, "http") {
			urls = append(urls, u)
		} else {
			oth = append(oth, x)
		}
	}
	return
}

func httpsReachesWorkCtx(p Proxy, url *url.URL) core.WorkCtx[bool] {
	return func(ctx context.Context) (bool, error) {
		return httpsReaches(idstr(p), httpclient(p, url), url)
	}
}

func httpsReaches(who string, c *http.Client, url *url.URL) (bool, error) {
	start := time.Now()

	req, err := http.NewRequest("HEAD", url.String(), nil)
	if err != nil {
		return false, fmt.Errorf("proxy: reaches: err creating req: %w", err)
	}

	setua := settings.SetUserAgent.Load()
	if setua {
		req.Header.Set("User-Agent", settings.AndroidCcUa)
	}

	statuscode := -1
	resp, err := c.Do(req)
	if resp != nil {
		defer core.Close(resp.Body)
		statuscode = resp.StatusCode
	}

	ok := statuscode > 0

	logeif(!ok)("proxy: %s reaches: %v (ua? %t); ok? %t, status: %d, rtt: %s; err: %v",
		who, url, setua, ok, statuscode, core.FmtPeriod(time.Since(start)), err)

	if ok {
		err = nil // wipe out err as it makes core.Race discard "ok"
	}
	return ok, err
}
