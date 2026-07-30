// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dialers

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect/ipmap"
	"github.com/celzero/firestack/intra/settings"
)

const dialRetryTimeout = 35 * time.Second

var errRetryTimeout = errors.New("dialers: retry timeout")

func reorderIPs(ips []netip.Addr, alwaysExclude netip.Addr) ([]netip.Addr, bool) {
	failingopen := true
	front := make([]netip.Addr, 0, len(ips))
	back := make([]netip.Addr, 0, len(ips))

	if len(ips) == 1 {
		if alwaysExclude.Compare(ips[0]) == 0 || !ipok(ips[0]) {
			return back, failingopen
		}
		return append(front, ips[0]), !failingopen
	}

	use4 := Use4()
	use6 := Use6()
	only4 := use4 && !use6
	only6 := use6 && !use4

	prefer4 := use4
	prefer6 := use6
	ptmode := settings.PtMode.Load()
	switch ptmode {
	case settings.PtModeForce46:
		prefer6 = true
	case settings.PtModeForce64:
		prefer4 = true
	case settings.PtModeForce:
		if only4 {
			prefer4 = true
		} else if only6 {
			prefer6 = true
		} // else: prefer4, prefer6 retain use4, use6 values
	}

	for _, ip := range ips {
		if ip.Compare(alwaysExclude) == 0 || !ipok(ip) {
			continue
		} else if prefer4 && ip.Is4() {
			front = append(front, ip)
		} else if prefer6 && ip.Is6() {
			front = append(front, ip)
		} else {
			back = append(back, ip)
		}
	}
	if len(front) <= 0 {
		// if all ips are filtered out, fail open and return unfiltered
		return back, failingopen
	}
	if len(back) > 0 {
		// sample one unfiltered ip in an ironic case that it works
		// but the filtered out ones don't. this can happen in scenarios
		// where tunnel's ipProto is IP4 but the underlying network is IP6:
		// that is, IP6 is filtered out even though it might have worked.
		front = append(front, back...)
	}
	return front, !failingopen
}

func commondial[D rdials, C rconns](d D, network, addr string, connect dialFn[D, C]) (C, error) {
	return commondial2(d, network, "", addr, connect)
}

func commondial2[D rdials, C rconns](d D, network, laddr, raddr string, connect dialFn[D, C]) (C, error) {
	start := time.Now()

	local, lerr := netip.ParseAddrPort(laddr) // okay if local is invalid
	domain, portstr, err := net.SplitHostPort(raddr)

	if log.Debug {
		log.D("commondial: dialing (host:port) %s=>%s; errs? %v %v",
			laddr, raddr, lerr, err)
	}

	if err != nil {
		return nil, err
	}

	// cannot dial into a wildcard address
	// while, listen is unsupported
	if len(domain) == 0 {
		return nil, net.InvalidAddrError(raddr)
	}
	port, err := strconv.Atoi(portstr)
	if err != nil {
		return nil, err
	}

	var conn C
	var errs error
	ips := ipm.Get(domain)
	dontretry := ips.OneIPOnly() // just one IP, no retries possible
	confirmed := ips.Confirmed() // may be zeroaddr
	confirmedIPOK := ipok(confirmed)

	defer func() {
		dur := time.Since(start)
		if log.Debug {
			log.D("commondial: duration: %s; addr %s; confirmed? %s, sz: %d",
				core.FmtPeriod(dur), raddr, confirmed, ips.Size())
		}
	}()

	// One the TODO is fixed, change ipn/proxy.go:Reaches to rely on this behaviour
	// TODO: confirmedIPOK must be used depending on network type "tcp4", "udp4", "tcp6", "udp6" etc
	if confirmedIPOK {
		remote := netip.AddrPortFrom(confirmed, uint16(port))
		if log.Verbose {
			log.V("commondial: dialing confirmed ip %s for %s", confirmed, remote)
		}
		conn, err = connect(d, network, local, remote)
		// nilaway: tx.socks5 returns nil conn even if err == nil
		if conn == nil {
			err = core.OneErr(err, errNoConn)
		}
		if err == nil {
			if log.Verbose {
				log.V("commondial: ip %s works for %s", confirmed, remote)
			}
			return conn, nil
		}
		errs = core.JoinErr(errs, err)
		ips.Disconfirm(confirmed)
		logwd(err)("rdial: commondial: confirmed %s for %s failed; err %v",
			confirmed, remote, err)
	}

	if dontretry {
		if !confirmedIPOK {
			log.E("commondial: ip %s not ok for %s", confirmed, raddr)
			errs = core.JoinErr(errs, errNoIps)
		}
		return nil, errs
	}

	ipset := ips.Addrs()
	// One the TODO is fixed, change ipn/proxy.go:Reaches to rely on this behaviour
	// TODO: maybeFilter should consider incoming network types "tcp4", "udp4", "tcp6", "udp6" etc
	ordered, failingopen := reorderIPs(ipset, confirmed)
	if len(ordered) <= 0 || failingopen {
		var renewed bool
		if ips, renewed = renew(domain, ips); renewed {
			ipset = ips.Addrs()
			ordered, failingopen = reorderIPs(ipset, confirmed)
		}
		if log.Debug {
			log.D("commondial: renew ips for %s; renewed? %t, failingopen? %t", raddr, renewed, failingopen)
		}
	}

	if log.Debug {
		log.D("commondial: trying all ips %d/%d %v for %s, failingopen? %t",
			len(ordered), len(ipset), ordered, raddr, failingopen)
	}
	for _, ip := range ordered {
		end := time.Since(start)
		if end > dialRetryTimeout {
			errs = core.JoinErr(errs, errRetryTimeout)
			log.W("commondial: timeout %s for %s", end, raddr)
			break
		}
		if ipok(ip) {
			remote := netip.AddrPortFrom(ip, uint16(port))
			conn, err = connect(d, network, local, remote)
			// nilaway: tx.socks5 returns nil conn even if err == nil
			if conn == nil {
				err = core.OneErr(err, errNoConn)
			}
			if err == nil {
				confirm(ips, ip)
				log.I("commondial: ip %s works for %s", ip, remote)
				return conn, nil
			}
			errs = core.JoinErr(errs, err)
			logwd(err)("commondial: ip %s for %s failed; err %v", ip, remote, err)
		} else {
			log.W("commondial: ip %s not ok for %s", ip, raddr)
		}
	}

	if len(ipset) <= 0 {
		errs = errNoIps
	}

	return nil, errs
}

func clos(c ...core.MinConn) {
	core.CloseConn(c...)
}

func confirm(ips *ipmap.IPSet, ip netip.Addr) {
	if ips != nil && ipok(ip) {
		ips.Confirm(ip)
	}
}

func ipok(ip netip.Addr) bool {
	return ip.IsValid() && !ip.IsUnspecified()
}

func logwd(err error) log.LogFn {
	if err != nil {
		return log.W
	}
	return log.D
}
