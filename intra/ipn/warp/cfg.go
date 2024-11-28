// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//    SPDX-License-Identifier: MIT

// from: github.com/bepass-org/warp-plus/blob/19ac233cc/warp/endpoint.go

package warp

import (
	"math/rand"
	"net/netip"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
)

const warpApiUrl string = "https://api.cloudflareclient.com/v0a4005"

// 141.101.113.0 cloudflare ip fronting
var cfip141 = netip.MustParsePrefix("141.101.113.0/24")

var ports = []uint16{
	500,
	854,
	859,
	864,
	878,
	880,
	890,
	891,
	894,
	903,
	908,
	928,
	934,
	939,
	942,
	943,
	945,
	946,
	955,
	968,
	987,
	988,
	1002,
	1010,
	1014,
	1018,
	1070,
	1074,
	1180,
	1387,
	1701,
	1843,
	2371,
	2408,
	2506,
	3138,
	3476,
	3581,
	3854,
	4177,
	4198,
	4233,
	4500,
	5279,
	5956,
	7103,
	7152,
	7156,
	7281,
	7559,
	8319,
	8742,
	8854,
	8886,
}

var cidrs4 = []netip.Prefix{
	netip.MustParsePrefix("162.159.192.0/24"),
	netip.MustParsePrefix("162.159.193.0/24"),
	netip.MustParsePrefix("162.159.195.0/24"),
	netip.MustParsePrefix("188.114.96.0/24"),
	netip.MustParsePrefix("188.114.97.0/24"),
	netip.MustParsePrefix("188.114.98.0/24"),
	netip.MustParsePrefix("188.114.99.0/24"),
}

var cidrs6 = []netip.Prefix{
	netip.MustParsePrefix("2606:4700:d0::/64"),
	netip.MustParsePrefix("2606:4700:d1::/64"),
}

// preset 6to4 NATs; from: nat64.xyz
var Net6to4 = []netip.Prefix{
	netip.MustParsePrefix("2a00:1098:2b::/96"),          // kasper
	netip.MustParsePrefix("2a00:1098:2c:1::/96"),        // kasper
	netip.MustParsePrefix("2a01:4f8:c2c:123f:64::/96"),  // kasper
	netip.MustParsePrefix("2a01:4f9:c010:3f02:64::/96"), // kasper
	netip.MustParsePrefix("2001:67c:2960:6464::/96"),    // level66
	netip.MustParsePrefix("2001:67c:2b0:db32:0:1::/96"), // trex
}

var defaultHeaders = map[string]string{
	"Content-Type":      "application/json; charset=UTF-8",
	"User-Agent":        "okhttp/3.12.1",
	"CF-Client-Version": "a-6.30-3596",
}

func anyCidrs() (v4 netip.Prefix, v6 netip.Prefix) {
	return cidrs4[rand.Intn(len(cidrs4))], cidrs6[rand.Intn(len(cidrs6))]
}

func anyPort() uint16 {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	return ports[rng.Intn(len(ports))]
}

func WarpEndpoints() (v4 netip.AddrPort, v6 netip.AddrPort, err error) {
	cidr4, cidr6 := anyCidrs()
	ip4, err4 := core.RandomIPFromPrefix(cidr4)
	ip6, err6 := core.RandomIPFromPrefix(cidr6)
	if err4 != nil && err6 != nil {
		err = core.JoinErr(err4, err6)
		return
	}
	v4ok, v6ok := ip4.IsValid(), ip6.IsValid()
	if !v4ok && !v6ok {
		err = errZeroRandomEp
		return
	}
	if v4ok {
		v4 = netip.AddrPortFrom(ip4, anyPort())
	}
	if v6ok {
		v6 = netip.AddrPortFrom(ip6, anyPort())
	}
	return
}

func AmzEndpoints() (v4 []netip.AddrPort, v6 []netip.AddrPort, err error) {
	var v4ok, v6ok bool
	for _, ip := range dialers.For(agwProdUrl) {
		if ip.IsValid() && ip.Is4() && !ip.IsUnspecified() {
			v4 = append(v4, netip.AddrPortFrom(ip, uint16(80)))
			v4ok = true
		}
		if ip.IsValid() && ip.Is6() && !ip.IsUnspecified() {
			v6 = append(v6, netip.AddrPortFrom(ip, uint16(80)))
			v6ok = true
		}
	}
	if !v4ok && !v6ok {
		err = errZeroRandomEp
	}
	return
}

func Exit64Endpoints() (v6 []netip.Addr, errs error) {
	for _, cidr6 := range Net6to4 {
		if ip6, err := core.RandomIPFromPrefix(cidr6); err == nil {
			if ip6.IsValid() && !ip6.IsUnspecified() {
				v6 = append(v6, ip6)
			} // else: discard
		} else {
			errs = core.JoinErr(errs, err)
		}
	}
	if len(v6) <= 0 {
		return nil, core.JoinErr(errs, errZeroRandomEp)
	}
	return v6, nil
}
