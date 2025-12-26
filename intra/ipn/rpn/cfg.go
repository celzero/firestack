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

package rpn

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/protect"
)

// developers.cloudflare.com/1.1.1.1/ip-addresses/
const cfdns4 = "1.1.1.1"

const gw4 = "0.0.0.0/0" // netip.ParsePrefix("0.0.0.0/0")

// preset 6to4 NATs; from: nat64.xyz
var Net6to4 = []netip.Prefix{
	netip.MustParsePrefix("2a00:1098:2b::/96"),          // kasper
	netip.MustParsePrefix("2a00:1098:2c:1::/96"),        // kasper
	netip.MustParsePrefix("2a01:4f8:c2c:123f:64::/96"),  // kasper
	netip.MustParsePrefix("2a01:4f9:c010:3f02:64::/96"), // kasper
	netip.MustParsePrefix("2001:67c:2960:6464::/96"),    // level66
	netip.MustParsePrefix("2001:67c:2b0:db32:0:1::/96"), // trex
}

var (
	errRpnCountryless = errors.New("rpn is not multi-country")
	errRpnStateless   = errors.New("rpn has no state or config")
	errRpnUpdateless  = errors.New("rpn cannot be updated only registered")

	errZeroRandomEp = errors.New("warp: zero random endpoint")
)

type RpnAcc interface {
	x.RpnAcc
	ProviderID() string // x.RpnWg, x.RpnPro, x.RpnAmz
	MultiCountry() bool
	Conf(key string) (string, error)
}

var _ RpnAcc = (*WsClient)(nil)

type BaseClient struct {
	d  protect.RDialer
	h2 http.Client
}

var dob = time.Now()
var neverEver = time.Date(5253, time.March, 6, 0, 0, 0, 0, time.UTC)

type RpnForever struct{}

func (RpnForever) Created() int64 { return dob.UnixMilli() }
func (RpnForever) Expires() int64 { return neverEver.UnixMilli() }

type RpnMultiCountry struct{}

func (RpnMultiCountry) MultiCountry() bool { return true }

type RpnCountryless struct{}

func (c RpnCountryless) MultiCountry() bool               { return false }
func (c RpnCountryless) Locations() (x.RpnServers, error) { return nil, errRpnCountryless }

type RpnStateless struct {
	RpnUpdateless
}

func (RpnStateless) State() (*x.Gobyte, error)      { return nil, errRpnStateless }
func (RpnStateless) Conf(cc string) (string, error) { return "", errRpnStateless }

type RpnUpdateless struct{}

func (RpnUpdateless) Update() (*x.Gobyte, error) { return nil, errRpnUpdateless }

type RpnMultiCountryServers struct {
	all []x.RpnServer
}

var _ x.RpnServers = (*RpnMultiCountryServers)(nil)

func (s *RpnMultiCountryServers) Get(i int) (*x.RpnServer, error) {
	if i < 0 || i >= len(s.all) {
		return nil, fmt.Errorf("rpn: %d out of range [0, %d)", i, len(s.all))
	}
	return &s.all[i], nil
}

func (s *RpnMultiCountryServers) Len() int {
	return len(s.all)
}

func (s *RpnMultiCountryServers) Json() (*x.Gobyte, error) {
	if s == nil || len(s.all) <= 0 {
		return nil, fmt.Errorf("rpn: no servers")
	}
	// go.dev/play/p/Cxy0imeHYKx
	b, err := json.Marshal(s.all)
	if err != nil {
		return nil, fmt.Errorf("rpn: json: %w", err)
	}
	return x.BytesOf(b), nil
}

func WinEndpoints() (v4 []netip.AddrPort, v6 []netip.AddrPort, err error) {
	var v4ok, v6ok bool
	for _, u := range []string{svchost, wsMyIp2, wsMyIp} {
		// svchost is a host, but url.Parse will work
		for _, ip := range dialers.ResolveForUrl(u) {
			if ipok(ip) {
				if ip.Is4() {
					v4 = append(v4, netip.AddrPortFrom(ip, uint16(80)))
					v4ok = true
				} else if ip.Is6() {
					v6 = append(v6, netip.AddrPortFrom(ip, uint16(80)))
					v6ok = true
				}
			}
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
			if ipok(ip6) {
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

func NewExtClient(d protect.RDialer) *BaseClient {
	w := &BaseClient{d: d}
	w.h2.Transport = &http.Transport{
		Dial:                  d.Dial,
		ForceAttemptHTTP2:     true,
		ResponseHeaderTimeout: 15 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		TLSClientConfig: &tls.Config{
			ClientSessionCache: core.TlsSessionCache(),
		},
	}
	return w
}

func ipok(ip netip.Addr) bool {
	return ip.IsValid() && !ip.IsUnspecified()
}

func fmtUnixMillis(ms int64) string {
	return core.FmtUnixMillisAsTimestamp(ms)
}

func fmtTime(t time.Time) string {
	return core.FmtTimeAsPeriod(t)
}
