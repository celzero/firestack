// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     SPDX-License-Identifier: MIT
//
//     Copyright (c) 2021 Snawoot

package seasy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	se "github.com/Snawoot/opera-proxy/seclient"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
)

// from: github.com/Snawoot/opera-proxy/blob/27b3da3004830c/main.go

// see: se.DefaultSESettings
const (
	API_DOMAIN = "api2.sec-tunnel.com"
	API_LOGIN  = "se0316"
	API_CRED   = "SILrMEPBmJuhomxWkfm3JalqHX2Eheg1YhlEZiMh8II"
)

// A PEM encoded intermediate cert.
//
// go.dev/play/p/q4N5C7ak1L8
//
// - DNSNames: []
//
// - Issuer: CN=AAA Certificate Services, O=Comodo CA Limited,L=Salford,ST=Greater Manchester,C=GB
//
// - SerialNumber: 114849002793238729640937462275813569940
//
// - PublicKeyAlg: ECDSA
//
// - SigAlg: SHA384-RSA
//
// - NotAfter: 2028-12-31 23:59:59 +0000 UTC
//
// - NotBefore: 2019-03-12 00:00:00 +0000 UTC
//
// - CRL: http://crl.comodoca.com/AAACertificateServices.crl
//
// - OCSP: http://ocsp.comodoca.com
const (
	MISSING_CHAIN_CERT = `-----BEGIN CERTIFICATE-----
MIID0zCCArugAwIBAgIQVmcdBOpPmUxvEIFHWdJ1lDANBgkqhkiG9w0BAQwFADB7
MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYD
VQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UE
AwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTE5MDMxMjAwMDAwMFoXDTI4
MTIzMTIzNTk1OVowgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5
MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBO
ZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgRUNDIENlcnRpZmljYXRpb24gQXV0
aG9yaXR5MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEGqxUWqn5aCPnetUkb1PGWthL
q8bVttHmc3Gu3ZzWDGH926CJA7gFFOxXzu5dP+Ihs8731Ip54KODfi2X0GHE8Znc
JZFjq38wo7Rw4sehM5zzvy5cU7Ffs30yf4o043l5o4HyMIHvMB8GA1UdIwQYMBaA
FKARCiM+lvEH7OKvKe+CpX/QMKS0MB0GA1UdDgQWBBQ64QmG1M8ZwpZ2dEl23OA1
xmNjmjAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zARBgNVHSAECjAI
MAYGBFUdIAAwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5j
b20vQUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNAYIKwYBBQUHAQEEKDAmMCQG
CCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wDQYJKoZIhvcNAQEM
BQADggEBABns652JLCALBIAdGN5CmXKZFjK9Dpx1WywV4ilAbe7/ctvbq5AfjJXy
ij0IckKJUAfiORVsAYfZFhr1wHUrxeZWEQff2Ji8fJ8ZOd+LygBkc7xGEJuTI42+
FsMuCIKchjN0djsoTI0DQoWz4rIjQtUfenVqGtF8qmchxDM6OW1TyaLtYiKou+JV
bJlsQ2uRl9EMC5MCHdK8aXdJ5htN978UeAOwproLtOGFfy/cQjutdAFI3tZs4RmY
CV4Ks2dH/hzg1cEo70qLRDEmBDeNiXQ2Lu+lIg+DdEmSx/cQwgwp+7e9un/jX9Wf
8qn0dNW44bOwgeThpWOjzOoEeJBuv/c=
-----END CERTIFICATE-----
`
)

const refreshTimeout = 30 * time.Second

var (
	defaultGeos = []se.SEGeoEntry{
		{CountryCode: "EU", Country: "Europe"},
		{CountryCode: "AS", Country: "Asia"},
		{CountryCode: "AM", Country: "Americas"},
	}
)

type SEApi struct {
	*se.SEClient
	eps  []se.SEIPEntry
	ipps []netip.AddrPort
}

func NewSEasyClient(d protect.RDialer) (sec *SEApi, err error) {
	c, err := se.NewSEClient(API_LOGIN, API_CRED, &http.Transport{
		Dial:                  d.Dial, // resolves addrs if needed
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       2 * time.Minute,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify:     true, // custom validation
			SessionTicketsDisabled: false,
			ClientSessionCache:     core.TlsSessionCache(),
		},
	})
	if c != nil { // rare for c to be nil
		return &SEApi{
			SEClient: c,
			eps:      make([]se.SEIPEntry, 0),
		}, nil
	}
	return nil, err
}

func (sec *SEApi) Start(ctx context.Context) (ok bool, err error) {
	if err = sec.AnonRegister(ctx); err != nil {
		return
	}
	if err = sec.RegisterDevice(ctx); err != nil {
		return
	}
	geos, _ := sec.GeoList(ctx)
	if len(geos) <= 0 {
		geos = defaultGeos
	}

	for _, geo := range geos {
		if discovered, discoerr := sec.Discover(ctx, fmt.Sprintf("\"%s\",,", geo.CountryCode)); err == nil {
			for _, ep := range discovered {
				if !sec.hasEp(ep) {
					addr := ep.NetAddr()
					if ipp, err := netip.ParseAddrPort(addr); err == nil {
						sec.ipps = append(sec.ipps, ipp)
						sec.eps = append(sec.eps, ep)
					} else {
						log.W("se: %s: err parsing %s: %v", geo.Country, addr, err)
					}
				}
			}
		} else {
			err = core.JoinErr(err, discoerr)
		}
	}
	if err != nil {
		return
	}

	return len(sec.eps) > 0, nil
}

func (sec *SEApi) Endpoints() []se.SEIPEntry {
	return sec.eps
}

func (sec *SEApi) Addrs() []netip.AddrPort {
	return sec.ipps
}

func (sec *SEApi) Refresh() {
	bg := context.Background()

	ctx, done := context.WithTimeout(bg, refreshTimeout)
	defer done()
	err := sec.Login(ctx)
	loged(err)("se: login refresh; err? %v", err)

	ctx, done = context.WithTimeout(bg, refreshTimeout)
	defer done()
	err = sec.DeviceGeneratePassword(ctx)
	loged(err)("se: auth refresh; err? %v", err)

	// todo: retry on error?
}

func loged(err error) log.LogFn {
	if err != nil {
		return log.E
	}
	return log.D
}

func (sec *SEApi) hasEp(ep se.SEIPEntry) bool {
	for _, v := range sec.eps { // sec.eps may be nil
		if v.NetAddr() == ep.NetAddr() {
			return true
		}
	}
	return false
}
