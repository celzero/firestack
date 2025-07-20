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

// developers.cloudflare.com/1.1.1.1/ip-addresses/
const cfdns4 = "1.1.1.1"
const cfdns6 = "2606:4700:4700::1001"

const quad9dns4 = "9.9.9.10"

const gw4 = "0.0.0.0/0" // netip.ParsePrefix("0.0.0.0/0")
const gw6 = "::/0"      // netip.ParsePrefix("::/0")

// 141.101.113.0 cloudflare ip fronting
var cfip141 = netip.MustParsePrefix("141.101.113.0/24")

// use random but valid warp ip:port
const usePooledWarpEndpoints = false

// use utls for warp api requests
const useUtlsWarpApis = false

var warpPorts = []uint16{
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

var warpCidrs4 = []netip.Prefix{
	netip.MustParsePrefix("162.159.192.0/24"),
	netip.MustParsePrefix("162.159.193.0/24"),
	netip.MustParsePrefix("162.159.195.0/24"),
	netip.MustParsePrefix("188.114.96.0/24"),
	netip.MustParsePrefix("188.114.97.0/24"),
	netip.MustParsePrefix("188.114.98.0/24"),
	netip.MustParsePrefix("188.114.99.0/24"),
}

var warpCidrs6 = []netip.Prefix{
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

var warpDefaultHeaders = map[string]string{
	"Content-Type":      "application/json; charset=UTF-8",
	"User-Agent":        "okhttp/3.12.1",
	"CF-Client-Version": "a-6.30-3596",
}

// raw.githubusercontent.com/ProtonVPN/android-app/81a6dfb9a0/app/src/main/assets/GuestHoleServers.json
var prebuiltProtonServersJson = []byte(`[
    {
        "Name": "CH#134",
        "EntryCountry": "CH",
        "ExitCountry": "CH",
        "Domain": "node-ch-19.protonvpn.net",
        "Tier": 2,
        "Features": 28,
        "Region": null,
        "City": "Zurich",
        "Score": 1.9545809733000001,
        "HostCountry": null,
        "OrganizationID": null,
        "VPNGatewayID": null,
        "ID": "zLENALrs0gKRxklX2WQEie3Id9jS8b1dmVJtSIdxNw6WQGrzLLbYn4Kopiw6qAtsS2g1UZYBGKsK5Hv5F5qL7w==",
        "Location": {
            "Lat": 47.369999999999997,
            "Long": 8.5399999999999991
        },
        "Status": 1,
        "Servers": [
            {
                "EntryIP": "149.88.27.233",
                "ExitIP": "79.127.207.150",
                "Domain": "node-ch-19.protonvpn.net",
                "ID": "UEdFuY56fyOmtHF4kvRsAXiwO4UD11B4sxErD_8LocIhC7OewevUWGYEkNxFC-vyTUDBAd2Ov3zPZFM7YoEwew==",
                "Label": "21",
                "X25519PublicKey": "MDJPYLKrGYv11Mis97Ihk/aPULhC5us44hx3Fa1/8lk=",
                "Generation": 0,
                "Status": 1,
                "ServicesDown": 0,
                "ServicesDownReason": null
            }
        ],
        "Load": 52
    },
    {
        "Name": "RU#32",
        "EntryCountry": "RU",
        "ExitCountry": "RU",
        "Domain": "node-ru-05.protonvpn.net",
        "Tier": 2,
        "Features": 0,
        "Region": null,
        "City": "Moscow",
        "Score": 6.9646272026,
        "HostCountry": null,
        "OrganizationID": null,
        "VPNGatewayID": null,
        "ID": "S1DylepEYb4v1k1UttfdkjuEnmpw-jcJ-gewEGvrILOhipr9XJDOO15s1AtK3HmYOXga6XfIVW45qCnTpRx-yA==",
        "Location": {
            "Lat": 55.75,
            "Long": 37.609999999999999
        },
        "Status": 1,
        "Servers": [
            {
                "EntryIP": "176.96.226.242",
                "ExitIP": "176.96.226.246",
                "Domain": "node-ru-05.protonvpn.net",
                "ID": "4Vk8ZzXUZoNm92MlX_QleLkyxUDZRLNGk-3ICGwDXBz_aQhK4_9hxRUyhTI_qeBYP34LsCMJ9AzIOi7CZswtfg==",
                "Label": "3",
                "X25519PublicKey": "2VsdP/qE6leGtnym8gEFd4DN0Q9iFFEBOZOo8WqArz8=",
                "Generation": 0,
                "Status": 1,
                "ServicesDown": 0,
                "ServicesDownReason": null
            }
        ],
        "Load": 7
    },
    {
        "Name": "MX#34",
        "EntryCountry": "MX",
        "ExitCountry": "MX",
        "Domain": "mx-04.protonvpn.net",
        "Tier": 2,
        "Features": 12,
        "Region": null,
        "City": "Mexico City",
        "Score": 2.9912186567000001,
        "HostCountry": "US",
        "OrganizationID": null,
        "VPNGatewayID": null,
        "ID": "g9LIAs16UvlmcB-wFUD6AzvO6ogSHFpGL8Rw6F0Zgcr-KBIq2a9wCr0sPe_EZeZR6Q_crA6WYveE8qSMjka3Iw==",
        "Location": {
            "Lat": 19.43,
            "Long": -99.129999999999995
        },
        "Status": 1,
        "Servers": [
            {
                "EntryIP": "84.252.113.9",
                "ExitIP": "84.252.113.18",
                "Domain": "mx-04.protonvpn.net",
                "ID": "LbRenZdjlNtnRS2_KlEkrP3173vU9TTNngo3kbq5ID6iyWubqAbvKRbbd9NNI4PouDsFy6mJYFskd1-4GHs6Vw==",
                "Label": "9",
                "X25519PublicKey": "G/3o3VMavYShMnCn6wN1XLNKrAzUYmK7NAEXqmpTCgo=",
                "Generation": 0,
                "Status": 1,
                "ServicesDown": 0,
                "ServicesDownReason": null
            }
        ],
        "Load": 17
    },
    {
        "Name": "CH#511",
        "EntryCountry": "CH",
        "ExitCountry": "CH",
        "Domain": "node-ch-27.protonvpn.net",
        "Tier": 2,
        "Features": 28,
        "Region": null,
        "City": "Zurich",
        "Score": 1.9270561310000001,
        "HostCountry": null,
        "OrganizationID": null,
        "VPNGatewayID": null,
        "ID": "rJtc6OoWrH_jOkCjTaupVRKX_3cL-itVggpXXTdTh-GqUxO-GOck2psgmqSKUo1aqlIwqiPMHyXKT841wx6b2g==",
        "Location": {
            "Lat": 47.369999999999997,
            "Long": 8.5399999999999991
        },
        "Status": 1,
        "Servers": [
            {
                "EntryIP": "185.230.125.2",
                "ExitIP": "185.230.125.28",
                "Domain": "node-ch-27.protonvpn.net",
                "ID": "MqVcFGvDWbWDQbJpin9HbX_seNES20sDozDlV2QC3W-wGdjhpKam9h2-X_-DdnSC4hMisp6n0aGN9aEzawiyVA==",
                "Label": "25",
                "X25519PublicKey": "mJ0AogpjvmGEhogMux0gWjWu0rFIdyZORR7caFa5SG0=",
                "Generation": 0,
                "Status": 1,
                "ServicesDown": 0,
                "ServicesDownReason": null
            }
        ],
        "Load": 32
    },
    {
        "Name": "US-IL#133",
        "EntryCountry": "US",
        "ExitCountry": "US",
        "Domain": "node-us-240.protonvpn.net",
        "Tier": 2,
        "Features": 28,
        "Region": null,
        "City": "Chicago",
        "Score": 2.9868736071999997,
        "HostCountry": null,
        "OrganizationID": null,
        "VPNGatewayID": null,
        "ID": "hnYz1B3WxfEzVfbqQFtk-64knsPCcKPlMHPolh6vsZyW-Z8AFSEYQP4e8acapH2x7WXsdQbRSj9vmDBCAuM5OA==",
        "Location": {
            "Lat": 41.880000000000003,
            "Long": -87.620000000000005
        },
        "Status": 1,
        "Servers": [
            {
                "EntryIP": "87.249.134.138",
                "ExitIP": "149.88.105.97",
                "Domain": "node-us-240.protonvpn.net",
                "ID": "qjQirVbyfZ4Ly028xgvI-OqClK9EguQ1wKjckEl2JENe--tr2mRRNPJ1AMVyvr9gX3c-13YBepzx5BRdd2SD9A==",
                "Label": "6",
                "X25519PublicKey": "WNLAmQkeAvdg9QRFMXq7EuwpEWWkltWwiS/DGIcjHjs=",
                "Generation": 0,
                "Status": 1,
                "ServicesDown": 0,
                "ServicesDownReason": null
            }
        ],
        "Load": 32
    },
    {
        "Name": "CH#297",
        "EntryCountry": "CH",
        "ExitCountry": "CH",
        "Domain": "node-ch-16.protonvpn.net",
        "Tier": 2,
        "Features": 12,
        "Region": null,
        "City": "Zurich",
        "Score": 1.9631482647,
        "HostCountry": null,
        "OrganizationID": null,
        "VPNGatewayID": null,
        "ID": "WycCMPTW6NR7BOSoGV9oDfw9e6dueKy3XkGC7Vob7RYnJMlV6eErpKX-2aHb1xAKbWNkT2C83KRvEh9g_2u4nA==",
        "Location": {
            "Lat": 47.369999999999997,
            "Long": 8.5399999999999991
        },
        "Status": 1,
        "Servers": [
            {
                "EntryIP": "149.88.27.193",
                "ExitIP": "149.22.89.84",
                "Domain": "node-ch-16.protonvpn.net",
                "ID": "EiNVXtn15vfpDsstwlqKGO4WKDVTBF6-7ST_P0w3TNqAeDQLBg23f3icE745OQoZ3tOy8nN5XfJLNqTrMFmonQ==",
                "Label": "15",
                "X25519PublicKey": "WYXA8DeAZIF4th8Dfbw02osdbFc24sK10zKijcJvZwU=",
                "Generation": 0,
                "Status": 1,
                "ServicesDown": 0,
                "ServicesDownReason": null
            }
        ],
        "Load": 59
    },
    {
        "Name": "UK#183",
        "EntryCountry": "UK",
        "ExitCountry": "UK",
        "Domain": "node-uk-21.protonvpn.net",
        "Tier": 2,
        "Features": 28,
        "Region": null,
        "City": "London",
        "Score": 2.9825145305,
        "HostCountry": null,
        "OrganizationID": null,
        "VPNGatewayID": null,
        "ID": "whlvasrl4qkvLv-bOYyQ9gOqXCXqfHtwK2rTNPtMIYtK1oKj2LxNW-YZL4MgJaY-kmaweUVCbwWtKuUeMmp16g==",
        "Location": {
            "Lat": 51.5,
            "Long": -0.11
        },
        "Status": 1,
        "Servers": [
            {
                "EntryIP": "149.40.48.65",
                "ExitIP": "149.40.48.70",
                "Domain": "node-uk-21.protonvpn.net",
                "ID": "pCauEp8FKwUwgskElW98TZSywQVOyLel1ksxvSIRD23wh-tFpHToweoB_LDygS-ludddLjfJFqg3A7945QvZlQ==",
                "Label": "4",
                "X25519PublicKey": "DgzYjQOQBgtBFUeyj3bVXpzl0qZE1I3/rk/IDS1b8kg=",
                "Generation": 0,
                "Status": 1,
                "ServicesDown": 0,
                "ServicesDownReason": null
            }
        ],
        "Load": 45
    },
    {
        "Name": "US-CA#365",
        "EntryCountry": "US",
        "ExitCountry": "US",
        "Domain": "node-us-243.protonvpn.net",
        "Tier": 2,
        "Features": 28,
        "Region": null,
        "City": "Los Angeles",
        "Score": 2.9968377886999997,
        "HostCountry": null,
        "OrganizationID": null,
        "VPNGatewayID": null,
        "ID": "L9BIB5vx8r1w57krBMtZMXue2gdAiVs0h5-f8qFUMbywnH8SxrjNmT-gSfvz04qC0pezI9PF8FXEYBiXmVLIpA==",
        "Location": {
            "Lat": 34.049999999999997,
            "Long": -118.23999999999999
        },
        "Status": 1,
        "Servers": [
            {
                "EntryIP": "149.22.80.28",
                "ExitIP": "149.22.80.37",
                "Domain": "node-us-243.protonvpn.net",
                "ID": "wrizr7jcG4nxQ4CrDiOJL7PKp6TFAiHPwesC2HhR3hbna_tIa_GDpjz7VMU-Zo68zjswYlEYXnr4UJ2fqKtZGw==",
                "Label": "8",
                "X25519PublicKey": "bXiKQCzCfajtuTNSQQpAqcrO0Rhid5d6E3MseL2lxXU=",
                "Generation": 0,
                "Status": 1,
                "ServicesDown": 0,
                "ServicesDownReason": null
            }
        ],
        "Load": 27
    },
    {
        "Name": "US-IL#171",
        "EntryCountry": "US",
        "ExitCountry": "US",
        "Domain": "node-us-241.protonvpn.net",
        "Tier": 2,
        "Features": 28,
        "Region": null,
        "City": "Chicago",
        "Score": 2.9939104842000002,
        "HostCountry": null,
        "OrganizationID": null,
        "VPNGatewayID": null,
        "ID": "_rjpVVYhXwwq_k16LC-oxgqqGG9mZwcpFXPe891qLAh-_SUSYRq-dNO4RBnLQWxcJdxXMcD65D0pn4Dgg2E7IA==",
        "Location": {
            "Lat": 41.880000000000003,
            "Long": -87.620000000000005
        },
        "Status": 1,
        "Servers": [
            {
                "EntryIP": "87.249.134.139",
                "ExitIP": "149.88.105.83",
                "Domain": "node-us-241.protonvpn.net",
                "ID": "fnKtG6JlaQdbaEKtia64PcwIORN0kxc8XQ1pi_jKAiJDPcF7YONGbJdJN_wUFaMyECeffoTdtX0-v-rmJ0jFxw==",
                "Label": "18",
                "X25519PublicKey": "xuqP9uEGryELhamLSK9IDRNhljo3lA1zL9/gS7yj2WQ=",
                "Generation": 0,
                "Status": 1,
                "ServicesDown": 0,
                "ServicesDownReason": null
            }
        ],
        "Load": 37
    },
    {
        "Name": "US-NJ#63",
        "EntryCountry": "US",
        "ExitCountry": "US",
        "Domain": "node-us-257.protonvpn.net",
        "Tier": 2,
        "Features": 12,
        "Region": null,
        "City": "Secaucus",
        "Score": 2.9916803943999999,
        "HostCountry": null,
        "OrganizationID": null,
        "VPNGatewayID": null,
        "ID": "MtThHF-IVjIqsu9MiCD0kB1rLQ92CRxSKTzeHYKEOZZvRgv8gntoZ1OlMh5g7M6IDcNVplSEl3Aiu6AdYJBuxw==",
        "Location": {
            "Lat": 40.777999999999999,
            "Long": -74.099999999999994
        },
        "Status": 1,
        "Servers": [
            {
                "EntryIP": "163.5.171.29",
                "ExitIP": "163.5.171.43",
                "Domain": "node-us-257.protonvpn.net",
                "ID": "k8fdOxB-uYdEbn5vQmLpHrEeEfqz-AQEiPMBrVZWhETnwYlMNgAauQMGiwxwLO4fRuMS0kFG8c4Y4CQ33ROKVg==",
                "Label": "13",
                "X25519PublicKey": "6Ct2qC5B3ayxBtkV2y6ScFzYcLD/6fLmtMmHPCJTAVU=",
                "Generation": 0,
                "Status": 1,
                "ServicesDown": 0,
                "ServicesDownReason": null
            }
        ],
        "Load": 33
    }
]`)

func randomWarpCidrs() (v4 netip.Prefix, v6 netip.Prefix) {
	return warpCidrs4[rand.Intn(len(warpCidrs4))], warpCidrs6[rand.Intn(len(warpCidrs6))]
}

func randomWarpPort() uint16 {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	return warpPorts[rng.Intn(len(warpPorts))]
}

func WarpEndpoints() (v4 netip.AddrPort, v6 netip.AddrPort, err error) {
	if usePooledWarpEndpoints {
		err = errDisabledRandomEp
		return
	}
	cidr4, cidr6 := randomWarpCidrs()
	ip4, err4 := core.RandomIPFromPrefix(cidr4)
	ip6, err6 := core.RandomIPFromPrefix(cidr6)
	if err4 != nil && err6 != nil {
		err = core.JoinErr(err4, err6)
		return
	}
	v4ok, v6ok := ipok(ip4), ipok(ip6)
	if !v4ok && !v6ok {
		err = errZeroRandomEp
		return
	}
	if v4ok {
		v4 = netip.AddrPortFrom(ip4, randomWarpPort())
	}
	if v6ok {
		v6 = netip.AddrPortFrom(ip6, randomWarpPort())
	}
	return
}

func WinEndpoints() (v4 []netip.AddrPort, v6 []netip.AddrPort, err error) {
	var v4ok, v6ok bool
	for _, u := range []string{wsProdUrl, wsProdUrl2} {
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

func AmzEndpoints() (v4 []netip.AddrPort, v6 []netip.AddrPort, err error) {
	var v4ok, v6ok bool
	for _, ip := range dialers.ResolveForUrl(agwProdUrl) {
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

func ipok(ip netip.Addr) bool {
	return ip.IsValid() && !ip.IsUnspecified()
}
