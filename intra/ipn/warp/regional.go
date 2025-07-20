// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package warp

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

type RegionalWgConf struct {
	CC   string `json:"CC"`
	Name string `json:"Name"`

	ClientAddr4   string `json:"ClientAddr4"`
	ClientAddr6   string `json:"ClientAddr6"`
	ClientPrivKey string `json:"ClientPrivKey"`
	ClientPubKey  string `json:"ClientPubKey"`
	ClientDNS4    string `json:"ClientDNS4"`
	ClientDNS6    string `json:"ClientDNS6"`

	PskKey string `json:"PskKey"`

	ServerPubKey     string   `json:"ServerPubKey"`
	ServerIPPort4    string   `json:"ServerIPPort4"`
	ServerIPPort6    string   `json:"ServerIPPort6"`
	ServerDomainPort string   `json:"ServerDomainPort"`
	AllowedIPs       []string `json:"AllowedIPs"` // csv

	WgConf     string `json:"wgconf"`     // generated
	UapiWgConf string `json:"uapiwgconf"` // generated
}

func (rwg *RegionalWgConf) String() string {
	if rwg == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s: %s", rwg.CC, rwg.Name)
}

func toHex(b64 string) string {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func (rwg *RegionalWgConf) genUapiConfig() {
	// github.com/WireGuard/wireguard-android/blob/4ba87947ae/tunnel/src/main/java/com/wireguard/config/Config.java#L179
	// github.com/WireGuard/wireguard-android/blob/4ba87947ae/tunnel/src/main/java/com/wireguard/config/Interface.java#L257
	// allowedips must be individual entries in uapi, but our custom impl can handle csv
	// see: wgproxy.go:wgIfConfigOf => wgproxy.go:loadIPNets
	allowedips := rwg.AllowedIPs
	if len(allowedips) <= 0 {
		// github.com/ProtonVPN/android-app/blob/b9c6e59de40/app/src/main/java/com/protonvpn/android/models/vpn/ConnectionParamsWireguard.kt#L96
		allowedips = []string{gw4}
	}

	// not added: listen_port, persistent_keepalive_interval
	rwg.UapiWgConf = fmt.Sprintf(`private_key=%s
replace_peers=true
address=%s
dns=%s
mtu=(auto)
public_key=%s`,
		toHex(rwg.ClientPrivKey),
		rwg.ClientAddr4,
		rwg.ClientDNS4,
		toHex(rwg.ServerPubKey),
	)
	if len(rwg.ServerIPPort4) > 0 {
		rwg.UapiWgConf += "\nendpoint=" + rwg.ServerIPPort4
	}
	if len(rwg.ServerIPPort6) > 0 {
		rwg.UapiWgConf += "\nendpoint=" + rwg.ServerIPPort6
	}
	if len(rwg.ServerDomainPort) > 0 {
		rwg.UapiWgConf += "\nendpoint=" + rwg.ServerDomainPort
	}
	if len(rwg.PskKey) > 0 {
		rwg.UapiWgConf += "\npreshared_key=" + toHex(rwg.PskKey)
	}
	if len(rwg.ClientAddr6) > 0 {
		rwg.UapiWgConf += "\naddress=" + rwg.ClientAddr6
	}
	if len(rwg.ClientDNS6) > 0 {
		rwg.UapiWgConf += "\ndns=" + rwg.ClientDNS6
	}
	for _, ip := range allowedips {
		rwg.UapiWgConf += fmt.Sprintf("\nallowed_ip=%s", ip)
	}
}

func (rwg *RegionalWgConf) dnsCsv() string {
	var dnses []string
	if len(rwg.ClientDNS4) > 0 {
		dnses = append(dnses, rwg.ClientDNS4)
	}
	if len(rwg.ClientDNS6) > 0 {
		dnses = append(dnses, rwg.ClientDNS6)
	}
	if len(dnses) <= 0 {
		dnses = []string{cfdns4}
	}
	return strings.Join(dnses, ",")
}

func (rwg *RegionalWgConf) addrCsv() string {
	var addrs []string
	if len(rwg.ClientAddr4) > 0 {
		addrs = append(addrs, rwg.ClientAddr4)
	}
	if len(rwg.ClientAddr6) > 0 {
		addrs = append(addrs, rwg.ClientAddr6)
	}
	if len(addrs) <= 0 {
		addrs = []string{gw4}
	}
	return strings.Join(addrs, ",")
}

func (rwg *RegionalWgConf) genWgConf() {
	if rwg == nil {
		return
	}
	rwg.WgConf = fmt.Sprintf(`[Interface]
PrivateKey = %s
PublicKey = %s
Address = %s
DNS = %s
[Peer]
PublicKey = %s`,
		rwg.ClientPrivKey,
		rwg.ClientPubKey,
		rwg.addrCsv(),
		rwg.dnsCsv(),
		rwg.ServerPubKey,
	)
	if len(rwg.PskKey) > 0 {
		rwg.WgConf += fmt.Sprintf("\nPresharedKey = %s", rwg.PskKey)
	}
	if len(rwg.ServerIPPort4) > 0 {
		rwg.WgConf += fmt.Sprintf("\nEndpoint = %s", rwg.ServerIPPort4)
	}
	if len(rwg.ServerIPPort6) > 0 {
		rwg.WgConf += fmt.Sprintf("\nEndpoint = %s", rwg.ServerIPPort6)
	}
	if len(rwg.ServerDomainPort) > 0 {
		rwg.WgConf += fmt.Sprintf("\nEndpoint = %s", rwg.ServerDomainPort)
	}
	if len(rwg.AllowedIPs) > 0 {
		rwg.WgConf += "\nAllowedIPs = " + strings.Join(rwg.AllowedIPs, ",")
	} else {
		rwg.WgConf += "\nAllowedIPs = " + gw4 // default
	}

	rwg.genUapiConfig()
}
