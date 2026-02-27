// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package rpn

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

type RegionalWgConf struct {
	// WsServerList.CountryCode (uppercased)
	CC string `json:"CC"`
	// WsServerGroup.City
	City string `json:"City"`
	// City (Nick)
	Name string `json:"Name"`
	// WsServerGroup.Health (0-100, lower is better)
	Load int32 `json:"Load"`
	// WsServerGroup.LinkSpeed (100, 1000, 10000 in mbps)
	Link int32 `json:"Link"`
	// len(WsServerGroup.Nodes) (number of nodes in this group)
	Count int32 `json:"Count"`
	// WsServerList.PremiumOnly == 1
	Premium bool `json:"Premium"`

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
	return fmt.Sprintf("%s, %s: %s", rwg.City, rwg.CC, rwg.Name)
}

func toHex(b64 string) string {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func (rwg *RegionalWgConf) GenUapiConfig() (didGenerate bool) {
	return rwg.genUapiConfig()
}

func (rwg *RegionalWgConf) genUapiConfigIfNeeded() (hasConfig bool) {
	if len(rwg.UapiWgConf) <= 0 {
		return rwg.genUapiConfig()
	}
	return true
}

// TODO: genWgConf github.com/celzero/firestack/blob/31633dc6f3/intra/ipn/warp/id.go#L260
func (rwg *RegionalWgConf) genUapiConfig() (didGenerate bool) {
	// github.com/WireGuard/wireguard-android/blob/4ba87947ae/tunnel/src/main/java/com/wireguard/config/Config.java#L179
	// github.com/WireGuard/wireguard-android/blob/4ba87947ae/tunnel/src/main/java/com/wireguard/config/Interface.java#L257
	// allowedips must be individual entries in uapi, but our custom impl can handle csv
	// see: wgproxy.go:wgIfConfigOf => wgproxy.go:loadIPNets
	allowedips := rwg.AllowedIPs
	if len(allowedips) <= 0 {
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

	return true
}

func (rwg *RegionalWgConf) addrCsv() string {
	var addrs []string
	if len(rwg.ClientAddr4) > 0 {
		addrs = append(addrs, rwg.ClientAddr4)
	}
	if len(rwg.ClientAddr6) > 0 {
		addrs = append(addrs, rwg.ClientAddr6)
	}
	return strings.Join(addrs, ",")
}
