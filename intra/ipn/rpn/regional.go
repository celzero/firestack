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
	"net"
	"strings"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
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

	UapiWgConf string `json:"uapiwgconf,omitempty"` // generated
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

// MakeUapiConfig builds an on-the-fly UAPI config string that overlays
// the credentials from a permanent config (private key, address, DNS,
// preshared key, allowed IPs) onto this regional config's server endpoints.
// rwg.UapiWgConf is NOT modified; the generated string is returned directly.
// Returns ("", false) when rwg/perma is nil or PrivateKey/Address is absent.
func (rwg *RegionalWgConf) MakeUapiConfig(creds *WsWgCreds, port string) (string, bool) {
	if rwg == nil || creds == nil || len(creds.PrivateKey) <= 0 {
		return "", false
	}

	addr4 := rwg.ClientAddr4
	if len(creds.Address) > 0 {
		addr4 = creds.Address // perma address
	}
	dns4 := rwg.ClientDNS4
	if len(creds.DNS) > 0 {
		dns4 = creds.DNS // perma dns
	}

	clientpriv := creds.PrivateKey
	psk := creds.PresharedKey
	peerpub := rwg.ServerPubKey

	if len(clientpriv) <= 0 || len(peerpub) <= 0 {
		log.E("rpn: regconf: cannot gen; empty priv (%t) or peer pub (%t) key", len(clientpriv) <= 0, len(peerpub) <= 0)
		return "", false
	}

	// github.com/WireGuard/wireguard-android/blob/4ba87947ae/tunnel/src/main/java/com/wireguard/config/Config.java#L179
	// github.com/WireGuard/wireguard-android/blob/4ba87947ae/tunnel/src/main/java/com/wireguard/config/Interface.java#L257
	// allowedips must be individual entries in uapi, but our custom impl can handle csv
	// see: wgproxy.go:wgIfConfigOf => wgproxy.go:loadIPNets
	allowedips := []string{gw4}
	if len(creds.AllowedIPs) > 0 {
		parts := strings.Split(creds.AllowedIPs, ",")
		allowedips = make([]string, 0, len(parts))
		for _, p := range parts {
			if t := strings.TrimSpace(p); len(t) > 0 {
				allowedips = append(allowedips, t)
			}
		}
	}

	// port may be empty
	ipp4str := changeport(rwg.ServerIPPort4, port)
	ipp6str := changeport(rwg.ServerIPPort6, port)
	domstr := changeport(rwg.ServerDomainPort, port)

	if settings.Debug {
		log.V("rpn: regconf: gen for %s/%s (port? %s); endpoint: %s %s %s; psk? %t; allowed: %v",
			addr4, dns4, port, ipp4str, ipp6str, domstr, len(psk) > 0, allowedips)
	}

	// not added: listen_port, persistent_keepalive_interval
	var conf strings.Builder
	conf.WriteString(fmt.Sprintf(`private_key=%s
replace_peers=true
address=%s
dns=%s
mtu=(auto)
public_key=%s`,
		toHex(clientpriv),
		addr4,
		dns4,
		toHex(peerpub),
	))
	if len(ipp4str) > 0 {
		conf.WriteString("\nendpoint=" + ipp4str)
	}
	if len(ipp6str) > 0 {
		conf.WriteString("\nendpoint=" + ipp6str)
	}
	if len(domstr) > 0 {
		conf.WriteString("\nendpoint=" + domstr)
	}
	if len(psk) > 0 {
		conf.WriteString("\npreshared_key=" + toHex(psk))
	}
	for _, ip := range allowedips {
		conf.WriteString(fmt.Sprintf("\nallowed_ip=%s", ip))
	}

	return conf.String(), true
}

func changeport(endpoint, newPort string) string {
	if len(endpoint) <= 0 || len(newPort) <= 0 || newPort == "0" {
		return endpoint
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return endpoint // malformed, return as is
	}
	return net.JoinHostPort(host, newPort)
}
