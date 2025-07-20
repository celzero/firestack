// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package warp

import (
	"bytes"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
)

// github.com/Windscribe/browser-extension/blob/ed83749ad/modules/ext/src/utils/constants.js#L31
const (
	wsTestUrl  = "https://api-staging.windscribe.com/"
	wsProdUrl  = "https://api.windscribe.com/"
	wsProdUrl2 = "https://api.totallyacdn.com/"

	wsTestAssets  = "https://assets-staging.windscribe.com/"
	wsProdAssets  = "https://assets.windscribe.com/"
	wsProdAssets2 = "https://assets.totallyacdn.com/"

	wsMyIp  = "https://checkip.windscribe.com/"
	wsMyIp2 = "https://checkip.totallyacdn.com/"
)

const (
	// "/init" registers this client's identity with remote. Calling multiple times
	// registers identity multiple times (different Preshared Keys are generated), and so,
	// calling just the once is sufficient. Though, if called multiple times, only the latest
	// config (address + preshared key) it generates is valid, while the rest won't work.
	//
	// if the dynamic wg interface was released, connecting to WG using current config (old interface),
	// the handshakes will fail. This is a trigger to re-run the "/connect" call to get a new interface,
	// and handshake again. There is no harm blindly running "/connect" before every WG connection attempt,
	// as it will reuse the interface if its still reserved. Avoid running "/init" multiple times as after
	// you hit the limit, you will get an error like this:
	// {
	//     "errorCode": 1313,
	//     "errorMessage": "You have reached your limit of WireGuard keys. Do you want to delete your oldest key?",
	//     "errorDescription": "Maximum number of pub keys reached",
	//     "logStatus": null
	// }
	//
	// To recover from this, either supply the optional "force_init=1" field,
	// which will delete the oldest keypair, or delete all keypais using
	// the PUT "/Users" method + "delete_credentials=1" field.
	//
	// If "/connect" is attempted using such a deleted key (still stored locally, but not useless)
	// the API returns:
	// {
	//     "errorCode": 1311,
	//     "errorMessage": "Invalid WireGuard public key was provided",
	//     "errorDescription": "WG pub key is unknown",
	//     "logStatus": null
	// }
	//
	// This error is a trigger to run a new "/init" API call to generate a new keypair,
	// as you're effectively in a clean slate (how all accounts start out).
	//
	// Once local (client) has keypair, do not make the "/init" call again unless on errors
	// as described above.
	wswginitpath = "WgConfigs/init"
	// To setup WG interface after "/init", run "/connect", which reserves an interface on remote
	// A full WG config must now be built form WsServerList and "/init"d keypair.
	// This interface reservation is active while connected, and up to 4m after disconnect.
	// That is, the keys are released 4-5 mins after the the last handshake
	// occurs from the perspective of the server. This usually happens when a user disconnects
	// in the app, or the connection is severed for any reason.
	// If more time passes, this interface is released into the pool and will no longer work,
	// requiring a new "/connect" API call.
	// If possible, hook into WireGuard's "verbose logging"
	// to detect a handshake failure and not wait for a handshake timeout.
	wswgconnectpath = "WgConfigs/connect"
	// TTL reservation time using param "wg_ttl", not for longer than an hour, if needed.
	// github.com/Windscribe/Android-App/blob/3f9c2ab98a70fa/base/src/main/java/com/windscribe/vpn/repository/WgConfigRepository.kt#L143
	wgttl = "3600" // an hour in seconds

	wspxpath = "ServerCredentials/"

	wssessionpath = "Session/"
	wsportpath    = "PortMap/"
	wslocpath     = "/serverlist/mob-v2/1/" // + $loc_hash

	wsbestloc = "/BestLocation"
)

// github.com/Windscribe/Android-App/blob/746d505dc69/base/src/main/java/com/windscribe/vpn/constants/NetworkErrorCodes.kt
const (
	ekeylimit   = 1313
	ekeyinvalid = 1311
)

// github.com/Windscribe/Android-App/blob/746d505dc69/base/src/main/res/raw/port_map.txt#L76
var wswgports = []string{"443", "80", "53", "123", "1194", "65142"}

var (
	errInvalidWsGwArgs  = errors.New("ws: cannot make gw; missing args")
	errNoWsConfig       = errors.New("ws: no config")
	errNoWsJsonConfig   = errors.New("ws: no json config")
	errNoWsSession      = errors.New("ws: no session info")
	errWsSessionExpired = errors.New("ws: session expired")
	errNoWsClient       = errors.New("ws: no client")
	errNoEntitlement    = errors.New("ws: missing entitlement")
	errNoWsToken        = errors.New("ws: missing token")
	errNoWsResponse     = errors.New("ws: no response")
	errNoLocHash        = errors.New("ws: no loc hash")
	errNoWsServerList   = errors.New("ws: no server list")
	errWsRetryUpdate    = errors.New("ws: retry update")
)

/*
	{
	    "data": {
	        "portmap": [
			{...}, {...}
			],
		}
		"metadata": { ... }
*/
type WsPortMapResponse struct {
	Data struct {
		PortMap []PortMap `json:"portmap"`
	} `json:"data"`
	Metadata WsMetadata `json:"metadata"`
}

/*
	{
	    "errorCode": 502,
	    "errorMessage": "1 arguments had validation errors",
	    "errorDescription": "Argument did not validate",
	    "logStatus": null,
	    "validationFailuresArray": {
	        "0": {
	            "wg_pubkey": {
	                "lengthMin": {
	                    "validationValue": "44"
	                }
	            }
	        },
	        "validationErrorMessageArray": [
	            "wg pubkey is too short. Minimum value is 44 characters"
	        ]
	    }
	}
*/
type WsErrorResponse struct {
	Code      int            `json:"errorCode"`
	Msg       string         `json:"errorMessage"`
	Desc      string         `json:"errorDescription"`
	LogStatus string         `json:"logStatus"`
	Failures  map[string]any `json:"validationFailuresArray"`
}

/*
		{
	        "serviceRequestId": "1752328061104032696",
	        "hostName": "staging",
	        "duration": "0.00278ms",
	        "logStatus": null,
	        "md5": "f90552b29b73b6899f7f00dc0c9fe5f4"
	    }
*/
type WsMetadata struct {
	ServiceRequestId string `json:"serviceRequestId"`
	HostName         string `json:"hostName"`
	Duration         string `json:"duration"`
	LogStatus        string `json:"logStatus"`
	MD5              string `json:"md5"`
}

/*
	{
	        "portmap": [
	            {
	                "protocol": "wg",
	                "heading": "WireGuard",
	                "use": "ip3",
	                "ports": [
	                    "443",
	                    "80",
	                    "53",
	                    "123",
	                    "1194",
	                    "65142"
	                ]
	            },
	            {
	                "protocol": "ikev2",
	                "heading": "IKEv2",
	                "use": "hostname",
	                "ports": [
	                    "500"
	                ],
	                "legacy_ports": [
	                    "500"
	                ]
	            },
	            {
	                "protocol": "udp",
	                "heading": "UDP",
	                "use": "ip2",
	                "ports": [
	                    "443",
	                    "80",
	                ],
	                "legacy_ports": [
	                    "443"
	                ]
	            },
	            {
	                "protocol": "tcp",
	                "heading": "TCP",
	                "use": "ip2",
	                "ports": [
	                    "443",
	                    "587",
	                    "21",
	                    "1194"
	                ],
	                "legacy_ports": [
	                    "1194"
	                ]
	            },
	            {
	                "protocol": "stunnel",
	                "heading": "Stealth",
	                "use": "ip3",
	                "ports": [
	                    "443",
	                    "587",
	                    "21",
	                    "22",
	                    "80",
	                    "123",
	                    "8443"
	                ],
	                "legacy_ports": [
	                    "8443"
	                ]
	            },
	            {
	                "protocol": "wstunnel",
	                "heading": "WStunnel",
	                "use": "hostname",
	                "ports": [
	                    "443"
	                ],
	                "legacy_ports": [
	                    "443"
	                ]
	            }
	        ]
	}
*/
type PortMap struct {
	Protocol    string   `json:"protocol"`
	Heading     string   `json:"heading"`
	Use         string   `json:"use"`
	Ports       []string `json:"ports"`
	LegacyPorts []string `json:"legacy_ports,omitempty"`
}

/*
	{
	        "revision": 2672,
	        "revision_hash": "6ad01549d6643292d8021f19a14b82310ff44c90",
	        "changed": 1,
	        "fc": 1
	}
*/
type WsInfo struct {
	Revision      int    `json:"revision"`
	RevisionHash  string `json:"revision_hash"`
	Changed       int    `json:"changed"`
	FeatureConfig int    `json:"fc"`
}

/*
	{
	            "id": 90,
	            "name": "Guatemala",
	            "country_code": "gt",
	            "status": 1,
	            "premium_only": 1,
	            "short_name": "GT",
	            "p2p": 1,
	            "tz": "America/Toronto",
	            "tz_offset": "-4,EST",
	            "loc_type": "normal",
	            "dns_hostname": "gt.windscribe.dev",
	            "groups": [
	                {
	                    "id": 110,
	                    "city": "San Marcos",
	                    "nick": "Trafficker",
	                    "pro": 1,
	                    "gps": "14.97,-91.80",
	                    "tz": "America/Guatemala",
	                    "wg_pubkey": "NXPIQ0kD2ww9VkgFqMWvJs7ZLthd5PS259/yJPyDyz0=",
	                    "wg_endpoint": "gua-110-wg.whiskergalaxy.dev",
	                    "ovpn_x509": "gua-110.windscribe.dev",
	                    "ping_ip": "66.66.66.70",
	                    "ping_host": "http://gt-stg-001.whiskergalaxy.dev:6464/latency",
	                    "link_speed": "100",
	                    "nodes": [
	                        {
	                            "ip": "66.66.66.70",
	                            "ip2": "66.66.66.71",
	                            "ip3": "66.66.66.72",
	                            "hostname": "gt-stg-001.whiskergalaxy.dev",
	                            "weight": 1,
	                            "health": 0
	                        }
	                    ],
	                    "health": 0
	                }
	            ]
	        },
	        {
	            "id": 38,
	            "name": "Canada East",
	            "country_code": "CA",
	            "status": 1,
	            "premium_only": 0,
	            "short_name": "CA",
	            "p2p": 0,
	            "tz": "America/Toronto",
	            "tz_offset": "-4,EST",
	            "loc_type": "normal",
	            "dns_hostname": "ca.windscribe.dev",
	            "groups": [
	                { ... }
	            ]
	        },
	        {
	            "id": 52,
	            "name": "United States",
	            "country_code": "US",
	            "status": 1,
	            "premium_only": 0,
	            "short_name": "US",
	            "p2p": 0,
	            "tz": "America/Chicago",
	            "tz_offset": "-6,CET",
	            "loc_type": "normal",
	            "dns_hostname": "us.windscribe.dev",
	            "groups": [
	                { ... }
	            ]
	        },
	        {
	            "id": 84,
	            "name": "The Best Korea",
	            "country_code": "KP",
	            "status": 2,
	            "premium_only": 1,
	            "short_name": "KP",
	            "p2p": 1,
	            "tz": "Asia/Pyongyang",
	            "tz_offset": "9,PYT",
	            "loc_type": "normal",
	            "groups": [
	                { ... }
	            ]
	        }
*/
type WsServerList struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	CountryCode string `json:"country_code"`
	// Status is for country level location record,
	// flips to a value thats not 1 only if all servers
	// in the whole country are unavailable.
	Status      int    `json:"status"`
	PremiumOnly int    `json:"premium_only"`
	ShortName   string `json:"short_name"`
	// p2p is 0 as a signal that common torrent trackers are null routed
	// on these machines and torrenting is discouraged. Nothing prevents
	// users from still doing so, especially on private trackers.
	// This flag has no impact on port forwarding.
	P2P         int             `json:"p2p"`
	TZ          string          `json:"tz"`
	TZOffset    string          `json:"tz_offset"`
	LocType     string          `json:"loc_type"`
	DNSHostname string          `json:"dns_hostname,omitempty"`
	Groups      []WsServerGroup `json:"groups"`
}

/*
					{
	                    "id": 87,
	                    "city": "Boston",
	                    "nick": "The Wahlberg",
	                    "pro": 1,
	                    "gps": "42.36,-71.06",
	                    "tz": "EST",
	                    "wg_pubkey": "M/kVfITvFaz8i8msJi7C3jsgk45vnbnYLJIOl/zBsVk=",
	                    "wg_endpoint": "bos-87-wg.whiskergalaxy.dev",
	                    "ovpn_x509": "bos-87.windscribe.dev",
	                    "ping_ip": "181.215.52.122",
	                    "ping_host": "http://us-014.whiskergalaxy.dev:6464/latency",
	                    "link_speed": "1000",
	                    "nodes": [
	                        { ... }
	                    ],
	                    "health": 0
	                }
*/
type WsServerGroup struct {
	ID   int    `json:"id"`
	City string `json:"city"`
	Nick string `json:"nick"`
	Pro  int    `json:"pro"`
	GPS  string `json:"gps"`
	TZ   string `json:"tz"`
	// public key for all servers in this datacenter / building
	WgPubKey string `json:"wg_pubkey"`
	// WireGuard hostname to connect to, which will connect to a
	// random WireGuard server in this datacenter: Its A/AAAA records
	// contains all "ip3" (WireGuard-only) IPs for individual Nodes
	// (all hosts in this datacenter).
	WgEndpoint string `json:"wg_endpoint"`
	OvpnX509   string `json:"ovpn_x509"`
	PingIP     string `json:"ping_ip"`
	// GET <ping-host>
	// {"rtt": "5775"}  = 5.7ms
	PingHost string `json:"ping_host"`
	// 100mbps, 1000mbps, 10,000mbps etc;
	LinkSpeed string `json:"link_speed"`
	// Nodes are online servers that can be connected to in a datacneter.
	// If empty, the datacenter is offline.
	Nodes []WsServerNode `json:"nodes"`
	// Health is a measure of load, between 0 and 100.
	Health int `json:"health"`
}

/*
							{
	                            "ip": "181.215.52.122",
	                            "ip2": "181.215.52.123",
	                            "ip3": "181.215.52.124",
	                            "hostname": "us-014.whiskergalaxy.dev",
	                            "weight": 1,
	                            "health": 0
	                        },
	                        {
	                            "ip": "181.215.52.2",
	                            "ip2": "181.215.52.3",
	                            "ip3": "181.215.52.4",
	                            "hostname": "us-004.whiskergalaxy.dev",
	                            "weight": 1,
	                            "health": 0
	                        }
*/
type WsServerNode struct {
	IP  string `json:"ip"`
	IP2 string `json:"ip2,omitempty"`
	// Init direct connections to "ip3" + port to connect to
	// a specific node (host) skipping DNS.
	IP3      string `json:"ip3,omitempty"`
	Hostname string `json:"hostname"`
	Weight   int    `json:"weight"`
	Health   int    `json:"health"`
}

/*
	{
	    "data": [
			{ ... }, { ... },
	    ],
	    "info": { ... },
	    "metadata": { ... }
	}
*/
type WsServerListResponse struct {
	Data     []WsServerList `json:"data"`
	Info     WsInfo         `json:"info"`
	Metadata WsMetadata     `json:"metadata"`
}

/*
	{
	        "user_id": "l7xfy9c1",
	        "session_auth_hash": "id:typ:epochsec:sig1:sig2",
	        "username": "celz_l7xfy9c1",
	        "traffic_used": 0,
	        "traffic_max": -1,
	        "status": 1,
	        "email": null,
	        "email_status": 0,
	        "billing_plan_id": 120,
	        "is_premium": 1,
	        "rebill": 0,
	        "premium_expiry_date": "2025-07-15",
	        "reg_date": 1749999508,
	        "last_reset": null,
	        "loc_rev": 2672,
	        "loc_hash": "6ad01549d66..."
	}
*/
type WsSession struct {
	UserID string `json:"user_id"`
	// Account session token authenticates this user with the API to get
	// and set any state, incl WG configuration which are unique and bound
	// to each session token. Session token is the "bearer token".
	// The session/bearer token is of shape, id:type:timestamp:sig1:sig2.
	// However it could change to a new format in the future.
	SessionAuthHash string `json:"session_auth_hash"`
	Username        string `json:"username"`
	// TrafficUsed shows byte count of data used since LastReset date.
	TrafficUsed int64 `json:"traffic_used"`
	TrafficMax  int64 `json:"traffic_max"`
	// Status is 1 under normal circumstances. Any other state means
	// this user is banned (or a free account has expired).
	// Bans are extremely rare, and there is no appeal process.
	// Bans are issued on repeated abuse, never right away.
	// This user is permanently disabled if banned.
	Status        int    `json:"status"`
	Email         string `json:"email"`
	EmailStatus   int    `json:"email_status"`
	BillingPlanID int    `json:"billing_plan_id"`
	IsPremium     int    `json:"is_premium"`
	Rebill        int    `json:"rebill"`
	// This will downgrade on this date, unless its renewed.
	// ex: "2025-07-22" go.dev/play/p/IoeH1Ee6cZ3
	ExpiryDate string    `json:"premium_expiry_date"`
	RegDate    int64     `json:"reg_date"`
	LastReset  time.Time `json:"last_reset"` // can be null
	LocRev     int       `json:"loc_rev"`
	// Latest revision hash of the server list.
	LocHash string `json:"loc_hash"`
}

/*
	{
	    "data": WsSession ,
	    "metadata": { ... }
	}
*/
type WsSessionResponse struct {
	Data     WsSession  `json:"data"`
	Metadata WsMetadata `json:"metadata"`
}

/*
	{
	        "username": "string",
	        "password": "string"
	}
*/
type WsProxyCreds struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

/*
	{
	    "data": WsProxyCreds,
		metadata: { ... }
	}
*/
type WsProxyCredsResponse struct {
	Data     WsProxyCreds `json:"data"`
	Metadata WsMetadata   `json:"metadata"`
}

/*
	{
	            "PrivateKey": "stdbase64",
	            "PublicKey": "tsoZzRelDNFe/xF6eQz+xxzjmgS0xKfxEmlqsZKPNgs=",
	            "PresharedKey": "stdbase64",
	            "AllowedIPs": "0.0.0.0/0"
	}
*/
type WsWgCreds struct {
	PrivateKey   string `json:"PrivateKey,omitempty"` // base64, always empty as remote does not generate for us
	PublicKey    string `json:"PublicKey"`            // base64, generated locally
	PresharedKey string `json:"PresharedKey"`         // base64, only the latest key is valid (generated by remote)
	AllowedIPs   string `json:"AllowedIPs"`           // for now, it is "0.0.0.0/0"
}

/*
	{
	        "config": WsWgCfg,
	        "debug": {
	            "init": "generated: tsoZzRelDNFe/xF6eQz+xxzjmgS0xKfxEmlqsZKPNgs="
	        },
	        "success": 1
	}
*/
type WsWgCredsData struct {
	Config  WsWgCreds         `json:"config"`
	Debug   map[string]string `json:"debug,omitempty"`
	Success int               `json:"success"`
}

/*
	{
	    "data": WsWgCredsData,
	    "metadata": { ... }
	}
*/
type WsWgCredsResponse struct {
	Data     WsWgCredsData `json:"data"`
	Metadata WsMetadata    `json:"metadata"`
}

/*
	{
	            "Address": "100.65.61.145/32",
	            "DNS": "10.255.255.2"
	}
*/
type WsWgInterface struct {
	Address string `json:"Address"` // cidr notation
	DNS     string `json:"DNS"`     // ip address
}

/*
	{
	        "config": WsWgInterface,
	        "debug": {
	            "pub_key": "supplied: tsoZzRelDNFe/xF6eQz+xxzjmgS0xKfxEmlqsZKPNgs=",
	            "interface": "generated + attached: 100.65.61.145"
	        },
	        "success": 1
	    }
*/
type WsWgConnectData struct {
	Config  WsWgInterface     `json:"config"`
	Debug   map[string]string `json:"debug,omitempty"` // optional
	Success int               `json:"success"`
}

/*
	{
	    "data": WsWgConnectData,
	    "metadata": { ... }
	}
*/
type WsWgConnectResponse struct {
	Data     WsWgConnectData `json:"data"`
	Metadata WsMetadata      `json:"metadata"`
}

type WsClient struct {
	RpnMultiCountry

	http      *http.Client
	configExt *core.Volatile[*WsWgConfig]
}

type WsWgConfig struct {
	Entitlement *WsEntitlement    `json:"entitlement"` // entitlement info
	Session     *WsSession        `json:"session"`
	Configs     []*RegionalWgConf `json:"configs"`
	Servers     []WsServerList    `json:"servers"` // all servers in the server list
	Creds       *WsWgCreds        `json:"creds"`   // base64 encoded private key
}

/*
{
"kind": "ws#v1",
"cid": "hex", // Identifier
"sid": "id:epochsec:parentcidsig", // profile identifier, if any
"sessiontoken": "id:typ:epochsec:sig1:sig2",
"expiry": "2025-07-15T00:00:00Z", // Expiry date of the entitlement
"status": "valid" // "valid" | "invalid" | "banned" | "expired" | "unknown"
"test": false // true if this is a test entitlement
}
*/
type WsEntitlement struct {
	Kind         string `json:"kind"`          // e.g. "ws#v1"
	Cid          string `json:"cid"`           // Client ID
	Sid          string `json:"pid,omitempty"` // Share ID
	SessionToken string `json:"sessiontoken"`  // Session token
	// Expiry date of the entitlement; go.dev/play/p/d2gshytEF61
	Expiry time.Time `json:"expiry"`
	Status string    `json:"status"` // "valid" | "invalid" | "banned" | "expired" | "unknown"
	Test   bool      `json:"test"`   // true if this is a test entitlement
}

func (id *WsWgConfig) Json() ([]byte, error) {
	if id == nil {
		return nil, errNoProtonConfig
	}

	var w bytewriter
	if err := id.writeJson(&w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

func (id *WsWgConfig) writeJson(w io.Writer) error {
	if id == nil {
		return errNoProtonConfig
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(id)
}

func (a *WsClient) config() *WsWgConfig {
	if a == nil {
		return nil
	}
	return a.configExt.Load()
}

// Who implements x.RpnAcc.
func (a *WsClient) Who() *x.Gostr {
	if a == nil {
		return nil
	}
	c := a.config()
	if c == nil || c.Session == nil {
		return nil
	}
	return x.StrOf(c.Session.UserID + "@" + a.kid())
}

// ProviderID implements RpnAcc.
func (*WsClient) ProviderID() string { return x.RpnWin }

// State implements x.RpnAcc.
func (a *WsClient) State() (*x.Gobyte, error) {
	if a == nil {
		return nil, errNoWsClient
	}
	c := a.config()
	if c == nil {
		return nil, errNoWsConfig
	}
	return x.BytesOfFunc(c.Json)
}

// Created implements x.RpnAcc.
func (a *WsClient) Created() int64 {
	if a == nil {
		return 0
	}
	c := a.config()
	if c == nil {
		return 0
	}
	createdAt := time.Unix(int64(c.Session.RegDate), 0)
	return createdAt.UnixMilli()
}

// Expires implements x.RpnAcc.
func (a *WsClient) Expires() int64 {
	if a == nil {
		return 0
	}
	c := a.config()
	if c == nil {
		return 0
	}

	refreshAt, err := time.Parse(time.DateOnly, c.Session.ExpiryDate)
	if err != nil {
		log.W("ws: expires: cannot parse %s; err: %v", c.Session.ExpiryDate, err)
		return 0
	}

	return refreshAt.UnixMilli()
}

// Update implements x.RpnAcc.
func (a *WsClient) Update() (newstate *x.Gobyte, err error) {
	b, refreshed, err := makeWsWgFrom(a.http, a.config())
	if err != nil || !refreshed {
		log.E("ws: update: refreshed? %t; err: %v", refreshed, err)
		return nil, core.OneErr(err, errWsRetryUpdate)
	}

	if err = a.shallowCopyConfig(b); err != nil {
		log.E("ws: update: shallow copy err: %v", err)
		return nil, err
	}

	return a.State()
}

func (a *WsClient) shallowCopyConfig(b *WsClient) error {
	if a == nil || b == nil {
		return nil // no-op
	}
	bc := b.config()
	if bc == nil {
		log.E("ws: shallowcopy: storing nil config...")
		return errNoWsConfig
	}
	a.configExt.Store(bc)
	return nil
}

// Conf implements RpnAcc.
func (a *WsClient) Conf(cc string) (string, error) {
	cfg := a.config()
	if cfg == nil {
		return "", errNoWsConfig
	}
	tot := 0
	c := 0
	out := make([]string, 0, maxPerRegionWgConfs)
	for _, rc := range cfg.Configs {
		if rc.CC == cc && c < maxPerRegionWgConfs {
			out = append(out, rc.UapiWgConf)
			c++
		}
		tot++
	}
	if len(out) > 0 {
		r := rand.IntN(len(out))
		log.I("proton: conf: cc %s: %d/%d => chosen: %d", cc, c, len(out), r)
		return out[r], nil
	}
	log.D("proton: conf: cc %s not found (tot: %d)", cc, tot)
	return "", errNoProtonCcConf
}

func baseurl(test bool) string {
	if test {
		return wsTestUrl
	}
	return wsProdUrl
}

func authHeader(req *http.Request, t string) {
	if req == nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+t)
}

func wsErr(res *http.Response, op string) error {
	_, err := wsErr2(res, op)
	return err
}

func wsErr2(res *http.Response, op string) (*WsErrorResponse, error) {
	if res == nil {
		return nil, fmt.Errorf("ws: %s: %v", op, errNoWsResponse)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("ws: %s: read body err: %v", op, err)
	}

	var wsErr WsErrorResponse
	err = json.Unmarshal(body, &wsErr)
	if err != nil {
		return nil, fmt.Errorf("ws: unmarshal err: %v; body: %s", err, body)
	}

	return &wsErr, fmt.Errorf("ws: status: %d, error %d: %s; why: %s", res.StatusCode, wsErr.Code, wsErr.Msg, wsErr.Desc)
}

func wsRes[T any](res *http.Response, out *T, op string) (*T, error) {
	if res == nil {
		return nil, fmt.Errorf("ws: %s: %v", op, errNoWsResponse)
	}
	if out == nil {
		return nil, fmt.Errorf("ws: %s: out is nil", op)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("ws: %s: read res err: %v", op, err)
	}

	err = json.Unmarshal(body, out)
	if err != nil {
		return nil, fmt.Errorf("ws: %s: unmarshal err: %v; res: %s", op, err, body)
	}

	return out, nil
}

func getSession(h *http.Client, tok string, test bool) (*WsSession, error) {
	if len(tok) <= 0 {
		return nil, errNoWsToken
	}
	/*
		curl -x GET '.../Session'
		-H 'Authorization: Bearer id:typ:epochsec:sig1:sig2'
	*/
	req, err := http.NewRequest("GET", baseurl(test)+wssessionpath, nil)
	if err != nil {
		return nil, fmt.Errorf("ws: getsess: make req err: %v", err)
	}
	authHeader(req, tok)

	res, err := h.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ws: getsess: req err: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, wsErr(res, "getsess")
	}

	var wsSess WsSessionResponse
	_, err = wsRes(res, &wsSess, "getsess")
	if err != nil {
		return nil, err
	}

	return &wsSess.Data, nil
}

func ordFromPid(pid string) string {
	if len(pid) <= 0 {
		return ""
	}
	// "id:epochsec:parentcidsig" => "id"
	parts := strings.Split(pid, ":")
	if len(parts) <= 0 {
		return ""
	}
	// return the first part, which is the "id"
	return parts[0]
}

func skipWsServer(server WsServerList) bool {
	if server.PremiumOnly != 1 { // skip non-premium servers
		return true
	} else if server.Status != 1 { // skip servers that are not okay
		return true
	} else if len(server.Groups) <= 0 {
		return true // skip servers without groups
	} // else if: skip server.P2P == 0?
	return false // this server is okay to use
}

func anyWsEndpoint(s []WsServerList) string {
	if len(s) <= 0 {
		return ""
	}
	for _, server := range s {
		if skipWsServer(server) {
			continue
		}
		for _, g := range server.Groups {
			if len(g.Nodes) <= 0 {
				continue // skip servers without nodes
			}
			if len(g.WgPubKey) <= 0 || len(g.WgEndpoint) <= 0 {
				continue // skip servers without wg
			}
			return g.WgEndpoint // return the first wg endpoint found
		}
	}
	return "" // no wg endpoint found
}

func wsRandomPort() string {
	// return a random port from the list of WireGuard ports
	return wswgports[rand.Int32N(int32(len(wswgports)))]
}

func wsRandomIP3(nodes []WsServerNode) string {
	if len(nodes) <= 0 {
		return ""
	}
	return nodes[rand.Int32N(int32(len(nodes)))].IP3
}

func convertToRegionalWgConfs(id *WsWgCreds, reservation *WsWgConnectData, list []WsServerList, sess *WsSession, test bool) ([]*RegionalWgConf, error) {
	if id == nil || reservation == nil || len(list) <= 0 {
		return nil, errNoWsServerList
	}

	out := make([]*RegionalWgConf, 0, len(list))
	for _, server := range list {
		if skipWsServer(server) {
			continue
		}

		port := wsRandomPort()
		for _, group := range server.Groups {
			servername := group.City + " (" + group.Nick + ")"
			if len(group.WgPubKey) <= 0 || len(group.WgEndpoint) <= 0 {
				continue // skip servers without wg
			}
			if len(group.Nodes) <= 0 {
				log.W("ws: wgconfs: no nodes in %s (%s)", group.City, group.Nick)
				continue // skip servers without nodes
			}
			out = append(out, &RegionalWgConf{
				CC:               server.CountryCode,
				Name:             servername,
				ClientAddr4:      reservation.Config.Address,
				ClientPrivKey:    id.PrivateKey,
				ClientPubKey:     id.PublicKey,
				ClientDNS4:       reservation.Config.DNS,
				PskKey:           id.PresharedKey,
				ServerPubKey:     group.WgPubKey,
				ServerDomainPort: net.JoinHostPort(group.WgEndpoint, port),
				ServerIPPort4:    net.JoinHostPort(wsRandomIP3(group.Nodes), port),
				// TODO: ipv6 or use id.AllowedIPs
				AllowedIPs: []string{gw4},
			})
		}
	}

	return out, nil
}

func getServerList(h *http.Client, sess *WsSession, ent *WsEntitlement) (*WsServerListResponse, error) {
	if sess == nil || ent == nil {
		return nil, errNoWsSession
	}
	lochash := sess.LocHash
	if len(lochash) <= 0 {
		return nil, errNoLocHash
	}
	bearer := sess.SessionAuthHash
	if len(bearer) <= 0 {
		return nil, errNoWsToken
	}
	test := ent.Test

	// curl -x GET '.../serverlist/mob-v2/1/<lochash>'
	locreq, err := http.NewRequest("GET", baseurl(test)+wslocpath+lochash, nil)
	if err != nil {
		return nil, fmt.Errorf("ws: wgconfs: req err: %v", err)
	}

	locres, err := h.Do(locreq)
	if err != nil {
		return nil, fmt.Errorf("ws: wgconfs: res err: %v", err)
	}

	defer core.Close(locres.Body)
	if locres.StatusCode != http.StatusOK {
		return nil, wsErr(locres, "wgconfs")
	}

	var wsServerList WsServerListResponse

	return wsRes(locres, &wsServerList, "wgconfs")
}

func genWgConfs(h *http.Client, existingCreds *WsWgCreds, sess *WsSession, servers []WsServerList, ent *WsEntitlement) (*WsWgCreds, []*RegionalWgConf, error) {
	if sess == nil || ent == nil {
		return nil, nil, errNoWsSession
	}
	lochash := sess.LocHash
	if len(lochash) <= 0 {
		return nil, nil, errNoLocHash
	}
	bearer := sess.SessionAuthHash
	if len(bearer) <= 0 {
		return nil, nil, errNoWsToken
	}
	test := ent.Test

	keyed := 0
keyagain:
	useExistingCreds := existingCreds != nil && keyed == 0

	var priv x.WgKey
	if !useExistingCreds {
		// register a deterministic WireGuard key for this client
		m := sha(ent.Cid)
		if ord := ordFromPid(ent.Sid); len(ord) > 0 {
			m = append(m, sha(ord)...)
		}
		if keyed != 0 {
			r := prng(16)
			if len(r) > 0 {
				m = append(m, r...)
			} // give up silently, same key as when keyed == 0
		}
		seed := hmac256(m, sha(sess.SessionAuthHash))
		key, err := newProtonKeyPairOf(bytes.NewReader(seed))
		if err != nil {
			return nil, nil, err
		}
		priv = key.ToX25519()
	} else {
		var err error
		// use the existing key, which is already registered
		priv, err = x.NewWgPrivateKeyOf(existingCreds.PrivateKey)
		if err != nil {
			return nil, nil, fmt.Errorf("ws: wgconfs: existing key err: %v", err)
		}
	}
	pub := priv.Mult()
	pubkeybase64 := pub.Base64().V()

	log.I("ws: wgconfs: gen creds: pubkey: %s, existing key? %t", trunc8(pubkeybase64), useExistingCreds)

	force := "0" // reset to 0, if force init is not needed

initagain:
	keyNeedsInit := !useExistingCreds || force == "1"

	var creds *WsWgCreds
	if keyNeedsInit {
		// POST 'https://api-staging.windscribe.com/WgConfigs/init' \
		// --header 'Content-Type: application/x-www-form-urlencoded' \
		// --header 'Authorization: Bearer id:typ:epochsec:sig1:sig2' \
		// --data-urlencode 'force_init=1'
		// --data-urlencode 'wg_pubkey=base64'
		initdata := url.Values{}
		initdata.Set("wg_pubkey", pubkeybase64)
		initdata.Set("force_init", force)
		initreq, err := http.NewRequest("POST", baseurl(test)+wswginitpath, strings.NewReader(initdata.Encode()))
		if err != nil {
			return nil, nil, fmt.Errorf("ws: wgconfs: req err: %v", err)
		}
		initreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		authHeader(initreq, bearer)

		initres, err := h.Do(initreq)

		if err != nil {
			return nil, nil, fmt.Errorf("ws: wgconfs: res err: %v", err)
		}

		if initres.StatusCode != http.StatusOK {
			wserr, err := wsErr2(initres, "wsinit")
			core.Close(initres.Body)
			if wserr.Code == ekeylimit {
				if force != "1" {
					log.I("ws: wgconfs: redo init with force for %s; err: %v", trunc8(pubkeybase64), err)
					force = "1"
					goto initagain
				}
			}
			log.E("ws: wgconfs: init %s, force? %t, err: %v", trunc8(pubkeybase64), force == "1", err)
			return nil, nil, err
		}

		defer core.Close(initres.Body)

		var wgCreds WsWgCredsResponse
		_, err = wsRes(initres, &wgCreds, "wgconfs")
		if err != nil {
			return nil, nil, err
		}

		d := wgCreds.Data
		creds = &d.Config
		if d.Success != 1 {
			return nil, nil, fmt.Errorf("ws: wgconfs: success != 1; debug: %d", d.Debug)
		}
		if len(d.Config.PrivateKey) <= 0 { // private key is generated locally (by the client)
			d.Config.PrivateKey = priv.Base64().V()
			if d.Config.PublicKey != pubkeybase64 { // registered public key must match the local one
				return nil, nil, fmt.Errorf("ws: wgconfs: pubkey mismatch; expected %s, got %s",
					pubkeybase64, d.Config.PublicKey)
			}
		} // TODO: else panic?
	} else {
		creds = existingCreds
	}

	if creds == nil || len(creds.PublicKey) <= 0 || len(creds.PrivateKey) <= 0 {
		return nil, nil, fmt.Errorf("ws: wgconfs: invalid creds for %s, useExisting? %t", trunc8(pubkeybase64), useExistingCreds)
	}

	log.I("ws: wgconfs: got creds for %s, usingExisting? %t", trunc8(pubkeybase64), useExistingCreds)

	someEndpoint := anyWsEndpoint(servers)
	if len(someEndpoint) <= 0 {
		return nil, nil, fmt.Errorf("ws: wgconfs: no endpoint")
	}
	/*
		curl -x POST '.../WgConfigs/connect' \
		--data-urlencode 'hostname=<>' \
		--data-urlencode 'wg_pubkey=stdbase64=='
		--data-urlencode 'wg_ttl=3600'
		-H 'Content-Type: application/x-www-form-urlencoded' \
		-H 'Authorization: Bearer id:typ:epochsec:sig1:sig2'
	*/
	cdata := url.Values{}
	// github.com/Windscribe/Android-App/blob/746d505dc69/base/src/main/java/com/windscribe/vpn/backend/utils/WindVpnController.kt#L159
	cdata.Set("hostname", someEndpoint)
	cdata.Set("wg_pubkey", pubkeybase64)
	cdata.Set("wg_ttl", wgttl)

	creq, err := http.NewRequest("POST", baseurl(test)+wswgconnectpath, strings.NewReader(cdata.Encode()))
	if err != nil {
		return nil, nil, fmt.Errorf("ws: wgconfs: connect req err: %v", err)
	}
	creq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	authHeader(creq, sess.SessionAuthHash)

	cres, err := h.Do(creq)
	if err != nil {
		return nil, nil, fmt.Errorf("ws: wgconfs: connect send err: %v", err)
	}
	if cres.StatusCode != http.StatusOK {
		core.Close(cres.Body)
		wserr, err := wsErr2(cres, "wsconnect")
		if wserr.Code == ekeyinvalid { // the key was deleted!
			if keyed == 0 {
				keyed = 1
				goto keyagain // try again with a non-default key
			}
		}
		return nil, nil, err
	}

	var wgConnect WsWgConnectResponse
	_, err = wsRes(cres, &wgConnect, "wgconfs")
	core.Close(cres.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("ws: wgconfs: connect res err: %v", err)
	}

	if wgConnect.Data.Success != 1 {
		return nil, nil, fmt.Errorf("ws: wgconfs: connect success != 1; debug: %v", wgConnect.Data.Debug)
	}

	if len(wgConnect.Data.Config.Address) <= 0 || len(wgConnect.Data.Config.DNS) <= 0 {
		return nil, nil, fmt.Errorf("ws: wgconfs: connect missing config; debug: %v", wgConnect.Data.Debug)
	}

	// TODO: if wgconnect.Data.Config.Address has not changed and useExistingCreds is true,
	// then we do not have to generate regional configs again (unless location hash has changed).
	regconfs, err := convertToRegionalWgConfs(creds, &wgConnect.Data, servers, sess, test)

	if err != nil || len(regconfs) <= 0 {
		return nil, nil, fmt.Errorf("ws: wgconfs: no regions found for %s; %v", trunc8(pubkeybase64), err)
	}

	log.I("ws: wgconfs: found %d regions for %s", len(regconfs), trunc8(pubkeybase64))
	return creds, regconfs, nil
}

func (a *WsClient) kid() string {
	if a == nil {
		return "<nil>"
	}
	c := a.config()
	if c == nil {
		return "<no cfg>"
	}
	pub := c.Creds.PublicKey
	if len(pub) <= 0 {
		return "<no pub key>"
	}
	return trunc8(pub)
}

func trunc8(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8] + "..."
}

func prng(n int) []byte {
	if n <= 0 {
		return nil
	}
	b := make([]byte, n)
	_, err := crand.Read(b)
	if err != nil {
		log.E("ws: randbytes: cannot read %d bytes; err: %v", n, err)
		return nil
	}
	return b
}

func newWsGw(c *WsWgConfig, h *http.Client) (*WsClient, error) {
	if h == nil || c == nil || c.Session == nil || c.Creds == nil {
		return nil, errInvalidWsGwArgs
	}
	a := &WsClient{
		http:      h,
		configExt: core.NewVolatile(c),
	}

	log.I("ws: gw: for %s; from: %s until: %s", a.Who(), fmtUnixMillis(a.Created()), fmtUnixMillis(a.Expires()))

	return a, nil
}

func (w *BaseClient) MakeWsWg(entitlement []byte) (*WsClient, error) {
	if len(entitlement) <= 0 {
		return nil, errNoEntitlement
	}

	var ent WsEntitlement
	err := json.Unmarshal(entitlement, &ent)
	if err != nil {
		return nil, err
	}

	return w.makeWsWg(&ent)
}

func (w *BaseClient) makeWsWg(hent *WsEntitlement) (*WsClient, error) {
	return makeWsWg(&w.h2, hent)
}

func makeWsWg(h *http.Client, ent *WsEntitlement) (*WsClient, error) {
	if ent == nil || len(ent.SessionToken) <= 0 {
		log.E("ws: makeWsWg: entitlement is nil")
		return nil, errNoEntitlement
	}

	sess, err := getSession(h, ent.SessionToken, ent.Test)
	if err != nil {
		return nil, err
	}

	servers, err := getServerList(h, sess, ent)
	if err != nil {
		return nil, err
	}

	creds, wgconfs, err := genWgConfs(h, nil, sess, servers.Data, ent)
	if err != nil {
		return nil, err
	}

	cfg := &WsWgConfig{
		Entitlement: ent,
		Session:     sess,
		Configs:     wgconfs,
		Servers:     servers.Data,
		Creds:       creds,
	}

	return newWsGw(cfg, h)
}

func (w *BaseClient) MakeWsWgFrom(entitlementOrWsConfigJson []byte) (*WsClient, error) {
	if len(entitlementOrWsConfigJson) <= 0 {
		return nil, errNoWsJsonConfig
	}

	var existingConf WsWgConfig
	err := json.Unmarshal(entitlementOrWsConfigJson, &existingConf)
	if err != nil {
		// may be this is an entitlement?
		log.W("ws: make: unmarshal config err: %v; retry as entitlement", err)
		return w.MakeWsWg(entitlementOrWsConfigJson)
	}

	return w.makeWsWgFrom(&existingConf)
}

func (w *BaseClient) makeWsWgFrom(existingConf *WsWgConfig) (*WsClient, error) {
	ws, _, err := makeWsWgFrom(&w.h2, existingConf)
	return ws, err
}

func makeWsWgFrom(h *http.Client, existingConf *WsWgConfig) (ws *WsClient, refreshedSess bool, err error) {
	existingEnt := existingConf.Entitlement
	if existingEnt == nil || len(existingEnt.SessionToken) <= 0 {
		err = errNoEntitlement
		return
	}

	existingSess := existingConf.Session
	existingCreds := existingConf.Creds
	if existingCreds == nil || existingSess == nil || len(existingSess.SessionAuthHash) <= 0 {
		ws, err = makeWsWg(h, existingEnt)
		refreshedSess = true
		return
	}

	existingLocHash := existingSess.LocHash
	if existingEnt.SessionToken != existingSess.SessionAuthHash {
		log.W("ws: make: entitlement does not match session")
	}

	newSess, err := getSession(h, existingEnt.SessionToken, existingEnt.Test)
	if err == nil {
		existingConf.Session = newSess // update session with the latest info
		refreshedSess = true
	} else {
		log.W("ws: make: get session err: %v; using existing", err)
		newSess = existingConf.Session // use existing session
	}

	exp, err := time.Parse(time.DateOnly, newSess.ExpiryDate)
	active := exp.After(time.Now())
	if !active {
		log.W("ws: make: session expired at %s", fmtTime(exp))
	}

	existingServers := existingConf.Servers
	downloadServerList := existingLocHash != newSess.LocHash

	if active {
		var maybeNewServers []WsServerList

		hasnew := false
		if downloadServerList {
			newServersRes, err := getServerList(h, newSess, existingEnt)

			loge(err)("ws: make: lochash changed %s != %s; fetch err? %v",
				existingLocHash, newSess.LocHash, err)

			if err != nil && len(existingServers) > 0 {
				maybeNewServers = existingServers
			} else if err == nil {
				maybeNewServers = newServersRes.Data
				hasnew = true
			} else { // no new servers, no existing servers; bail
				return nil, refreshedSess, core.OneErr(err, errNoWsServerList)
			}
		}

		// create wg confs from new or existing server list
		// always reconfigure (as /WgConfigs/connect must be done once every wg_ttl, which is 60m)
		maybeNewCreds, maybeNewWgConfs, err := genWgConfs(h, existingCreds, newSess, maybeNewServers, existingConf.Entitlement)
		loge(err)("ws: make: gen wg confs; new loc? %t; err? %v", hasnew, err)

		existingConf.Servers = maybeNewServers
		existingConf.Configs = maybeNewWgConfs
		existingConf.Creds = maybeNewCreds
	}

	ws, err = newWsGw(existingConf, h)
	return
}

func loge(err error) log.LogFn {
	if err == nil {
		return log.I
	}
	return log.E
}
