// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package rpn

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
)

// github.com/Windscribe/browser-extension/blob/ed83749ad/modules/ext/src/utils/constants.js#L31
const (
	svchost     = "svc.rethinkdns.com"
	svchosttest = "redir.nile.workers.dev"
	wsMyIp      = "https://checkip.windscribe.com/"
	wsMyIp2     = "https://checkip.totallyacdn.com/"
	// didIDHeader is the HTTP request header carrying the raw device ID.
	didIDHeader = "x-rethink-app-did"
	// didTokenHeader is the HTTP response/request header for a device-id token
	// issued by svchost / svchosttest. Format: "a hextoken:expiryepochsec".
	didTokenHeader = "x-rethink-app-did-token"
	// github.com/celzero/redir/blob/4b65e7f71510aa74ac3623c85ee1d8a1ec979359/src/d.js#L14
	dbBookmarkHeader     = "x-rethink-db-rpn-session"
	dbBookmarkHeaderTest = "x-rethink-db-rpn-test-session"
	// by default, servers use read-replica; set primary bookmark to instruct
	// the servers to use primary for at least the first query (which may or may not
	// be a cid/did validation query; especially if didTokenHeader isn't present).
	forcePrimaryReads = "first-primary"
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
	// Another error 1312 - "Could not select a new WireGuard interface IP" is returned
	// by "/connect" if the "/init"d client IP was released by the server and assigned
	// to another user?
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
	// wswgpermanentpath generates a permanent (static) WireGuard config tied to a client-supplied
	// public key. Unlike /init+/connect, this config does not expire automatically.
	// POST with form fields: port, wg_pubkey. Bearer token is client-supplied.
	wswgpermanentpath = "WgConfigs/permanent"
	// wswglistkeyspath lists all active permanent WireGuard configs for the account (max 5).
	// GET with Bearer token client-supplied.
	wswglistkeyspath = "WgConfigs/list_keys"
	// wsgetfilterspath fetches the current Robert DNS filter list.
	// GET with Bearer session token; returns all filters and their enabled/disabled status.
	wsgetfilterspath = "Robert/filters"
	// wssetfilterpath enables or disables a single Robert DNS filter.
	// PUT with Bearer session token.
	wssetfilterpath = "Robert/filter"
	// TTL reservation time using param "wg_ttl", not for longer than an hour, if needed.
	// github.com/Windscribe/Android-App/blob/3f9c2ab98a70fa/base/src/main/java/com/windscribe/vpn/repository/WgConfigRepository.kt#L143
	wgttl = "3600" // an hour in seconds

	wssessionpath = "Session/"
	// wsportpath    = "PortMap/"
	wslocpath = "serverlist/mob-v2/1/" // + $loc_hash

	// for ovpn (unused):
	// wspxpath = "ServerCredentials/"
	// wsbestloc = "BestLocation/"

	wsMinServerLinkSpeed = 1    // 1mbps
	wsMaxServerHealth    = 100  // min is 0
	allPerRegionWgConfs  = true // when false, only maxPerRegionWgConfs*2 are chosen
	maxPerRegionWgConfs  = 4
	maxAnyWgConfs        = 8
	wsMaxPermaWgKeys     = 5

	disablePermaCreds = true

	// managedPermaCreds selects a server-managed keypair strategy for permanent creds.
	// When true, the keypair is generated entirely by the server (no local key-gen and no
	// /WgConfigs/init call). The server-generated keypair is always returned by
	// /WgConfigs/list_keys, so liveness can be checked without any /init round-trip.
	// When false (default), the existing locally-generated key + /init + /permanent flow is used.
	managedPermaCreds = false
)

// github.com/Windscribe/Android-App/blob/746d505dc69/base/src/main/java/com/windscribe/vpn/constants/NetworkErrorCodes.kt
const (
	ekeylimit   = 1313
	ekeyinvalid = 1311
	enoaddr     = 1312
)

const (
	confKeySep = ";"

	// onlyPremiumServers removes non-premium servers from the server list,
	// which may reduce its count substantially.
	onlyPremiumServers = false
)

// github.com/Windscribe/Android-App/blob/746d505dc69/base/src/main/res/raw/port_map.txt#L76
var wswgports = []string{ /*0th & 1st pos used by wsRandomPort */ "65142", "1194", "53", "123", "443", "80"}

var (
	errWsBadGatewayArgs = errors.New("ws: cannot make gw; missing args")
	errWsNoConfig       = errors.New("ws: no config")
	errWsNoPermaCreds   = errors.New("ws: no permanent creds")
	errWsNoJsonConfig   = errors.New("ws: no json config")
	errWsNoSession      = errors.New("ws: no session info")
	errWsNoClient       = errors.New("ws: no client")
	errWsNoEntitlement  = errors.New("ws: missing entitlement")
	errWsBadEntitlement = errors.New("ws: entitlement not good")
	errWsNoToken        = errors.New("ws: missing token")
	errWsNoCid          = errors.New("ws: missing cid")
	errWsNoDid          = errors.New("ws: missing device id")
	errWsNoResponse     = errors.New("ws: no response")
	errWsNoLocHash      = errors.New("ws: no loc hash")
	errWsNoServerList   = errors.New("ws: no server list")
	errWsBadServerList  = errors.New("ws: invalid server list")
	errWsRetryUpdate    = errors.New("ws: retry update")
	errWsNoCcConfig     = errors.New("ws: not available in that location")
	errWsNoFilters      = errors.New("ws: no filter list")
	errWsCCExcluded     = errors.New("ws: cc excluded")
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
		PortMap []WsPortMap `json:"portmap"`
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
	// RPN errors
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
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
type WsPortMap struct {
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
	// 100, 1000, 10000 (in mbps) etc;
	LinkSpeed string `json:"link_speed"`
	// Nodes are online servers that can be connected to in a datacneter.
	// If empty, the datacenter is offline.
	Nodes []WsServerNode `json:"nodes"`
	// Health is a measure of load, between 0 and 100. Lower is better.
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
	        "last_reset": "2025-07-12", // or null
	        "loc_rev": 2672,
	        "loc_hash": "6ad01549d66..."
	}
*/
type WsSession struct {
	UserID string `json:"user_id"`
	// Encrypted account session token authenticates this user with the API to get
	// and set any state, incl WG configuration which are unique and bound
	// to each session token. Session token is the "bearer token".
	// Unencrypted session/bearer token is of shape, id:type:timestamp:sig1:sig2.
	// However it could change to a new format in the future.
	SessionToken string `json:"session_auth_hash"`
	Username     string `json:"username"`
	// TrafficUsed shows byte count of data used since LastReset date?
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
	ExpiryDate string `json:"premium_expiry_date"`
	RegDate    int64  `json:"reg_date"`
	LastReset  string `json:"last_reset"` // can be null
	LocRev     int    `json:"loc_rev"`
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
	            "AllowedIPs": "0.0.0.0/0",
	            "Address": "100.64.236.203/32",  // omitempty: absent in /init responses; present in /permanent
	            "DNS": "10.255.255.1"             // omitempty: absent in /init responses; present in /permanent
	}
*/
type WsWgCreds struct {
	PrivateKey   string `json:"PrivateKey,omitempty"` // base64; locally generated for /init, server-generated for /permanent
	PublicKey    string `json:"PublicKey"`            // base64; locally generated for /init, server-generated for /permanent
	PresharedKey string `json:"PresharedKey"`         // base64; only the latest key is valid (generated by remote)
	AllowedIPs   string `json:"AllowedIPs"`           // e.g. "0.0.0.0/0" or "0.0.0.0/0, ::/0"
	// Address and DNS are populated only by the /permanent endpoint; empty for /init responses.
	// So dynamic creds, after /init, will have to /connect before populating these
	Address string `json:"Address,omitempty"` // CIDR notation, e.g. "100.64.236.203/32"
	DNS     string `json:"DNS,omitempty"`     // IP address, e.g. "10.255.255.1"
}

/*
	{
	        "config": WsWgCreds,
	        "debug": {
	            "init": "generated: tsoZzRelDNFe/xF6eQz+xxzjmgS0xKfxEmlqsZKPNgs="
	        },
	        "success": 1
	}

// Also used for /WgConfigs/permanent responses, where config additionally
// carries Address and DNS (populated in WsWgCreds via the omitempty fields).
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

// WsWgPermanentConfig is an alias for WsWgCreds; the /permanent endpoint returns
// the same envelope as /init (WsWgCredsData / WsWgCredsResponse) but additionally
// populates the Address and DNS fields added to WsWgCreds.
type WsWgPermanentConfig = WsWgCreds

/*
	{
	    "data": {
	        "pub_keys": ["WzPsW3p+t5rkbZ2zg/QciGN3vMQVKciP/csQzIZ0ohE=", ...],
	        "success": 1
	    },
	    "metadata": { ... }
	}
*/
type WsWgListKeysData struct {
	PubKeys []string `json:"pub_keys"`
	Success int      `json:"success"`
}

type WsWgListKeysResponse struct {
	Data     WsWgListKeysData `json:"data"`
	Metadata WsMetadata       `json:"metadata"`
}

// WsFilter represents a single Robert DNS filter entry.
type WsFilter struct {
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	ID          string `json:"id"`
	// Status is 1 when the filter is enabled, 0 when disabled.
	Status int `json:"status"`
}

type WsFiltersData struct {
	Filters []WsFilter `json:"filters"`
	Success int        `json:"success"`
}

type WsFiltersResponse struct {
	Data     WsFiltersData `json:"data"`
	Metadata WsMetadata    `json:"metadata"`
}

// WsFilterSetRequest is the JSON body for PUT Robert/filter.
type WsFilterSetRequest struct {
	Filter string `json:"filter"`
	Status int    `json:"status"`
}

type WsFilterSetData struct {
	Success int `json:"success"`
}

type WsFilterSetResponse struct {
	Data     WsFilterSetData `json:"data"`
	Metadata WsMetadata      `json:"metadata"`
}

// Robert DNS filter IDs as returned by the API.
const (
	wsFilterMalware     = "malware"
	wsFilterAds         = "ads"
	wsFilterSocial      = "social"
	wsFilterPorn        = "porn"
	wsFilterGambling    = "gambling"
	wsFilterFakeNews    = "fakenews"
	wsFilterCompetitors = "competitors"
	wsFilterCrypto      = "cryptominers"
)

// wsAllFilterIDs is the ordered list of every known Robert DNS filter ID.
var wsAllFilterIDs = []string{
	wsFilterMalware, wsFilterAds, wsFilterSocial, wsFilterPorn,
	wsFilterGambling, wsFilterFakeNews, wsFilterCompetitors, wsFilterCrypto,
}

// wsDNSPresetFilters maps each named preset to the filter IDs it enables.
// "none" and "default" are not in the map; their absence means "enable nothing".
var wsDNSPresetFilters = map[string][]string{
	"family":   {wsFilterMalware, wsFilterPorn, wsFilterGambling, wsFilterFakeNews},
	"security": {wsFilterMalware, wsFilterCrypto, wsFilterFakeNews},
	"social":   {wsFilterSocial},
	"privacy":  {wsFilterAds},
	"all":      wsAllFilterIDs,
}

// dnsConfigToFilters converts a csv of DNS preset names (e.g. "family,privacy")
// into a set of filter IDs that should be enabled. "none" and "default" disable
// all filters; absent presets leave the set unchanged.
func dnsConfigToFilters(dnsConfig string) map[string]bool {
	enabled := make(map[string]bool)
	for _, part := range strings.Split(dnsConfig, ",") {
		preset := strings.TrimSpace(strings.ToLower(part))
		switch preset {
		case "none", "default", "":
			// no filters enabled for these presets; leave enabled unchanged
		default:
			for _, fid := range wsDNSPresetFilters[preset] {
				enabled[fid] = true
			}
		}
	}
	return enabled
}

type WsClient struct {
	RpnMultiCountry

	http *http.Client
	ops  *core.Volatile[x.RpnOps] // current ops; retained across subsequent Conf() calls

	configExt           *core.Volatile[*WsWgConfig]
	configExtUpdateTime *core.Volatile[time.Time]
}

type WsWgConfig struct {
	Entitlement *WsEntitlement       `json:"entitlement"` // entitlement info
	Session     *WsSession           `json:"session"`
	Configs     []*RegionalWgConf    `json:"configs"`
	Servers     []WsServerList       `json:"servers"`              // all servers in the server list
	Creds       *WsWgCreds           `json:"creds"`                // base64 encoded private key
	PermaCreds  *WsWgPermanentConfig `json:"permacreds,omitempty"` // permanent WG config; nil if not yet fetched
	LastUpdate  time.Time
}

// wsUpdateThreshold is the minimum interval between session calls when ops.ForceInit() is false.
const wsUpdateThreshold = 40 * time.Minute

/*
{
"kind": "ws#v1",
"cid": "hex", // Identifier
"sid": "id:epochsec:parentcidsig", // profile identifier, if any
"sessiontoken": enc("id:typ:epochsec:sig1:sig2"),
"expiry": "2025-07-15T00:00:00Z", // Expiry date of the entitlement
"status": "valid" // "valid" | "invalid" | "banned" | "expired" | "unknown"
"allowRestore": false, // true if this entitlement can be restored
"test": false // true if this is a test entitlement
}
*/
type WsEntitlement struct {
	Kind         string `json:"kind"`          // e.g. "ws#v1"
	Cid          string `json:"cid"`           // Client ID
	Did          string `json:"did,omitempty"` // Device ID, if any
	Pid          string `json:"pid,omitempty"` // Share ID
	SessionToken string `json:"sessiontoken"`  // Encrypted session token
	// Expiry date of the entitlement; go.dev/play/p/1rWNG6GPGqN
	Exp              time.Time `json:"expiry"`
	AccStatus        string    `json:"status"`       // "valid" | "invalid" | "banned" | "expired" | "unknown"
	AllowCrossDevice bool      `json:"allowRestore"` // true if this entitlement can be restored
	TestDomain       bool      `json:"test"`         // true if this is a test entitlement
	// DidToken is the device-id token (x-rethink-app-did-token) issued by svchost,
	// format "hextoken:expiryepochsec".
	DidToken string `json:"didtoken,omitempty"`
}

var _ x.RpnAcc = (*WsClient)(nil)
var _ x.RpnEntitlement = (*WsEntitlement)(nil)

func (e *WsEntitlement) ok() bool {
	return e != nil && len(e.SessionToken) > 0 && len(e.Cid) > 0
}

func (e *WsEntitlement) ProviderID() string {
	return x.RpnWin
}

func (e *WsEntitlement) DID() string {
	return e.Did
}

func (e *WsEntitlement) CID() string {
	return e.Cid
}

func (e *WsEntitlement) Token() string {
	return e.SessionToken
}

func (e *WsEntitlement) Expiry() string {
	return e.Exp.Format(time.RFC3339)
}

func (e *WsEntitlement) Status() string {
	return e.AccStatus
}

func (e *WsEntitlement) AllowRestore() bool {
	return e.AllowCrossDevice
}

func (e *WsEntitlement) Test() bool {
	return e.TestDomain
}

func (e *WsEntitlement) Json() ([]byte, error) {
	if !e.ok() {
		return nil, errWsBadEntitlement
	}
	var w core.ByteWriter
	enc := json.NewEncoder(&w)
	if err := enc.Encode(e); err != nil {
		return nil, fmt.Errorf("ws: entitlement encode err: %w", err)
	}
	// Bytes not recycled as these are crossing into cgo
	return w.Bytes(), nil
}

func (a *WsWgConfig) Json() ([]byte, error) {
	if a == nil {
		return nil, errWsNoConfig
	}

	var w core.ByteWriter
	if err := a.writeJson(&w); err != nil {
		return nil, err
	}
	// Bytes not recycled as these are crossing into cgo
	return w.Bytes(), nil
}

func (a *WsWgConfig) writeJson(w io.Writer) error {
	if a == nil {
		return errWsNoConfig
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(a)
}

func (a *WsClient) config() *WsWgConfig {
	if a == nil {
		return nil
	}
	return a.configExt.Load()
}

// Who implements x.RpnAcc.
func (a *WsClient) Who() string {
	if a == nil {
		return "<nil>"
	}
	c := a.config()
	if c == nil || c.Session == nil {
		return "<no config>"
	}
	status := strconv.Itoa(c.Session.Status)
	return status + ":" + c.Session.UserID + "+" + trunc8(byte2hex(sha(c.Session.SessionToken))) + "@" + a.kid()
}

// ProviderID implements RpnAcc.
func (*WsClient) ProviderID() string { return x.RpnWin }

// State implements x.RpnAcc.
func (a *WsClient) State() ([]byte, error) {
	if a == nil {
		return nil, errWsNoClient
	}
	c := a.config()
	if c == nil {
		return nil, errWsNoConfig
	}
	return c.Json()
}

// Created implements x.RpnAcc.
func (a *WsClient) Created() int64 {
	if a == nil {
		return -1
	}
	c := a.config()
	if c == nil {
		return 0
	}
	createdAt := time.Unix(int64(c.Session.RegDate), 0)
	return createdAt.UnixMilli()
}

func (a *WsClient) Updated() int64 {
	if a == nil {
		return -1
	}
	c := a.config() // must have config
	if c == nil {
		return 0
	}
	updatedAt := a.configExtUpdateTime.Load()
	return updatedAt.UnixMilli()
}

// Ops implements x.RpnAcc.
func (a *WsClient) Ops() *x.RpnOps {
	ops := a.ops.Load()
	return &ops
}

// Expires implements x.RpnAcc.
func (a *WsClient) Expires() int64 {
	if a == nil {
		return -1
	}
	c := a.config()
	if c == nil {
		return 0
	}

	refreshAt, err := time.Parse(time.DateOnly, c.Session.ExpiryDate)
	if err != nil {
		log.W("ws: expires: cannot parse %s; err: %v", c.Session.ExpiryDate, err)
		return -2
	}

	return refreshAt.UnixMilli()
}

func (a *WsClient) Locations() (x.RpnServers, error) {
	if a == nil {
		return nil, errWsNoClient
	}
	c := a.config()
	if c == nil {
		return nil, errWsNoConfig
	}
	if len(c.Configs) <= 0 {
		return nil, errWsNoCcConfig
	}
	excl := ccCsvAsSet(a.Ops().ExcludeCCs())
	visited := make(map[string]bool, len(c.Configs))
	s := make([]x.RpnServer, 0, len(c.Configs)/maxPerRegionWgConfs)
	for i, rc := range c.Configs {
		if rc == nil {
			log.W("ws: locations: config %d is nil", i)
			continue
		}
		if len(rc.ServerPubKey) <= 0 {
			log.D("ws: locations: config#%d has no wg conf", i)
			continue
		}
		if len(rc.CC) <= 0 {
			log.W("ws: locations: config#%d has no cc", i)
			continue
		}
		if !visited[rc.Name] {
			_, isExcluded := excl[rc.CC]
			s = append(s, x.RpnServer{
				CC:       rc.CC,
				City:     rc.City,
				Name:     rc.Name,
				Load:     rc.Load,
				Link:     rc.Link,
				Count:    rc.Count,
				Premium:  rc.Premium,
				Excluded: isExcluded,
				// cc is always suffixed; see proxy.go:proxifier.postAddRpnProxy
				Key:   strings.Join([]string{rc.City, rc.CC}, confKeySep),
				Addrs: strings.Join([]string{rc.ServerDomainPort, rc.addrCsv()}, ","),
			})
		}
		visited[rc.Name] = true
	}
	return &RpnMultiCountryServers{s}, nil
}

// Update implements x.RpnAcc.
func (a *WsClient) Update(ops *x.RpnOps) (newstate []byte, err error) {
	if a == nil {
		return nil, errWsNoClient
	}
	c := a.config()
	if c == nil {
		return nil, errWsNoConfig
	}
	curops := a.Ops()
	if ops == nil {
		ops = curops
	} else {
		if len(ops.DNSConfig()) <= 0 {
			// retain existing dns config
			ops.SetDNSConfig(curops.DNSConfig())
		}
		// retain existing excludeCCs if not set by incoming ops
		if len(ops.ExcludeCCs()) <= 0 {
			ops.SetExcludeCCs(curops.ExcludeCCs())
		}
	}
	start := time.Now()
	b, refreshed, needsRedo, err := makeWsWgFrom(a.http, c, *ops, true /*updating*/, ops.ChangesConfig(*curops))
	if err != nil || !refreshed {
		log.E("ws: update: refreshed? %t; err: %v", refreshed, err)
		return nil, core.OneErr(err, errWsRetryUpdate)
	}

	// if configs have changed, the current proxies using those, if any,
	// will need to be updated.
	if _, err := a.shallowCopyConfig(b); err != nil {
		return nil, log.EE("ws: update: shallow copy err: %v", err)
	}
	log.I("ws: update: refreshed? %t / redo? %t; took %v", refreshed, needsRedo, core.FmtTimeAsPeriod(start))
	if !needsRedo {
		return nil, nil
	}

	return a.State()
}

func (a *WsClient) shallowCopyConfig(b *WsClient) (copied bool, err error) {
	if a == nil || b == nil {
		return false, nil // no-op
	}
	bc := b.config()
	if bc == nil {
		log.E("ws: shallowcopy: storing nil config...")
		return false, errWsNoConfig
	}
	a.configExt.Store(bc)
	a.configExtUpdateTime.Store(time.Now())
	a.ops.Store(*b.Ops())
	return true, nil
}

// Conf implements RpnAcc.
func (a *WsClient) Conf(cc string) (string, error) {
	cfg := a.config()
	if cfg == nil {
		return "", errWsNoConfig
	}
	usePerma := !disablePermaCreds && a.Ops().Perma()
	if usePerma && cfg.PermaCreds == nil {
		usePerma = false
		log.E("ws: conf: permacreds requested but nil; using dynamic creds")
	}
	portstr := ""
	if port := a.Ops().Port(); port > 0 {
		portstr = fmt.Sprintf("%d", port) // port may be 0
	}
	city := ""
	if cccsv := strings.Split(cc, confKeySep); len(cccsv) >= 2 {
		city = cccsv[0]
		cc = cccsv[1]
	}
	// in sync with anyCountryCode / noCountryForOldMen vars in proxy.go
	chooseAny := cc == "**" || len(cc) <= 0
	hasCity := len(city) > 0
	cc = strings.ToUpper(cc)

	excl := ccCsvAsSet(a.Ops().ExcludeCCs())
	// if a specific (non-wildcard) CC is explicitly excluded, bail early
	if !chooseAny && len(excl) > 0 {
		if _, excluded := excl[cc]; excluded {
			log.W("ws: conf: cc %s is excluded...", cc)
			return "", errWsCCExcluded
		}
	}

	retried := false
reconf:
	tot := 0  // total seen
	c := 0    // good cc conf
	badc := 0 // bad cc conf
	x := 0    // total excluded
	v := 0    // total visited
	visited := make(map[string]struct{}, len(cfg.Configs))
	out := make([]string, 0, maxPerRegionWgConfs)
	ids := make([]string, 0, maxPerRegionWgConfs)
	for _, rc := range cfg.Configs {
		// TODO: strings.HasSuffix(rc.Cc, cc) replaced with ==?
		if (chooseAny || strings.HasSuffix(rc.CC, cc)) && (!hasCity || rc.City == city) {
			if chooseAny {
				if _, ok := visited[rc.CC]; ok {
					continue
				}
				visited[rc.CC] = struct{}{}
				v++
				// skip CCs the user has excluded
				if _, excluded := excl[rc.CC]; excluded {
					x++
					continue
				}
				if c > 2 {
					// after a couple random servers, prefer low load and high link speed servers
					gbps10 := rc.Link >= 10000
					healthy50 := rc.Load <= 50
					gbps1 := rc.Link >= 1000
					healthy20 := rc.Load <= 20
					if !gbps10 && !gbps1 {
						continue
					}
					if (gbps10 && !healthy50) || (gbps1 && !healthy20) {
						continue
					}
				}
				if c >= maxAnyWgConfs {
					// generate maxAnyWgConfs across all CCs.
					break
				}
			} else {
				if !hasCity && c >= maxPerRegionWgConfs {
					// not chooseAny; city not specified;
					// generate maxPerRegionWgConfs for this cc.
					break
				}
			}

			var confstr string
			var confok bool
			if usePerma && cfg.PermaCreds != nil {
				confstr, confok = rc.MakeUapiConfig(cfg.PermaCreds, portstr)
			} else {
				confstr, confok = rc.MakeUapiConfig(cfg.Creds, portstr)
			}
			if confok {
				out = append(out, confstr)
				ids = append(ids, strings.Join([]string{rc.CC, rc.City, rc.Name}, "/"))
				c++
			} else {
				badc++
			}
		}
		tot++
	}
	if len(out) > 0 {
		r := rand.IntN(len(out))
		log.I("ws: conf: cc %s(%s): %d/%d => chosen (any? %t): %d[%s] (port: %s)", cc, city, c, len(out), chooseAny, r, ids[r], portstr)
		return out[r], nil
	}
	if tot == 0 || v <= x { // fail open if all CCs excluded
		logew(retried)("ws: conf: cc %s(%s): all visited(%d) / excluded(%d) / bad(%d); tot: %d / excl: %d; retry?",
			cc, city, v, x, badc, tot, len(excl), !retried)
		if !retried {
			clear(excl) // fail open; excluded none
			clear(visited)
			retried = true
			goto reconf
		}
	}
	log.E("ws: conf: cc %s(%s) not found (tot: %d)", cc, city, tot)
	return "", errWsNoCcConfig
}

// unused on the control plane, so use a fixed but valid hostname
func fixedValidWsEndpoint(test bool) string {
	if test {
		return "ca.windscribe.dev"
	}
	return "ca.windscribe.com"
}

func baseurl(test bool, cid string) *url.URL {
	svc := svchost
	if test {
		svc = svchosttest
	}
	u := url.URL{
		Scheme: "https",
		Host:   svc,
	}
	q := u.Query()
	q.Set("cid", cid)
	if test {
		q.Set("rpn", "wstest")
		q.Set("test", "") // value for the test param does not matter
	} else {
		q.Set("rpn", "ws")
	}
	u.RawQuery = q.Encode()

	return &u
}

func assetsurl(test bool, cid string) *url.URL {
	svc := svchost
	if test {
		svc = svchosttest
	}
	u := url.URL{
		Scheme: "https",
		Host:   svc,
	}
	q := u.Query()
	q.Set("cid", cid)
	if test {
		q.Set("rpn", "wsassetstest")
		q.Set("test", "") // value for the test param does not matter
	} else {
		q.Set("rpn", "wsassets")
	}
	u.RawQuery = q.Encode()

	return &u
}

func authHeader(req *http.Request, t string) {
	if req == nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+t)
}

// didAndDBHeader sets the x-rethink-app-did and x-rethink-app-did-token request
// headers when their respective values are non-empty.
func didAndDBHeader(req *http.Request, did, tok string, test bool) {
	if req == nil {
		return
	}
	if len(did) > 0 {
		req.Header.Set(didIDHeader, did)
	}
	if len(tok) > 0 {
		req.Header.Set(didTokenHeader, tok)
	} else {
		bmh := dbBookmarkHeader
		if test {
			bmh = dbBookmarkHeaderTest
		}
		req.Header.Set(bmh, forcePrimaryReads)
	}
}

func logDidToken(tok string) {
	if len(tok) <= 0 {
		log.W("ws: didtoken: empty token")
		return
	}
	// token format is "a hextoken:expiryepochsec"; parse the epoch to log expiry.
	parts := strings.SplitN(tok, ":", 2)
	if len(parts) < 2 {
		log.W("ws: didtoken: unknown format")
		return
	}
	expSec, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
	if err != nil {
		log.E("ws: didtoken: cannot parse expiry epoch: %v", err)
	}
	expTime := time.Unix(expSec, 0)
	log.I("ws: didtoken: expiry %s; expired? %t", fmtTime(expTime), expTime.Before(time.Now()))
}

// updateDidTokenIfNeeded reads didTokenHeader from the response, logs its expiry,
// and – when it differs from ent.DidToken – overwrites it in ent.
func updateDidTokenIfNeeded(ent *WsEntitlement, res *http.Response) {
	if ent == nil || res == nil {
		return
	}
	incoming := res.Header.Get(didTokenHeader)
	logDidToken(incoming)
	if len(incoming) > 0 && ent.DidToken != incoming {
		ent.DidToken = incoming
	}
}

func wsErr(res *http.Response, op string) error {
	_, err := wsErr2(res, op)
	return err
}

func wsErr2(res *http.Response, op string) (*WsErrorResponse, error) {
	if res == nil {
		return nil, log.EE("ws: %s: %v", op, errWsNoResponse)
	}
	code := res.StatusCode
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, log.EE("ws: %s: (%d) read body err: %v", op, code, err)
	}

	var wsErr WsErrorResponse
	err = json.Unmarshal(body, &wsErr)
	if err != nil {
		return nil, log.EE("ws: %s: (%d) unmarshal err: %v; body: %s", op, code, err, truncate2k(body))
	}

	if len(wsErr.Error) > 0 {
		wsErr.Msg += "/" + wsErr.Error
	}
	if len(wsErr.Details) > 0 {
		if len(wsErr.Desc) > 0 {
			wsErr.Desc += "/" + wsErr.Details
		} else {
			wsErr.Desc = wsErr.Details
		}
	}
	if len(wsErr.Msg) <= 0 {
		wsErr.Msg = string(truncate2k(body))
	}

	return &wsErr, log.EE("ws: %s: (%d) error %d: %s; why: %s", op, code, wsErr.Code, wsErr.Msg, wsErr.Desc)
}

func wsRes[T any](res *http.Response, out *T, op string) (*T, error) {
	if res == nil {
		return nil, log.EE("ws: %s: %v", op, errWsNoResponse)
	}
	if out == nil {
		return nil, log.EE("ws: %s: out is nil", op)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, log.EE("ws: %s: read res err: %v", op, err)
	}

	err = json.Unmarshal(body, out)
	if err != nil {
		return nil, log.EE("ws: %s: unmarshal err: %v; res: %s", op, err, truncate2k(body))
	}

	if settings.Debug {
		log.V("ws: wgconfs: %s: res json: %+v", op, out)
	}

	return out, nil
}

func getSession(h *http.Client, ent *WsEntitlement) (*WsSession, error) {
	if ent == nil {
		return nil, errWsNoSession
	}
	tok := ent.SessionToken
	if len(tok) <= 0 {
		return nil, errWsNoToken
	}
	cid := ent.Cid
	if len(cid) <= 0 {
		return nil, errWsNoCid
	}
	did := ent.Did
	tokst := tokenState(tok)
	/*
		curl -x GET '.../Session'
		-H 'Authorization: Bearer id:typ:epochsec:sig1:sig2'
	*/
	u := baseurl(ent.TestDomain, cid).JoinPath(wssessionpath)
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, log.EE("ws: getsess: make req err: %v", err)
	}
	authHeader(req, tok)
	didAndDBHeader(req, did, ent.DidToken, ent.TestDomain)

	if settings.Debug {
		log.V("ws: getsess: req: %s tok %s", u.String(), tokst)
	}

	res, err := h.Do(req)
	if err != nil || res == nil {
		return nil, log.EE("ws: getsess: res err (nil? %t / tok? %s): %v", res == nil, tokst, err)
	}
	defer core.Close(res.Body)
	updateDidTokenIfNeeded(ent, res)
	if res.StatusCode != http.StatusOK {
		return nil, wsErr(res, "getsess/"+tokst)
	}

	var wsSess WsSessionResponse
	_, err = wsRes(res, &wsSess, "getsess/"+tokst)
	if err != nil {
		return nil, err
	}

	return &wsSess.Data, nil
}

func skipWsServer(server WsServerList) (bool, string) {
	if onlyPremiumServers && server.PremiumOnly != 1 { // skip non-premium servers
		return true, "not premium"
	} else if server.Status != 1 { // skip servers that are not okay
		return true, "status not okay"
	} else if len(server.Groups) <= 0 {
		return true, "no groups" // skip servers without groups
	} // else if: skip server.P2P == 0?
	return false, "" // this server is okay to use
}

func wsRandomPort() string {
	// return a random port from the list of WireGuard ports
	// return wswgports[rand.Int32N(int32(len(wswgports)))]
	if rand.Uint()%2 == 0 {
		return wswgports[0]
	}
	return wswgports[1]
}

func wsRandomIP3(nodes []WsServerNode) string {
	if len(nodes) <= 0 {
		return ""
	}
	return nodes[rand.Int32N(int32(len(nodes)))].IP3
}

func hasIP3(nodes []WsServerNode) bool {
	if len(nodes) <= 0 {
		return false
	}
	for _, node := range nodes {
		if len(node.IP3) > 0 {
			return true
		}
	}
	return false
}

func convertToRegionalWgConfs(id *WsWgCreds, list []WsServerList, test bool, port string) ([]*RegionalWgConf, error) {
	if id == nil || len(id.DNS) <= 0 || len(id.Address) <= 0 || len(list) <= 0 {
		return nil, fmt.Errorf("regional configs err: DNS/Addr/creds? %t; servers? %d",
			id != nil, len(list))
	}

	tot := make(map[string]int)
	out := make([]*RegionalWgConf, 0, len(list))
	for _, server := range list {
		if !test {
			if skip, why := skipWsServer(server); skip {
				log.VV("ws: conf: convert skip; %s: %s", server.CountryCode, why)
				continue
			}
		}

		cc := server.CountryCode
		portStr := port
		if len(portStr) <= 0 {
			portStr = wsRandomPort()
		}
		sorted := core.Sort(server.Groups, func(a, b WsServerGroup) int {
			ia, _ := strconv.ParseInt(a.LinkSpeed, 10, 64)
			ib, _ := strconv.ParseInt(b.LinkSpeed, 10, 64)
			// max(..., wsMinServerLinkSpeed) preserves actual link speed (100/1000/10000 mbps)
			// rather than clamping everything to 1 with min.
			// Score: higher = healthier (lower load) AND faster link; best servers first.
			la := max(int(ia), wsMinServerLinkSpeed) * (wsMaxServerHealth - a.Health)
			lb := max(int(ib), wsMinServerLinkSpeed) * (wsMaxServerHealth - b.Health)
			if la > lb { // descending: highest composite score (healthiest + fastest) first
				return -1
			} else if la < lb {
				return 1
			}
			return 0
		})

		for _, group := range sorted {
			servername := group.City + " (" + group.Nick + ")"
			if len(group.WgPubKey) <= 0 || len(group.WgEndpoint) <= 0 {
				continue // skip servers without wg
			}
			noip3 := !hasIP3(group.Nodes)
			if len(group.Nodes) <= 0 || noip3 {
				log.W("ws: wgconfs: no nodes in %s (%s); ip3? %t", group.City, group.Nick, noip3)
				continue // skip servers without nodes
			}
			if !allPerRegionWgConfs && tot[cc] >= maxPerRegionWgConfs*2 {
				log.D("ws: wgconfs: skip! %s (%s) has %d configs already",
					cc, servername, tot[cc])
				break // we have enough configs for this region
			}
			tot[cc] = tot[cc] + 1
			dnsaddr := id.DNS
			if len(dnsaddr) <= 0 {
				dnsaddr = cfdns4
			}
			// Use any IPv4 permutation of AllowedIPs. The API only sends a hint.
			// IPv6s are firewalled.
			allowed := []string{gw4}
			linkspeed, lerr := strconv.Atoi(group.LinkSpeed)
			out = append(out, &RegionalWgConf{
				CC:               strings.ToUpper(server.CountryCode),
				City:             strings.ToUpper(group.City),
				Name:             servername,
				Load:             int32(group.Health),
				Link:             int32(linkspeed),
				Count:            int32(len(group.Nodes)),
				Premium:          server.PremiumOnly == 1,
				ClientAddr4:      id.Address,
				ClientPrivKey:    id.PrivateKey,
				ClientPubKey:     id.PublicKey,
				ClientDNS4:       dnsaddr,
				PskKey:           id.PresharedKey,
				ServerPubKey:     group.WgPubKey,
				ServerDomainPort: net.JoinHostPort(group.WgEndpoint, portStr),
				ServerIPPort4:    net.JoinHostPort(wsRandomIP3(group.Nodes), portStr),
				AllowedIPs:       allowed,
			})
			if settings.Debug {
				log.VV("ws: wgconfs: gen for %s (%s) [load: %d; link: %s; count: %d]; total for %s: %d; errs? %v",
					group.City, group.Nick, group.Health, group.LinkSpeed, len(group.Nodes), cc, tot[cc], lerr)
			}
		}
	}

	if len(out) <= 0 {
		return nil, errWsBadServerList
	}

	return out, nil
}

func tokenState(t string) (s string) {
	l := strconv.Itoa(len(t))
	if len(t) <= 0 {
		s = "notok-"
	} else if len(strings.Split(t, ":")) > 4 {
		s = "plaintok-" + l
	} else {
		s = "enctok-" + l
	}
	return
}

func (a *WsWgConfig) tokenState() string {
	if a == nil {
		return "no-cfg"
	}
	s1, s2 := "no-ent", "no-sess"
	if ent := a.Entitlement; ent != nil {
		s1 = "ent-" + tokenState(ent.SessionToken)
	}
	if sess := a.Session; sess != nil {
		s2 = "sess-" + tokenState(sess.SessionToken)
	}
	return s1 + " | " + s2
}

func getServerList(h *http.Client, sess *WsSession, ent *WsEntitlement) (*WsServerListResponse, error) {
	if sess == nil || ent == nil {
		return nil, errWsNoSession
	}
	lochash := sess.LocHash
	if len(lochash) <= 0 {
		return nil, errWsNoLocHash
	}
	bearer := sess.SessionToken
	if len(bearer) <= 0 {
		return nil, errWsNoToken
	}
	cid := ent.Cid
	if len(cid) <= 0 {
		return nil, errWsNoCid
	}
	did := ent.Did
	test := ent.TestDomain

	// curl -x GET '.../serverlist/mob-v2/1/<lochash>'
	u := assetsurl(test, cid).JoinPath(wslocpath, lochash)
	locreq, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, log.EE("ws: wgconfs: req err: %v", err)
	}
	didAndDBHeader(locreq, did, ent.DidToken, test)

	if settings.Debug {
		log.V("ws: wgconfs: req: %s tok %s", u.String(), tokenState(bearer))
	}

	locres, err := h.Do(locreq)
	if err != nil || locres == nil {
		return nil, log.EE("ws: wgconfs: res err (nil? %t): %v", locres == nil, err)
	}

	defer core.Close(locres.Body)
	updateDidTokenIfNeeded(ent, locres)
	if locres.StatusCode != http.StatusOK {
		return nil, wsErr(locres, "wgconfs")
	}

	var wsServerList WsServerListResponse

	return wsRes(locres, &wsServerList, "wgconfs")
}

// initAndConnectCreds registers creds via /WgConfigs/init and then either:
//   - dynamic creds (perma=false): reserves a WireGuard interface via /WgConfigs/connect.
//   - perma creds (perma=true, managedPermaCreds=false): registers the init'd pubkey via
//     /WgConfigs/permanent.  The keypair is generated locally; /WgConfigs/init is required.
//   - managed perma creds (perma=true, managedPermaCreds=true): delegates entirely to
//     managedPermaCredsFn; no local key-gen and no /WgConfigs/init call is performed.
//
// For perma=true (non-managed), if existingCreds is non-nil and its pubkey is still present
// in /WgConfigs/list_keys, existingCreds is returned as-is (no /init or /permanent needed).
// If the key is no longer listed, a fresh /init + /permanent cycle is performed.
// The /init error handling is identical for both dynamic and perma paths.
func initAndConnectCreds(h *http.Client, existingCreds *WsWgCreds, perma bool, sess *WsSession, ent *WsEntitlement, forceInit bool) (*WsWgCreds, error) {
	if sess == nil || ent == nil {
		return nil, errWsNoSession
	}
	bearer := sess.SessionToken
	if len(bearer) <= 0 {
		return nil, errWsNoToken
	}
	cid := ent.Cid
	if len(cid) <= 0 {
		return nil, errWsNoCid
	}
	test := ent.TestDomain
	tokst := "sess-" + tokenState(bearer)

	if perma && disablePermaCreds {
		log.W("ws: wgconfs: perma creds disabled; skipping...")
		return nil, nil // perma creds disabled; no API calls, no error
	}

	// Managed perma creds: server generates both priv+pub; no /init call required.
	// list_keys always includes remotely-generated keys, so liveness is cheap to verify.
	if perma && managedPermaCreds {
		return managedPermaCredsFn(h, existingCreds, ent, bearer)
	}

	force := "0" // 0 when forced registration (which deletes older keys) is not needed

	// For perma creds, check whether the existing pubkey is still registered on the server.
	// If found, reuse it directly without any /init or /permanent API call.
	// If not found (key was dropped from the server list), discard the stale creds so the
	// key-gen + /init + /permanent path below produces a fresh registration.
	if perma && existingCreds != nil && len(existingCreds.PublicKey) > 0 {
		var kerr error
		for range 2 {
			var keys *WsWgListKeysResponse
			keys, kerr = listKeys(h, ent, bearer)
			if kerr != nil || keys == nil {
				log.E("ws: wgconfs: perma: list keys err (nil? %t / tok? %s): %v", keys == nil, tokst, kerr)
				wsBriefPauseBeforeRetry()
				continue
			}
			for _, k := range keys.Data.PubKeys {
				if k == existingCreds.PublicKey {
					log.I("ws: wgconfs: perma: existing key %s active (%s); reusing", trunc8(existingCreds.PublicKey), tokst)
					return existingCreds, nil
				}
			}
			if len(keys.Data.PubKeys) >= wsMaxPermaWgKeys {
				force = "1" // does not yet work
			}
			break
		}

		// TODO: creds not generated by the server are not returned by listKeys anyway
		// if kerr != nil {
		// 	return nil, log.EE("ws: wgconfs: perma: failed key verification; err: %v", kerr)
		// }
		// pubkey no longer in list; force a fresh /init so a new keypair is generated.
		// setting forceInit=true makes useExistingCreds=false below, triggering NewWgPrivateKey.
		forceInit = true
	} // fallthrough to WgConfigs/init the credential

	runkey := 0
	runinit := 0
	runconnect := 0
	keyed := 0
keyagain:
	useExistingCreds := existingCreds != nil && keyed == 0 && !forceInit
	runkey += 1

	var priv x.WgKey
	if !useExistingCreds {
		var err error
		priv, err = x.NewWgPrivateKey()
		if err != nil {
			return nil, log.EE("ws: wgconfs: gen key #%d (perma? %t) err: %v", runkey, perma, err)
		}
	} else {
		var err error
		// use the existing key, which is already registered
		priv, err = x.NewWgPrivateKeyOf(existingCreds.PrivateKey)
		if err != nil {
			return nil, log.EE("ws: wgconfs: existing key #%d (perma? %t) err: %v", runkey, perma, err)
		}
	}
	pub := priv.Mult()
	pubkeybase64 := pub.Base64()

	log.I("ws: wgconfs: gen creds: pubkey: %s, existing key #%d? %t; force? %t; perma? %t",
		trunc8(pubkeybase64), runkey, useExistingCreds, forceInit, perma)

initagain:
	keyNeedsInit := !useExistingCreds || force == "1"
	runinit += 1

	details := fmt.Sprintf("pub: %s, keyed#%d? %t; usingExisting#%d? %t; forceinit? %t; perma? %t",
		trunc8(pubkeybase64), runkey, keyNeedsInit, runinit, useExistingCreds, force == "1", perma)

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
		u := baseurl(test, cid).JoinPath(wswginitpath)
		initreq, err := http.NewRequest("POST", u.String(), strings.NewReader(initdata.Encode()))
		if err != nil {
			return nil, log.EE("ws: wgconfs: %s req err: %v", details, err)
		}
		initreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		authHeader(initreq, bearer)
		didAndDBHeader(initreq, ent.Did, ent.DidToken, test)

		if settings.Debug {
			log.V("ws: wgconfs: %s init req: %s; tok %s; force %s", details, u.String(), tokst, force)
		}

		initres, err := h.Do(initreq)

		if err != nil || initres == nil {
			return nil, log.EE("ws: wgconfs: %s res err (nil? %t / tok? %s): %v", details, initres == nil, tokst, err)
		}
		updateDidTokenIfNeeded(ent, initres)

		if initres.StatusCode != http.StatusOK {
			wserr, err := wsErr2(initres, "wsinit")
			core.Close(initres.Body)
			if wserr != nil && wserr.Code == ekeylimit {
				if force != "1" {
					log.I("ws: wgconfs: redo init with force %s; err: %v", details, err)
					force = "1"
					goto initagain
				}
			}
			log.E("ws: wgconfs: init %s; err: %v", details, err)
			return nil, err
		}

		defer core.Close(initres.Body)

		var wgCreds WsWgCredsResponse
		_, err = wsRes(initres, &wgCreds, "wgconfs")
		if err != nil {
			return nil, err
		}

		d := wgCreds.Data
		creds = &d.Config
		if d.Success != 1 {
			return nil, log.EE("ws: wgconfs: %s success != 1; debug: %v", details, d.Debug)
		}
		if len(d.Config.PrivateKey) <= 0 { // private key is generated locally (by the client)
			d.Config.PrivateKey = priv.Base64()
			if len(d.Config.PublicKey) > 0 && d.Config.PublicKey != pubkeybase64 { // registered public key must match the local one
				return nil, log.EE("ws: wgconfs: pubkey mismatch; expected %s, got %s",
					pubkeybase64, d.Config.PublicKey)
			}
			d.Config.PublicKey = pubkeybase64
		} // TODO: else panic?
	} else {
		creds = existingCreds
	}

	if creds == nil || len(creds.PublicKey) <= 0 || len(creds.PrivateKey) <= 0 {
		return nil, log.EE("ws: wgconfs: missing pub/priv creds %s", details)
	}

	log.I("ws: wgconfs: got creds;" + details)

	if perma {
		permaCreds, err := createPermaCreds(h, ent, bearer, pubkeybase64)
		if err != nil || permaCreds == nil {
			return nil, core.OneErr(err, errWsNoPermaCreds)
		}
		// private key is generated locally by the client (not the server)
		permaCreds.PrivateKey = priv.Base64()
		if len(permaCreds.PublicKey) > 0 && permaCreds.PublicKey != pubkeybase64 { // registered public key must match the local one
			return nil, log.EE("ws: wgconfs: perma: pubkey mismatch; expected %s, got %s",
				pubkeybase64, permaCreds.PublicKey)
		}
		permaCreds.PublicKey = pubkeybase64
		return permaCreds, nil
	}

	someEndpoint := fixedValidWsEndpoint(test)

connectagain:
	runconnect += 1
	// github.com/Windscribe/Android-App/blob/746d505dc69/base/src/main/java/com/windscribe/vpn/backend/utils/WindVpnController.kt#L159
	/*
		curl -x POST '.../WgConfigs/connect' \
		--data-urlencode 'hostname=<>' \
		--data-urlencode 'wg_pubkey=stdbase64=='
		--data-urlencode 'wg_ttl=3600'
		-H 'Content-Type: application/x-www-form-urlencoded' \
		-H 'Authorization: Bearer id:typ:epochsec:sig1:sig2'
	*/
	cdata := url.Values{}
	// The "hostname" for WgConfigs/connect call is requested, but currently it
	// does nothing as we never made use of this server side.
	cdata.Set("hostname", someEndpoint)
	cdata.Set("wg_pubkey", pubkeybase64)
	cdata.Set("wg_ttl", wgttl)
	u := baseurl(test, cid).JoinPath(wswgconnectpath)
	creq, err := http.NewRequest("POST", u.String(), strings.NewReader(cdata.Encode()))
	if err != nil {
		return nil, log.EE("ws: wgconfs: %s connect#%d req err: %v", details, runconnect, err)
	}
	creq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	authHeader(creq, sess.SessionToken)
	didAndDBHeader(creq, ent.Did, ent.DidToken, test)

	if settings.Debug {
		log.V("ws: wgconfs: %s connect#%d req: %s tok %s", details, runconnect, u.String(), tokst)
	}

	cres, err := h.Do(creq)
	if err != nil || cres == nil {
		return nil, log.EE("ws: wgconfs: %s connect#%d res err (nil? %t / tok? %s): %v",
			details, runconnect, cres == nil, tokst, err)
	}
	updateDidTokenIfNeeded(ent, cres)
	if cres.StatusCode != http.StatusOK {
		wserr, err := wsErr2(cres, "wsconnect")
		core.Close(cres.Body)
		if wserr != nil && wserr.Code == ekeyinvalid { // the key was deleted!
			if keyed == 0 {
				keyed = 1
				goto keyagain // try again with a non-default key
			}
		} else if wserr != nil && wserr.Code == enoaddr && runconnect < 2 {
			time.Sleep(3 * time.Second) // wait a bit before retrying once
			goto connectagain           // retry connect
		}
		return nil, err
	}

	var wgConnect WsWgConnectResponse
	_, err = wsRes(cres, &wgConnect, "wgconfs")
	defer core.Close(cres.Body)
	if err != nil {
		return nil, log.EE("ws: wgconfs: %s connect#%d res err: %v",
			details, runconnect, err)
	}

	// TODO: goto connectagain if runconnect < 2?
	if wgConnect.Data.Success != 1 {
		return nil, log.EE("ws: wgconfs: %s connect#%d success != 1; debug: %v",
			details, runconnect, wgConnect.Data.Debug)
	}
	// TODO: goto connectagain if runconnect < 2?
	if len(wgConnect.Data.Config.Address) <= 0 || len(wgConnect.Data.Config.DNS) <= 0 {
		return nil, log.EE("ws: wgconfs: %s connect#%d missing config; debug: %v",
			details, runconnect, wgConnect.Data.Debug)
	}

	if len(creds.Address) <= 0 {
		creds.Address = wgConnect.Data.Config.Address
	}
	if len(creds.DNS) <= 0 {
		creds.DNS = wgConnect.Data.Config.DNS
	}

	log.I("ws: wgconfs: got connect data; %s; config addr: %s, dns: %s; perma? %t",
		details, wgConnect.Data.Config.Address, wgConnect.Data.Config.DNS, perma)

	return creds, nil
}

func genWgConfs(h *http.Client, existingCreds *WsWgCreds, existingPermaCreds *WsWgPermanentConfig, sess *WsSession, servers []WsServerList, ent *WsEntitlement, ops x.RpnOps) (*WsWgCreds, *WsWgPermanentConfig, []*RegionalWgConf, error) {
	if sess == nil || ent == nil {
		return nil, nil, nil, errWsNoSession
	}
	forceInit := ops.Rotate()
	port := ""
	if ops.Port() > 0 {
		port = strconv.FormatUint(uint64(ops.Port()), 10)
	}
	if len(sess.LocHash) <= 0 {
		return nil, nil, nil, errWsNoLocHash
	}
	bearer := sess.SessionToken
	if len(bearer) <= 0 {
		return nil, nil, nil, errWsNoToken
	}
	if len(ent.Cid) <= 0 {
		return nil, nil, nil, errWsNoCid
	}
	test := ent.TestDomain
	tokst := "sess-" + tokenState(bearer)

	creds, err := initAndConnectCreds(h, existingCreds, false /*dynamic*/, sess, ent, forceInit)
	if err != nil || creds == nil {
		return nil, nil, nil, core.OneErr(err, errWsNoConfig)
	}

	// TODO: if wgConnectData.Config.Address has not changed and existingCreds is non-nil,
	// then we do not have to generate regional configs again (unless location hash has changed).
	regconfs, err := convertToRegionalWgConfs(creds, servers, test, port)
	if err != nil || len(regconfs) <= 0 {
		return nil, nil, nil, log.EE("ws: wgconfs: (test? %t / tok? %s) no regions found: %v", test, tokst, err)
	}

	// attempt to generate or reuse a permanent WG config (best-effort; non-fatal)
	var permaCreds *WsWgPermanentConfig
	if !disablePermaCreds {
		var permaErr error
		permaCreds, permaErr = initAndConnectCreds(h, existingPermaCreds /*may be nil*/, true /*perma*/, sess, ent, false /*forceInit is not useful for perma*/)
		if permaErr != nil || permaCreds == nil {
			log.W("ws: wgconfs: permacreds err (ops: %v): %v", &ops, permaErr)
			permaCreds = existingPermaCreds // keep existing on error
		}
	}

	log.I("ws: wgconfs: ok (test? %t / tok? %s) found %d regions", test, tokst, len(regconfs))

	return creds, permaCreds, regconfs, nil
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
	if len(s) <= 3 {
		return s
	}
	if len(s) <= 8 {
		return s[:3]
	}
	if len(s) <= 16 {
		return s[:2] + ".." + s[len(s)-2:]
	}
	return s[:4] + ".." + s[len(s)-4:]
}

func newWsGw(c *WsWgConfig, h *http.Client, o x.RpnOps) (*WsClient, error) {
	if h == nil || c == nil || c.Session == nil || c.Creds == nil {
		return nil, errWsBadGatewayArgs
	}
	a := &WsClient{
		http:                h,
		ops:                 core.NewVolatile(o),
		configExt:           core.NewVolatile(c),
		configExtUpdateTime: core.NewVolatile(time.Now()),
	}

	log.I("ws: gw: for %s/%s; ops: %s; from: %s until: %s",
		a.Who(), c.tokenState(), a.Ops(), fmtUnixMillis(a.Created()), fmtUnixMillis(a.Expires()))

	return a, nil
}

// overrideDid assigns did to ent.Did. If ent.Did is already set and does not match
// the incoming did, errWsDidMismatch is returned and ent is left unchanged.
func overrideDid(ent *WsEntitlement, did string) error {
	if !ent.ok() {
		return errWsBadEntitlement
	}
	if existing := ent.Did; len(existing) > 0 && existing != did {
		log.W("ws: did overriden: existing %s, incoming %s", trunc8(existing), trunc8(did))
	}
	ent.Did = did
	return nil
}

func (w *BaseClient) MakeWsWg(entitlement []byte, did string, ops x.RpnOps) (*WsClient, error) {
	if len(entitlement) <= 0 {
		return nil, errWsNoEntitlement
	}
	if len(did) <= 0 {
		return nil, errWsNoDid
	}

	var ent WsEntitlement
	err := json.Unmarshal(entitlement, &ent)
	if err != nil {
		return nil, err
	}
	if !ent.ok() {
		return nil, errWsBadEntitlement
	}

	// TODO: if ent already has did set; then err on mismatch?
	if err := overrideDid(&ent, did); err != nil {
		return nil, err
	}
	return makeWsWg(&w.h2, &ent, ops)
}

func makeWsWg(h *http.Client, ent *WsEntitlement, ops x.RpnOps) (*WsClient, error) {
	if !ent.ok() {
		log.E("ws: makeWsWg: entitlement is nil")
		return nil, errWsBadEntitlement
	}

	sess, err := getSession(h, ent)
	if err != nil {
		return nil, err
	}

	servers, err := getServerList(h, sess, ent)
	if err != nil {
		return nil, err
	}

	creds, permaCreds, wgconfs, err := genWgConfs(h, nil, nil, sess, servers.Data, ent, ops)
	if err != nil {
		return nil, err
	}

	cfg := &WsWgConfig{
		Entitlement: ent,
		Session:     sess,
		Configs:     wgconfs,
		Servers:     servers.Data,
		Creds:       creds,
		PermaCreds:  permaCreds, // may be nil
	}

	return newWsGw(cfg, h, ops)
}

func (w *BaseClient) MakeWsEntitlement(entitlementOrStateJson []byte, did string) (x.RpnEntitlement, error) {
	if len(entitlementOrStateJson) <= 0 {
		return nil, errWsNoEntitlement
	}
	if len(did) <= 0 {
		return nil, errWsNoDid
	}

	var ent WsEntitlement
	err1 := json.Unmarshal(entitlementOrStateJson, &ent)
	if err1 == nil && ent.ok() {
		if err := overrideDid(&ent, did); err != nil {
			return nil, err
		}
		return &ent, nil
	}
	var existingConf WsWgConfig
	err2 := json.Unmarshal(entitlementOrStateJson, &existingConf)
	if err2 == nil && existingConf.Entitlement.ok() {
		ent := existingConf.Entitlement
		if err := overrideDid(ent, did); err != nil {
			return nil, err
		}
		return ent, nil
	}
	return nil, core.OneErr(core.JoinErr(err1, err2), errWsBadEntitlement)
}

func (w *BaseClient) MakeWsWgFrom(entitlementOrWsConfigJson []byte, did string, ops x.RpnOps) (*WsClient, error) {
	if len(entitlementOrWsConfigJson) <= 0 {
		return nil, errWsNoJsonConfig
	}
	if len(did) <= 0 {
		return nil, errWsNoDid
	}

	var existingConf WsWgConfig
	err := json.Unmarshal(entitlementOrWsConfigJson, &existingConf)

	sz := len(entitlementOrWsConfigJson)
	hasEnt := existingConf.Entitlement.ok()
	if err != nil || !hasEnt {
		// may be this is an entitlement and not conf?
		log.W("ws: make: unmarshal config (sz %d / hasEnt %t) err? %v; retry as entitlement",
			sz, hasEnt, err)
		return w.MakeWsWg(entitlementOrWsConfigJson, did, ops)
	}
	if err := overrideDid(existingConf.Entitlement, did); err != nil {
		return nil, err
	}
	return w.makeWsWgFrom(&existingConf, ops)
}

func (w *BaseClient) makeWsWgFrom(existingConf *WsWgConfig, ops x.RpnOps) (*WsClient, error) {
	ws, _, _, err := makeWsWgFrom(&w.h2, existingConf, ops, false /*not updating*/, false /*field 'mustRedo' inconsequential*/)
	return ws, err
}

func makeWsWgFrom(h *http.Client, existingConf *WsWgConfig, ops x.RpnOps, updating, mustRedo bool) (ws *WsClient, refreshedSess, needsRedo bool, err error) {
	existingEnt := existingConf.Entitlement
	if !existingEnt.ok() {
		err = errWsBadEntitlement
		return
	}

	performingUpdate := updating
	// performingUpdate is set for "Update" calls only; that is, when remote api call fails to
	// either init or init+connect, we can safely errors out on the "Update";
	force := ops.ForceInit()

	var errs []error // accumulate non-fatal errors throughout

	existingSess := existingConf.Session
	existingCreds := existingConf.Creds
	noExistingCreds := existingCreds == nil
	noExistingSess := existingSess == nil || len(existingSess.SessionToken) <= 0
	if noExistingCreds || noExistingSess {
		log.W("ws: make: no existing creds? %t; no existing sess? %t; getting new ws wg", noExistingCreds, noExistingSess)
		ws, err = makeWsWg(h, existingEnt, ops)
		refreshedSess = true
		return
	}

	tokst := existingConf.tokenState()
	existingToken := existingSess.SessionToken
	existingLocHash := existingSess.LocHash
	if existingEnt.SessionToken != existingToken {
		log.W("ws: make: entitlement does not match session; tok? %s", tokst)
	}

	usingExitingSess := false

	var newSess *WsSession
	notold := !existingConf.LastUpdate.IsZero() &&
		time.Since(existingConf.LastUpdate) < wsUpdateThreshold

	if settings.Debug {
		log.D("ws: make: force? %t / old? %t (from: %s); tok? %s", !force, notold, fmtTime(existingConf.LastUpdate), tokst)
	}
	if !force && notold {
		newSess = existingConf.Session
		usingExitingSess = true
		refreshedSess = true // treated as refreshed even though we skipped the network call
	} else {
		var sessErr error
		newSess, sessErr = getSession(h, existingEnt)
		if sessErr == nil {
			existingConf.Session = newSess // update session with the latest info
			existingConf.LastUpdate = time.Now()
			refreshedSess = true
		} else {
			usingExitingSess = true
			log.W("ws: make: get session err: %v; using existing; tok? %s", sessErr, tokst)
			newSess = existingConf.Session // use existing session
			errs = append(errs, sessErr)
		}
	}

	exp, err := time.Parse(time.DateOnly, newSess.ExpiryDate)
	if err != nil {
		err = log.EE("ws: make: parsing expiry %s (newSess? %t / skipSess? %t); err: %v", newSess.ExpiryDate, !usingExitingSess, notold, err)
		err = core.JoinInto(errs, err)
		return
	}

	active := exp.After(time.Now())
	existingServers := existingConf.Servers
	// skip server refresh if ops requests it; but honour loc hash change regardless
	downloadServerList := (existingLocHash != newSess.LocHash) || ops.FetchServers()
	if active {
		// sync Robert DNS filters with the desired preset configuration (best-effort; non-fatal).
		if dnsConfig := ops.DNSConfig(); len(dnsConfig) > 0 {
			go syncDNSFilters(h, existingEnt, newSess, dnsConfig)
		} // else: no-op

		maybeNewServers := existingServers
		oldlen := len(existingServers)
		newlen := -1
		if downloadServerList {
			newServersRes, err := getServerList(h, newSess, existingEnt)

			if newServersRes != nil {
				newlen = len(newServersRes.Data)
				if newlen > 0 {
					maybeNewServers = newServersRes.Data
				}
			}

			loge(err)("ws: make: lochash changed %s != %s / len(%d / %d); fetch err? %v",
				existingLocHash, newSess.LocHash, oldlen, newlen, err)

			if newlen <= 0 && oldlen <= 0 { // no new servers, no existing servers; bail
				return nil, refreshedSess, needsRedo, core.JoinInto(errs, core.OneErr(err, errWsNoServerList))
			}
		}

		skipGen := !force && newlen <= 0 && notold
		if !mustRedo && skipGen {
			log.D("ws: make: skip gen (use existing servers and creds); tok? %s", tokst)
		} else {
			maybeNewCreds, maybeNewPermaCreds, maybeNewWgConfs, uerr := genWgConfs(h, existingCreds, existingConf.PermaCreds, newSess, maybeNewServers, existingConf.Entitlement, ops)
			loge(uerr)("ws: make: gen wg confs; tok? %s; mustgen? %t / downloadloc? %t / hasnewloc? %t len (%d/%d); ops: %v; err? %v",
				tokst, mustRedo, downloadServerList, newlen > 0, len(existingServers), len(maybeNewServers), &ops, uerr)

			if uerr == nil {
				// TODO: needsRedo must be set iff creds and/or serverlist has changed
				needsRedo = true
				existingConf.Servers = maybeNewServers
				existingConf.Configs = maybeNewWgConfs
				existingConf.Creds = maybeNewCreds
				existingConf.PermaCreds = maybeNewPermaCreds // may be nil
			} else if performingUpdate || mustRedo {
				// error out early as this was meant to create an update config for later use
				// but it itself is not the currently active config aka "existingConf"
				return nil, refreshedSess, needsRedo, core.JoinInto(errs, uerr)
			} else {
				errs = append(errs, uerr)
			} // use existingConf if gen failed, as it is better than nothing
		}
	} else {
		log.W("ws: make: session expired at %s (mustGen? %t / newSess? %t); tok? %s", fmtTime(exp), mustRedo, !usingExitingSess, tokst)
	}

	ws, err = newWsGw(existingConf, h, ops)
	if err != nil {
		err = core.JoinInto(errs, err)
	}
	return
}

// listKeys calls GET WgConfigs/list_keys and returns the parsed response.
func listKeys(h *http.Client, ent *WsEntitlement, bearer string) (*WsWgListKeysResponse, error) {
	if len(bearer) <= 0 {
		return nil, errWsNoToken
	}
	tokst := tokenState(bearer)
	// curl --location --request GET '.../WgConfigs/list_keys' \
	// --header 'Authorization: Bearer <token>'
	u := baseurl(ent.TestDomain, ent.Cid).JoinPath(wswglistkeyspath)
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, log.EE("ws: listkeys: req err: %v", err)
	}
	authHeader(req, bearer)
	didAndDBHeader(req, ent.Did, ent.DidToken, ent.TestDomain)

	if settings.Debug {
		log.V("ws: listkeys: req: %s tok %s", u.String(), tokst)
	}

	res, err := h.Do(req)
	if err != nil || res == nil {
		return nil, log.EE("ws: listkeys: do err (nil? %t / tok? %s): %v", res == nil, tokst, err)
	}
	defer core.Close(res.Body)
	updateDidTokenIfNeeded(ent, res)
	if res.StatusCode != http.StatusOK {
		return nil, wsErr(res, "listkeys/"+tokst)
	}

	var out WsWgListKeysResponse
	_, err = wsRes(res, &out, "listkeys/"+tokst)
	if err != nil {
		return nil, err
	}
	pubkeys := core.Map(out.Data.PubKeys, func(pub string) string { return trunc8(pub) })
	log.I("ws: listkeys: ok (tok? %s); %d keys: %v", tokst, len(out.Data.PubKeys), pubkeys)
	return &out, nil
}

// getDNSFilters returns the current DNS filter list.
func getDNSFilters(h *http.Client, ent *WsEntitlement, bearer string) ([]WsFilter, error) {
	if len(bearer) <= 0 {
		return nil, errWsNoToken
	}
	tokst := tokenState(bearer)
	u := baseurl(ent.TestDomain, ent.Cid).JoinPath(wsgetfilterspath)
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, log.EE("ws: getfilters: req err: %v", err)
	}
	authHeader(req, bearer)
	didAndDBHeader(req, ent.Did, ent.DidToken, ent.TestDomain)

	if settings.Debug {
		log.V("ws: getfilters: req: %s tok %s", u.String(), tokst)
	}

	res, err := h.Do(req)
	if err != nil || res == nil {
		return nil, log.EE("ws: getfilters: do err (nil? %t / tok? %s): %v", res == nil, tokst, err)
	}
	defer core.Close(res.Body)
	updateDidTokenIfNeeded(ent, res)
	if res.StatusCode != http.StatusOK {
		return nil, wsErr(res, "getrob/"+tokst)
	}

	var out WsFiltersResponse
	if _, err = wsRes(res, &out, "getrob/"+tokst); err != nil {
		return nil, err
	}
	if len(out.Data.Filters) <= 0 {
		return nil, log.EE("ws: getfilters: %v; tok? %s", errWsNoFilters, tokst)
	}
	log.I("ws: getfilters: ok (tok? %s); %d filters", tokst, len(out.Data.Filters))
	return out.Data.Filters, nil
}

// setDNSFilter enables or disables on a DNS filterID.
func setDNSFilter(h *http.Client, ent *WsEntitlement, bearer, filterID string, enable bool) error {
	if len(bearer) <= 0 {
		return errWsNoToken
	}
	status := 0
	if enable {
		status = 1
	}
	tokst := tokenState(bearer)
	body, err := json.Marshal(WsFilterSetRequest{Filter: filterID, Status: status})
	if err != nil {
		return log.EE("ws: setfilter: marshal err: %v", err)
	}

	u := baseurl(ent.TestDomain, ent.Cid).JoinPath(wssetfilterpath)
	req, err := http.NewRequest("PUT", u.String(), strings.NewReader(string(body)))
	if err != nil {
		return log.EE("ws: setfilter: req err: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	authHeader(req, bearer)
	didAndDBHeader(req, ent.Did, ent.DidToken, ent.TestDomain)

	if settings.Debug {
		log.V("ws: setfilter: %s status=%d req: %s tok %s", filterID, status, u.String(), tokst)
	}

	res, err := h.Do(req)
	if err != nil || res == nil {
		return log.EE("ws: setfilter: do err (nil? %t / tok? %s): %v", res == nil, tokst, err)
	}
	defer core.Close(res.Body)
	updateDidTokenIfNeeded(ent, res)
	if res.StatusCode != http.StatusOK {
		return wsErr(res, "setrob("+filterID+")/"+tokst)
	}

	var out WsFilterSetResponse
	if _, err = wsRes(res, &out, "setrob("+filterID+")/"+tokst); err != nil {
		return err
	}
	if out.Data.Success != 1 {
		return log.EE("ws: setfilter: %s status=%d success!=1; tok? %s", filterID, status, tokst)
	}
	log.I("ws: setfilter: ok %s status=%d (tok? %s)", filterID, status, tokst)
	return nil
}

// syncDNSFilters reconciles the Robert DNS filters on the server with the desired state
// derived from dnsConfig (a csv of presets such as "family,privacy").
// It fetches the current filter states once, then issues one PUT per filter that
// needs to change. The call is a no-op when dnsConfig is empty.
func syncDNSFilters(h *http.Client, ent *WsEntitlement, sess *WsSession, dnsConfig string) error {
	if len(dnsConfig) <= 0 {
		return nil
	}
	if sess == nil || ent == nil {
		return errWsNoSession
	}
	bearer := sess.SessionToken
	if len(bearer) <= 0 {
		return errWsNoToken
	}

	desired := dnsConfigToFilters(dnsConfig)

	all, err := getDNSFilters(h, ent, bearer)
	if err != nil {
		return err
	}

	if settings.Debug {
		log.D("ws: syncfilters: desired: %s => %v; all: %d", dnsConfig, desired, len(all))
	}

	errs := make([]error, 0)
	for _, f := range all {
		wantEnabled := desired[f.ID]
		isEnabled := f.Status == 1
		if wantEnabled == isEnabled {
			continue // already in the desired state
		}
		if serr := setDNSFilter(h, ent, bearer, f.ID, wantEnabled); serr != nil {
			errs = append(errs, fmt.Errorf("ws: syncfilters: %s => %t; err: %v", f.ID, wantEnabled, serr))
		} else {
			log.I("ws: syncfilters: %s => %t (tok? %s)", f.ID, wantEnabled, tokenState(bearer))
		}
	}
	return core.JoinErr(errs...)
}

// managedPermaCredsFn implements the managed-perma-creds flow (managedPermaCreds=true).
// The server generates both the private and public key; no /WgConfigs/init is needed.
// If existingCreds are still present in /WgConfigs/list_keys they are reused directly.
// Otherwise /WgConfigs/permanent is called without a pubkey so the server creates a fresh
// keypair. Remotely-generated keypairs are always included in subsequent list_keys responses.
func managedPermaCredsFn(h *http.Client, existingCreds *WsWgPermanentConfig, ent *WsEntitlement, bearer string) (*WsWgPermanentConfig, error) {
	if len(bearer) <= 0 {
		return nil, errWsNoToken
	}
	tokst := tokenState(bearer)

	// If we already have remotely-generated creds, verify they are still active.
	if existingCreds != nil && len(existingCreds.PublicKey) > 0 {
		for range 2 {
			keys, kerr := listKeys(h, ent, bearer)
			if kerr != nil || keys == nil {
				log.E("ws: wgconfs: perma(managed): list keys err (nil? %t / tok? %s): %v", keys == nil, tokst, kerr)
				wsBriefPauseBeforeRetry()
				continue
			}
			for _, k := range keys.Data.PubKeys {
				if k == existingCreds.PublicKey {
					log.I("ws: wgconfs: perma(managed): existing key %s active (%s); reusing", trunc8(existingCreds.PublicKey), tokst)
					return existingCreds, nil
				}
			}
			// key not found in list; fall through to generate a new remote keypair
			log.I("ws: wgconfs: perma(managed): existing key %s missing from list_keys (%s); regenerating", trunc8(existingCreds.PublicKey), tokst)
			break
		}
	}

	// Let the server generate both the private and public keys.
	// No pubkey is supplied; the returned creds include PrivateKey from the server.
	return createPermaCreds(h, ent, bearer, "" /*no pubkey: server generates keypair*/)
}

// createPermaCreds calls POST WgConfigs/permanent to create a permanent WG config.
// If pubkey is empty the server generates both the private and public keys.
func createPermaCreds(h *http.Client, ent *WsEntitlement, bearer, pubkey string) (*WsWgPermanentConfig, error) {
	if len(bearer) <= 0 {
		return nil, errWsNoToken
	}
	port := wsRandomPort() // some port; doesn't matter which one
	tokst := tokenState(bearer)
	managed := len(pubkey) <= 0
	// curl --location --request POST '.../WgConfigs/permanent' \
	// --header 'Authorization: Bearer <token>' \
	// --data-urlencode 'port=443' \
	// --data-urlencode 'wg_pubkey=...' (optional)
	data := url.Values{}
	data.Set("port", port)
	if len(pubkey) > 0 { // creds vended by the server
		data.Set("wg_pubkey", pubkey)
	}

	u := baseurl(ent.TestDomain, ent.Cid).JoinPath(wswgpermanentpath)
	req, err := http.NewRequest("POST", u.String(), strings.NewReader(data.Encode()))
	if err != nil {
		return nil, log.EE("ws: conf: perma: (m? %t) req err: %v", managed, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	authHeader(req, bearer)
	didAndDBHeader(req, ent.Did, ent.DidToken, ent.TestDomain)

	if settings.Debug {
		log.V("ws: conf: perma: (m? %t) req: %s tok %s; port %s", managed, u.String(), tokst, port)
	}

	res, err := h.Do(req)
	if err != nil || res == nil {
		return nil, log.EE("ws: conf: perma: (m? %t) do err (nil? %t / tok? %s): %v", managed, res == nil, tokst, err)
	}
	defer core.Close(res.Body)
	updateDidTokenIfNeeded(ent, res)
	if res.StatusCode != http.StatusOK {
		return nil, wsErr(res, "confperma/"+tokst)
	}

	var out WsWgCredsResponse
	_, err = wsRes(res, &out, "confperma/"+tokst)
	if err != nil {
		return nil, err
	}
	if out.Data.Success != 1 {
		return nil, log.EE("ws: conf: perma: (m? %t) success != 1; tok? %s; debug: %v", managed, tokst, out.Data.Debug)
	}

	cfg := out.Data.Config
	log.I("ws: conf: perma: ok (m? %t / tok? %s); pubkey: %s", managed, tokst, trunc8(cfg.PublicKey))
	return &cfg, nil
}

// ccCsvAsSet mods a csv of country codes into a set.
func ccCsvAsSet(csv string) map[string]struct{} {
	if len(csv) <= 0 {
		return nil
	}
	parts := strings.Split(csv, ",")
	out := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		p = strings.ToUpper(strings.TrimSpace(p))
		if len(p) > 0 {
			out[p] = struct{}{}
		}
	}
	return out
}

func wsBriefPauseBeforeRetry() {
	time.Sleep(2200 * time.Millisecond)
}

func loge(err error) log.LogFn {
	if err == nil {
		return log.I
	}
	return log.E
}

func logew(cond bool) log.LogFn {
	if cond {
		return log.E
	}
	return log.W
}

func sha(p string) []byte {
	return shab([]byte(p))
}

func shab(b []byte) []byte {
	digest := sha256.Sum256(b)
	return digest[:]
}

func byte2hex(b []byte) string {
	return hex.EncodeToString(b)
}

func truncate2k(b []byte) []byte {
	if len(b) <= 2048 {
		return b
	}
	return b[:2048]
}
