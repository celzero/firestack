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
)

// github.com/Windscribe/Android-App/blob/746d505dc69/base/src/main/java/com/windscribe/vpn/constants/NetworkErrorCodes.kt
const (
	ekeylimit   = 1313
	ekeyinvalid = 1311
)

const (
	confKeySep = ";"

	// onlyPremiumServers removes non-premium servers from the server list,
	// which may reduce its count substantially.
	onlyPremiumServers = false
)

// github.com/Windscribe/Android-App/blob/746d505dc69/base/src/main/res/raw/port_map.txt#L76
var wswgports = []string{ /*0th & 1st pos must always be 443, 80; see wsRandomPort */ "443", "53", "80", "123", "1194", "65142"}

var (
	errWsBadGatewayArgs = errors.New("ws: cannot make gw; missing args")
	errWsNoConfig       = errors.New("ws: no config")
	errWsNoJsonConfig   = errors.New("ws: no json config")
	errWsNoSession      = errors.New("ws: no session info")
	errWsNoClient       = errors.New("ws: no client")
	errWsNoEntitlement  = errors.New("ws: missing entitlement")
	errWsNoToken        = errors.New("ws: missing token")
	errWsNoCid          = errors.New("ws: missing cid")
	errWsNoDid          = errors.New("ws: missing device id")
	errWsNoResponse     = errors.New("ws: no response")
	errWsNoLocHash      = errors.New("ws: no loc hash")
	errWsNoServerList   = errors.New("ws: no server list")
	errWsBadServerList  = errors.New("ws: invalid server list")
	errWsRetryUpdate    = errors.New("ws: retry update")
	errWsNoCcConfig     = errors.New("ws: not available in that location")
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
	// Expiry date of the entitlement; go.dev/play/p/d2gshytEF61
	Exp              time.Time `json:"expiry"`
	AccStatus        string    `json:"status"`       // "valid" | "invalid" | "banned" | "expired" | "unknown"
	AllowCrossDevice bool      `json:"allowRestore"` // true if this entitlement can be restored
	TestDomain       bool      `json:"test"`         // true if this is a test entitlement
}

var _ x.RpnAcc = (*WsClient)(nil)
var _ x.RpnEntitlement = (*WsEntitlement)(nil)

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
	if e == nil {
		return nil, errWsNoEntitlement
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
		return ""
	}
	c := a.config()
	if c == nil || c.Session == nil {
		return ""
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
			s = append(s, x.RpnServer{
				CC:      rc.CC,
				City:    rc.City,
				Name:    rc.Name,
				Load:    rc.Load,
				Link:    rc.Link,
				Count:   rc.Count,
				Premium: rc.Premium,
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
func (a *WsClient) Update() (newstate []byte, err error) {
	if a == nil {
		return nil, errWsNoClient
	}
	c := a.config()
	if c == nil {
		return nil, errWsNoConfig
	}
	b, refreshed, err := makeWsWgFrom(a.http, c, true /*err on no update*/)
	if err != nil || !refreshed {
		log.E("ws: update: refreshed? %t; err: %v", refreshed, err)
		return nil, core.OneErr(err, errWsRetryUpdate)
	}

	// If configs have changed, the current proxies using those, if any,
	// will need to be updated.
	if _, err := a.shallowCopyConfig(b); err != nil {
		log.E("ws: update: shallow copy err: %v", err)
		return nil, err
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
	return true, nil
}

// Conf implements RpnAcc.
func (a *WsClient) Conf(cc string) (string, error) {
	cfg := a.config()
	if cfg == nil {
		return "", errWsNoConfig
	}
	city := ""
	if cccsv := strings.Split(cc, confKeySep); len(cccsv) >= 2 {
		city = cccsv[0]
		cc = cccsv[1]
	}
	visited := make(map[string]struct{}, 0)
	// in sync with anyCountryCode / noCountryForOldMen vars in proxy.go
	chooseAny := cc == "**" || len(cc) <= 0
	hasCity := len(city) > 0
	tot := 0
	c := 0
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
				if c > 2 {
					// choose only low load and high link speed servers
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

			if rc.genUapiConfigIfNeeded() {
				out = append(out, rc.UapiWgConf)
				ids = append(ids, strings.Join([]string{rc.CC, rc.City, rc.Name}, "/"))
				c++
			}
		}
		tot++
	}
	if len(out) > 0 {
		r := rand.IntN(len(out))
		log.I("ws: conf: cc %s(%s): %d/%d => chosen (any? %t): %d[%s]", cc, city, c, len(out), chooseAny, r, ids[r])
		return out[r], nil
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

func baseurl(test bool, cid, did string) *url.URL {
	u := url.URL{
		Scheme: "https",
		Host:   svchosttest,
	}
	q := u.Query()
	q.Set("cid", cid)
	q.Set("did", did)
	if test {
		q.Set("rpn", "wstest")
	} else {
		q.Set("rpn", "ws")
	}
	u.RawQuery = q.Encode()

	return &u
}

func assetsurl(test bool) *url.URL {
	u := url.URL{
		Scheme: "https",
		Host:   svchosttest,
	}
	q := u.Query()
	if test {
		q.Set("rpn", "wsassetstest")
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

func getSession(h *http.Client, cid, did, tok string, test bool) (*WsSession, error) {
	if len(tok) <= 0 {
		return nil, errWsNoToken
	}
	tokst := tokenState(tok)
	/*
		curl -x GET '.../Session'
		-H 'Authorization: Bearer id:typ:epochsec:sig1:sig2'
	*/
	u := baseurl(test, cid, did).JoinPath(wssessionpath)
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, log.EE("ws: getsess: make req err: %v", err)
	}
	authHeader(req, tok)

	if settings.Debug {
		log.V("ws: getsess: req: %s tok %s", u.String(), tokst)
	}

	res, err := h.Do(req)
	if err != nil || res == nil {
		return nil, log.EE("ws: getsess: res err (nil? %t / tok? %s): %v", res == nil, tokst, err)
	}
	defer core.Close(res.Body)
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

// TODO: For now, hardcode to use 443 (at pos 0) or 53 (at pos 1) as it has better "anti-censorship" property.
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

func convertToRegionalWgConfs(id *WsWgCreds, reservation *WsWgConnectData, list []WsServerList, test bool) ([]*RegionalWgConf, error) {
	if id == nil || reservation == nil || len(list) <= 0 {
		return nil, fmt.Errorf("regional configs err: creds? %t; res? %t; servers? %d",
			id != nil, reservation != nil, len(list))
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
		port := wsRandomPort()
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
			dnsaddr := reservation.Config.DNS
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
				ClientAddr4:      reservation.Config.Address,
				ClientPrivKey:    id.PrivateKey,
				ClientPubKey:     id.PublicKey,
				ClientDNS4:       dnsaddr,
				PskKey:           id.PresharedKey,
				ServerPubKey:     group.WgPubKey,
				ServerDomainPort: net.JoinHostPort(group.WgEndpoint, port),
				ServerIPPort4:    net.JoinHostPort(wsRandomIP3(group.Nodes), port),
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
	test := ent.TestDomain

	// curl -x GET '.../serverlist/mob-v2/1/<lochash>'
	u := assetsurl(test).JoinPath(wslocpath, lochash)
	locreq, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, log.EE("ws: wgconfs: req err: %v", err)
	}

	if settings.Debug {
		log.V("ws: wgconfs: req: %s tok %s", u.String(), tokenState(bearer))
	}

	locres, err := h.Do(locreq)
	if err != nil || locres == nil {
		return nil, log.EE("ws: wgconfs: res err (nil? %t): %v", locres == nil, err)
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
		return nil, nil, errWsNoSession
	}
	lochash := sess.LocHash
	if len(lochash) <= 0 {
		return nil, nil, errWsNoLocHash
	}
	bearer := sess.SessionToken
	if len(bearer) <= 0 {
		return nil, nil, errWsNoToken
	}
	cid := ent.Cid
	if len(cid) <= 0 {
		return nil, nil, errWsNoCid
	}
	test := ent.TestDomain

	tokst := "sess-" + tokenState(bearer)

	keyed := 0
keyagain:
	useExistingCreds := existingCreds != nil && keyed == 0

	var priv x.WgKey
	if !useExistingCreds {
		var err error
		priv, err = x.NewWgPrivateKey()
		if err != nil {
			return nil, nil, log.EE("ws: wgconfs: gen key err: %v", err)
		}
	} else {
		var err error
		// use the existing key, which is already registered
		priv, err = x.NewWgPrivateKeyOf(existingCreds.PrivateKey)
		if err != nil {
			return nil, nil, log.EE("ws: wgconfs: existing key err: %v", err)
		}
	}
	pub := priv.Mult()
	pubkeybase64 := pub.Base64()

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
		u := baseurl(test, cid, ent.Did).JoinPath(wswginitpath)
		initreq, err := http.NewRequest("POST", u.String(), strings.NewReader(initdata.Encode()))
		if err != nil {
			return nil, nil, log.EE("ws: wgconfs: req err: %v", err)
		}
		initreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		authHeader(initreq, bearer)

		if settings.Debug {
			log.V("ws: wgconfs: init req: %s; tok %s; force %s", u.String(), tokst, force)
		}

		initres, err := h.Do(initreq)

		if err != nil || initres == nil {
			return nil, nil, log.EE("ws: wgconfs: res err (nil? %t / tok? %s): %v", initres == nil, tokst, err)
		}

		if initres.StatusCode != http.StatusOK {
			wserr, err := wsErr2(initres, "wsinit")
			core.Close(initres.Body)
			if wserr != nil && wserr.Code == ekeylimit {
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
			return nil, nil, log.EE("ws: wgconfs: success != 1; debug: %v", d.Debug)
		}
		if len(d.Config.PrivateKey) <= 0 { // private key is generated locally (by the client)
			d.Config.PrivateKey = priv.Base64()
			if len(d.Config.PublicKey) > 0 && d.Config.PublicKey != pubkeybase64 { // registered public key must match the local one
				return nil, nil, log.EE("ws: wgconfs: pubkey mismatch; expected %s, got %s",
					pubkeybase64, d.Config.PublicKey)
			}
			d.Config.PublicKey = pubkeybase64
		} // TODO: else panic?
	} else {
		creds = existingCreds
	}

	if creds == nil || len(creds.PublicKey) <= 0 || len(creds.PrivateKey) <= 0 {
		return nil, nil, log.EE("ws: wgconfs: missing pub/priv creds for %s, useExisting? %t", trunc8(pubkeybase64), useExistingCreds)
	}

	log.I("ws: wgconfs: got creds for %s, usingExisting? %t", trunc8(pubkeybase64), useExistingCreds)

	someEndpoint := fixedValidWsEndpoint(test)
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
	u := baseurl(test, cid, ent.Did).JoinPath(wswgconnectpath)
	creq, err := http.NewRequest("POST", u.String(), strings.NewReader(cdata.Encode()))
	if err != nil {
		return nil, nil, log.EE("ws: wgconfs: connect req err: %v", err)
	}
	creq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	authHeader(creq, sess.SessionToken)

	if settings.Debug {
		log.V("ws: wgconfs: connect req: %s tok %s", u.String(), tokst)
	}

	cres, err := h.Do(creq)
	if err != nil || cres == nil {
		return nil, nil, log.EE("ws: wgconfs: connect res err (nil? %t / tok? %s): %v", cres == nil, tokst, err)
	}
	if cres.StatusCode != http.StatusOK {
		wserr, err := wsErr2(cres, "wsconnect")
		core.Close(cres.Body)
		if wserr != nil && wserr.Code == ekeyinvalid { // the key was deleted!
			if keyed == 0 {
				keyed = 1
				goto keyagain // try again with a non-default key
			}
		}
		return nil, nil, err
	}

	var wgConnect WsWgConnectResponse
	_, err = wsRes(cres, &wgConnect, "wgconfs")
	defer core.Close(cres.Body)
	if err != nil {
		return nil, nil, log.EE("ws: wgconfs: connect res err: %v", err)
	}

	if wgConnect.Data.Success != 1 {
		return nil, nil, log.EE("ws: wgconfs: connect success != 1; debug: %v", wgConnect.Data.Debug)
	}

	if len(wgConnect.Data.Config.Address) <= 0 || len(wgConnect.Data.Config.DNS) <= 0 {
		return nil, nil, log.EE("ws: wgconfs: connect missing config; debug: %v", wgConnect.Data.Debug)
	}

	// TODO: if wgconnect.Data.Config.Address has not changed and useExistingCreds is true,
	// then we do not have to generate regional configs again (unless location hash has changed).
	regconfs, err := convertToRegionalWgConfs(creds, &wgConnect.Data, servers, test)

	if err != nil || len(regconfs) <= 0 {
		return nil, nil, log.EE("ws: wgconfs: (test? %t) no regions found for %s; %v", test, trunc8(pubkeybase64), err)
	}

	log.I("ws: wgconfs: (test? %t / tok? %s) found %d regions for %s", test, tokst, len(regconfs), trunc8(pubkeybase64))
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

func newWsGw(c *WsWgConfig, h *http.Client) (*WsClient, error) {
	if h == nil || c == nil || c.Session == nil || c.Creds == nil {
		return nil, errWsBadGatewayArgs
	}
	a := &WsClient{
		http:      h,
		configExt: core.NewVolatile(c),
	}

	log.I("ws: gw: for %s/%s; from: %s until: %s",
		a.Who(), c.tokenState(), fmtUnixMillis(a.Created()), fmtUnixMillis(a.Expires()))

	return a, nil
}

func (w *BaseClient) MakeWsWg(entitlement []byte, did string) (*WsClient, error) {
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

	(&ent).Did = did
	return makeWsWg(&w.h2, &ent)
}

func makeWsWg(h *http.Client, ent *WsEntitlement) (*WsClient, error) {
	if ent == nil || len(ent.SessionToken) <= 0 {
		log.E("ws: makeWsWg: entitlement is nil")
		return nil, errWsNoEntitlement
	}

	sess, err := getSession(h, ent.Cid, ent.Did, ent.SessionToken, ent.TestDomain)
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

func (w *BaseClient) MakeWsEntitlement(entitlementOrStateJson []byte, did string) (x.RpnEntitlement, error) {
	if len(entitlementOrStateJson) <= 0 {
		return nil, errWsNoEntitlement
	}
	if len(did) <= 0 {
		return nil, errWsNoDid
	}

	var ent WsEntitlement
	err1 := json.Unmarshal(entitlementOrStateJson, &ent)
	if err1 == nil {
		(&ent).Did = did
		return &ent, nil
	}
	var existingConf WsWgConfig
	err2 := json.Unmarshal(entitlementOrStateJson, &existingConf)
	if err2 == nil && existingConf.Entitlement != nil && len(existingConf.Entitlement.SessionToken) > 0 {
		ent := existingConf.Entitlement
		(ent).Did = did
		return ent, nil
	}
	return nil, core.JoinErr(err1, err2)
}

func (w *BaseClient) MakeWsWgFrom(entitlementOrWsConfigJson []byte, did string) (*WsClient, error) {
	if len(entitlementOrWsConfigJson) <= 0 {
		return nil, errWsNoJsonConfig
	}
	if len(did) <= 0 {
		return nil, errWsNoDid
	}

	var existingConf WsWgConfig
	err := json.Unmarshal(entitlementOrWsConfigJson, &existingConf)

	sz := len(entitlementOrWsConfigJson)
	hasEnt := existingConf.Entitlement != nil
	hasTok := hasEnt && len(existingConf.Entitlement.SessionToken) > 0
	if err != nil || !hasEnt || !hasTok {
		// may be this is an entitlement and not conf?
		log.W("ws: make: unmarshal config (sz %d / hasEnt %t / hasTok %t) err? %v; retry as entitlement",
			sz, hasEnt, hasTok, err)
		return w.MakeWsWg(entitlementOrWsConfigJson, did)
	}
	(existingConf.Entitlement).Did = did
	return w.makeWsWgFrom(&existingConf)
}

func (w *BaseClient) makeWsWgFrom(existingConf *WsWgConfig) (*WsClient, error) {
	ws, _, err := makeWsWgFrom(&w.h2, existingConf, false)
	return ws, err
}

func makeWsWgFrom(h *http.Client, existingConf *WsWgConfig, errOnNoUpdate bool) (ws *WsClient, refreshedSess bool, err error) {
	existingEnt := existingConf.Entitlement
	if existingEnt == nil || len(existingEnt.SessionToken) <= 0 {
		err = errWsNoEntitlement
		return
	}

	existingSess := existingConf.Session
	existingCreds := existingConf.Creds
	noExistingCreds := existingCreds == nil
	noExistingSess := existingSess == nil || len(existingSess.SessionToken) <= 0
	if noExistingCreds || noExistingSess {
		log.W("ws: make: no existing creds? %t; no existing sess? %t; getting new ws wg", noExistingCreds, noExistingSess)
		ws, err = makeWsWg(h, existingEnt)
		refreshedSess = true
		return
	}

	cid := existingEnt.Cid
	did := existingEnt.Did
	tokst := existingConf.tokenState()
	existingToken := existingSess.SessionToken
	existingLocHash := existingSess.LocHash
	existingTestDomain := existingEnt.TestDomain
	if existingEnt.SessionToken != existingToken {
		log.W("ws: make: entitlement does not match session; tok? %s", tokst)
	}

	newSess, err := getSession(h, cid, did, existingToken, existingTestDomain)
	if err == nil {
		existingConf.Session = newSess // update session with the latest info
		refreshedSess = true
	} else {
		log.W("ws: make: get session err: %v; using existing; tok? %s", err, tokst)
		newSess = existingConf.Session // use existing session
		if errOnNoUpdate {
			return nil, refreshedSess, err
		}
	}

	exp, err := time.Parse(time.DateOnly, newSess.ExpiryDate)
	if err != nil {
		err = log.EE("ws: make: parsing expiry %s; err: %v", newSess.ExpiryDate, err)
		return
	}

	active := exp.After(time.Now())
	existingServers := existingConf.Servers
	downloadServerList := existingLocHash != newSess.LocHash
	if active {
		maybeNewServers := existingServers
		hasnew := false
		if downloadServerList {
			newServersRes, err := getServerList(h, newSess, existingEnt)

			loge(err)("ws: make: lochash changed %s != %s / exlen(%d); fetch err? %v",
				existingLocHash, newSess.LocHash, len(existingServers), err)

			if err == nil && newServersRes != nil && len(newServersRes.Data) > 0 {
				maybeNewServers = newServersRes.Data
				hasnew = true
			}

			if len(maybeNewServers) <= 0 { // no new servers, no existing servers; bail
				return nil, refreshedSess, core.OneErr(err, errWsNoServerList)
			}
		}

		// create wg confs from new or existing server list
		// always reconfigure (as /WgConfigs/connect must be done once every wg_ttl, which is 60m)
		maybeNewCreds, maybeNewWgConfs, uerr := genWgConfs(h, existingCreds, newSess, maybeNewServers, existingConf.Entitlement)
		loge(uerr)("ws: make: gen wg confs; tok? %s; downloadloc? %t / hasnewloc? %t len (%d/%d); err? %v",
			tokst, downloadServerList, hasnew, len(existingServers), len(maybeNewServers), uerr)

		if uerr == nil {
			existingConf.Servers = maybeNewServers
			existingConf.Configs = maybeNewWgConfs
			existingConf.Creds = maybeNewCreds
		} else if errOnNoUpdate {
			return nil, refreshedSess, uerr
		}
	} else {
		log.W("ws: make: session expired at %s; tok? %s", fmtTime(exp), tokst)
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
