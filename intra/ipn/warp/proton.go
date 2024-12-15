// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package warp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
)

const (
	protonBaseUrl    = "https://vpn-api.proton.me/"
	sessionV4UrlPath = "auth/v4/sessions"
	refreshV4UrlPath = "auth/v4/refresh"
	credsV4UrlPath   = "auth/v4/credentialless"
	certV1UrlPath    = "vpn/v1/certificate"
	serversV1UrlPath = "vpn/v1/logicals" // WithState=true&Tier=2&WithEntriesForProtocols=WireGuardTLS,WireGuardTCP,WireGuardUDP
)

const (
	// github.com/ProtonVPN/android-app/blob/b9c6e59de40/app/src/main/java/com/protonvpn/android/appconfig/DefaultPortsConfig.kt#L42
	// github.com/ProtonVPN/android-app/blob/b9c6e59de40/app/src/main/java/com/protonvpn/android/vpn/wireguard/WireguardBackend.kt#L272
	// github.com/ProtonVPN/android-app/blob/b9c6e59de40/app/src/main/java/com/protonvpn/android/vpn/PrepareForConnection.kt#L98
	protonPrimaryTcpPort = 443 // same for udp
	// github.com/ProtonVPN/android-app/blob/b9c6e59de40/app/src/main/java/com/protonvpn/android/models/vpn/ConnectionParamsWireguard.kt#L45
	protonClientAddr4 = "10.2.0.2/32"
	protonDNSAddr4    = "10.2.0.1"
	// github.com/ProtonVPN/android-app/blob/b9c6e59de40/app/src/main/java/com/protonvpn/android/models/vpn/ConnectionParamsWireguard.kt#L96
	protonAllowedIPs = "0.0.0.0/0"
)

// github.com/ProtonVPN/android-app/blob/b9c6e59de40/app/src/main/java/com/protonvpn/android/models/vpn/Server.kt#L28
const (
	protonFeatureSecureCore = 1
	// protonFeatureTor           = 2
	// protonFeatureP2P           = 4
	// protonFeatureStreaming = 8
	// protonFeatureIPv6          = 16
	protonFeatureRestricted = 32
	// protonFeaturePartnerServer = 64
)

var (
	errInvalidProtonGwArgs  = errors.New("proton: cannot make gw; missing args")
	errNoProtonServerInfo   = errors.New("proton: no known server key")
	errNoProtonClientInfo   = errors.New("proton: no client key")
	errNoProtonConfig       = errors.New("proton: no wg config")
	errNoProtonJsonConfig   = errors.New("proton: no json config")
	errProtonKeyMismatch    = errors.New("proton: key mismatch")
	errProtonUidMismatch    = errors.New("proton: uid mismatch")
	errProtonUserIDMismatch = errors.New("proton: userid mismatch")
	errProtonCredsMismatch  = errors.New("proton: creds mismatch")
)

const (
	maxProtonLogicalsRefreshThreshold = 72 * time.Hour
	maxPerRegionWgConfs               = 6
	maxRegisterCertTries              = 3
)

var protonLogicalsUpdateTime = time.Time{}

var defaultLoginPayload = ProtonLoginPayload{
	LoginPayload{
		LoginProductFramePrefix0{ // dummy
			V:                    "1.0",
			AppLang:              "en-US",
			Timezone:             "America/New_York",
			DeviceName:           1234567890,
			RegionCode:           "US",
			TimezoneOffset:       -300,
			IsJailbreak:          false,
			PreferredContentSize: "Medium",
			StorageCapacity:      128.0,
			IsDarkmodeOn:         true,
			Keyboards:            []string{"QWERTY", "AZERTY"},
		},
	},
}

// ProtonLoginResponse represents the response from ProtonVPN's login API.
// github.com/ProtonMail/protoncore_android/blob/9be02705ec/auth/data/src/main/kotlin/me/proton/core/auth/data/api/response/LoginResponse.kt#L29
//
//	{
//		"Code":1000,
//		"AccessToken":"base32 (len 32)",
//		"RefreshToken":"base32 (len 32)",
//		"TokenType":"Bearer",
//		"Scopes":[],
//		"UID":"base32 (len 32)",
//		"LocalID":0
//	}
//
// UID is aliased as "sessionID" in protoncore_android.
type ProtonLoginResponse struct {
	Code         int      `json:"Code"`
	Error        string   `json:"Error"`
	Details      string   `json:"Details"`
	AccessToken  string   `json:"AccessToken"`
	RefreshToken string   `json:"RefreshToken"`
	TokenType    string   `json:"TokenType"`
	Scopes       []string `json:"Scopes"`
	UID          string   `json:"UID"`
	LocalID      int      `json:"LocalID"`
}

// ProtonLoginPayload represents the payload to be sent to ProtonVPN's login API.
//
//	{
//	    "Payload": {
//	        "product-framePrefix-0": {
//	            "v": "1.0",
//	            "appLang": "en-US",
//	            "timezone": "America/New_York",
//	            "deviceName": 1234567890,
//	            "regionCode": "US",
//	            "timezoneOffset": -300,
//	            "isJailbreak": false,
//	            "preferredContentSize": "Medium",
//	            "storageCapacity": 128.0,
//	            "isDarkmodeOn": true,
//	            "keyboards": ["QWERTY", "AZERTY"]
//	        }
//	    }
//	}
type ProtonLoginPayload struct {
	LoginPayload `json:"Payload"`
}

type LoginPayload struct {
	LoginProductFramePrefix0 `json:"product-framePrefix-0"`
}

type LoginProductFramePrefix0 struct {
	V                    string   `json:"v"`
	AppLang              string   `json:"appLang"`
	Timezone             string   `json:"timezone"`
	DeviceName           int      `json:"deviceName"`
	RegionCode           string   `json:"regionCode"`
	TimezoneOffset       int      `json:"timezoneOffset"`
	IsJailbreak          bool     `json:"isJailbreak"`
	PreferredContentSize string   `json:"preferredContentSize"`
	StorageCapacity      float64  `json:"storageCapacity"`
	IsDarkmodeOn         bool     `json:"isDarkmodeOn"`
	Keyboards            []string `json:"keyboards"`
}

//	{
//		"Code":1000,
//		"UID": base32,
//		"UserID": base64url (padded),
//		"LocalID":0,
//		"Scopes":["user","vpn"],
//		"EventID": base64url (padded),
//		"TokenType":"Bearer",
//		"AccessToken": base32 (new token),
//		"RefreshToken": base32 (new token)
//	}
type ProtonCredentialResponse struct {
	Code         int      `json:"Code"`
	Error        string   `json:"Error"`
	Details      string   `json:"Details"`
	UID          string   `json:"UID"`
	UserID       string   `json:"UserID"`
	LocalID      int      `json:"LocalID"`
	Scopes       []string `json:"Scopes"`
	EventID      string   `json:"EventID"`
	TokenType    string   `json:"TokenType"`
	AccessToken  string   `json:"AccessToken"`
	RefreshToken string   `json:"RefreshToken"`
}

// github.com/ProtonMail/protoncore_android/blob/9be02705ec/auth/data/src/main/kotlin/me/proton/core/auth/data/api/request/RefreshSessionRequest.kt#L25
//
//	{
//		"UID": "base32",
//		"RefreshToken": "base32",
//		"ResponseType": "token",
//		"GrantType": "refresh_token",
//		"RedirectURI": "http://protonmail.ch"
//	}
type ProtonRefreshRequest struct {
	UID          string `json:"UID"`
	RefreshToken string `json:"RefreshToken"`
	ResponseType string `json:"ResponseType"`
	GrantType    string `json:"GrantType"`
	RedirectURI  string `json:"RedirectURI"`
}

// github.com/ProtonMail/protoncore_android/blob/9be02705ec/auth/data/src/main/kotlin/me/proton/core/auth/data/api/response/SessionResponse.kt#L30
//
//	{
//		"Code":1000",
//		"UID":"base32",
//		"AccessToken":"base32",
//		"RefreshToken":"base32",
//		"TokenType":"Bearer",
//		"ExpiresIn":86400,
//		"Scopes":[],
//		"LocalID":0,
//		"RefreshCounter": 0,
//	}
type ProtonRefreshResponse struct {
	Code           int      `json:"Code"`
	Error          string   `json:"Error"`
	AccessToken    string   `json:"AccessToken"`
	RefreshToken   string   `json:"RefreshToken"`
	ExpiresIn      int      `json:"ExpiresIn"`
	TokenType      string   `json:"TokenType"`
	Scopes         []string `json:"Scopes"`
	UID            string   `json:"UID"`
	LocalID        int      `json:"LocalID"`
	RefreshCounter int      `json:"RefreshCounter"`
}

//	{
//		"ClientPublicKey": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAFJ2 ... MRmdSNTikbTzToQWw=\n-----END PUBLIC KEY-----",
//		"ClientPublicKeyMode": "EC",
//		"DeviceName": "Google Pixel 9",
//		"Mode": "session", (or "persistent")
//		"Features": []
//	}
type ProtonCertRequest struct {
	ClientPublicKey     string   `json:"ClientPublicKey"`
	ClientPublicKeyMode string   `json:"ClientPublicKeyMode"`
	DeviceName          string   `json:"DeviceName"`
	Mode                string   `json:"Mode"`
	Features            []string `json:"Features"`
}

//	{
//		"Code":1000,
//		"SerialNumber":"4000000007",
//		"ClientKeyFingerprint":"CLje0UCe1vVDgsifJ0W6 ... v4M74ViT/jedV8lcfg4NgQ==",
//		"ClientKey":"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAFJ2 ... MRmdSNTikbTzToQWw=\n-----END PUBLIC KEY-----",
//		"Certificate":"-----BEGIN CERTIFICATE-----\nMIIB+DCCAaqg...\n...\nD...\n...\n...\n...\n...\n...\n...\n...==\n-----END CERTIFICATE-----\n",
//		"ExpirationTime":1732548421,
//		"RefreshTime":1732526821,
//		"Mode":"session",
//		"DeviceName":"Google Pixel 9",
//		"Features":[],
//		"ServerPublicKeyMode":"EC",
//		"ServerPublicKey":"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEANm3aIvkeaMO9ctcIeEfM4K1ME3bU9feum5sWQ3Sdx+o=\n-----END PUBLIC KEY-----"
//	}
type ProtonCertResponse struct {
	Code                 int      `json:"Code"`
	Error                string   `json:"Error"`
	Details              string   `json:"Details"`
	SerialNumber         string   `json:"SerialNumber"`
	ClientKeyFingerprint string   `json:"ClientKeyFingerprint"`
	ClientKey            string   `json:"ClientKey"`
	Certificate          string   `json:"Certificate"`
	ExpirationTime       int      `json:"ExpirationTime"` // 24 hours
	RefreshTime          int      `json:"RefreshTime"`    // 18 hours
	Mode                 string   `json:"Mode"`
	DeviceName           string   `json:"DeviceName"`
	Features             []string `json:"Features"`
	ServerPublicKeyMode  string   `json:"ServerPublicKeyMode"`
	ServerPublicKey      string   `json:"ServerPublicKey"`
}

// github.com/ProtonVPN/android-app/blob/master/app/src/b9c6e59de40/assets/GuestHoleServers.json
type ProtonServerResponse struct {
	Code int              `json:"Code"`
	R    []ProtonLogicals `json:"LogicalServers"`
}

//	{
//		"Name": "US-TX#211",
//		"EntryCountry": "US",
//		"ExitCountry": "US",
//		"Domain": "node-us-222.protonvpn.net",
//		"Tier": 2,
//		"Features": 28,
//		"Region": null,
//		"City": "Dallas",
//		"Score": 2.9895218788999998,
//		"HostCountry": null,
//		"OrganizationID": null,
//		"VPNGatewayID": null,
//		"ID": "nI-Q-DzkDKEfbHl8a_7pannKCxiirV-MARJzF4Sm01ErrazEi6Sq3qKP3wsEMh4Ot44pfFRPKBmJDTpUqennAg==",
//		"Location": {
//			"Lat": 32.770000000000003,
//			"Long": -96.799999999999997
//		},
//		"Status": 1,
//		"Servers": [
//			{
//				"EntryIP": "37.19.200.27",
//				"ExitIP": "169.150.254.169",
//				"Domain": "node-us-222.protonvpn.net",
//				"ID": "HSQ3bp4GuJRUV-w3eRdPyOzXeCX3k8RBYhtJ2GZUxCLyfTimMoHEIOuyRqie9GMd7uC2F8pq-XLH6T-_qTwtiw==",
//				"Label": "8",
//				"X25519PublicKey": "nZYSL1qRLQRFC71xHVmBxP6XMwTm7yEFGBNtCBckEAg=",
//				"Generation": 0,
//				"Status": 1,
//				"ServicesDown": 0,
//				"ServicesDownReason": null
//			}
//		],
//		"Load": 63
//	}
type ProtonLogicals struct {
	Name         string  `json:"Name"`
	EntryCountry string  `json:"EntryCountry"`
	ExitCountry  string  `json:"ExitCountry"`
	Domain       string  `json:"Domain"`
	Tier         int     `json:"Tier"`
	Features     int     `json:"Features"`
	Region       string  `json:"Region"`
	City         string  `json:"City"`
	Score        float64 `json:"Score"`
	HostCountry  string  `json:"HostCountry"`
	Organization string  `json:"OrganizationID"`
	VPNGatewayID string  `json:"VPNGatewayID"`
	ID           string  `json:"ID"`
	Load         int     `json:"Load"`
	Status       int     `json:"Status"`

	Location ProtonServerLocation `json:"Location"`
	Servers  []ProtonServer       `json:"Servers"`
}

//	"Location": {
//		"Lat": 32.770000000000003,
//		"Long": -96.799999999999997
//	}
type ProtonServerLocation struct {
	Lat  float64 `json:"Lat"`
	Long float64 `json:"Long"`
}

//	{
//		"EntryIP": "37.19.200.27",
//		"ExitIP": "169.150.254.169",
//		"Domain": "node-us-222.protonvpn.net",
//		"ID": "HSQ3bp4GuJRUV-w3eRdPyOzXeCX3k8RBYhtJ2GZUxCLyfTimMoHEIOuyRqie9GMd7uC2F8pq-XLH6T-_qTwtiw==",
//		"Label": "8",
//		"X25519PublicKey": "nZYSL1qRLQRFC71xHVmBxP6XMwTm7yEFGBNtCBckEAg=",
//		"Generation": 0,
//		"Status": 1,
//		"ServicesDown": 0,
//		"ServicesDownReason": null
//	}
type ProtonServer struct {
	Name               string `json:"Name"`
	Load               int    `json:"Load"`
	EntryIP            string `json:"EntryIP"`
	ExitIP             string `json:"ExitIP"`
	Domain             string `json:"Domain"`
	ID                 string `json:"ID"`
	Label              string `json:"Label"`
	X25519PublicKey    string `json:"X25519PublicKey"`
	Generation         int    `json:"Generation"`
	Status             int    `json:"Status"`
	ServicesDown       int    `json:"ServicesDown"`
	ServicesDownReason string `json:"ServicesDownReason"`
}

// github.com/ProtonVPN/android-app/blob/b9c6e59de40/app/src/main/java/com/protonvpn/android/models/vpn/Server.kt#L56-L58
func (s *ProtonServer) online() bool {
	return s.Status == 1
}

// github.com/ProtonVPN/android-app/blob/b9c6e59de40/app/src/main/java/com/protonvpn/android/models/vpn/usecase/SupportsProtocol.kt#L59
func (s *ProtonServer) wg() bool {
	return len(s.X25519PublicKey) > 6
}

func (s *ProtonLogicals) securecore() bool {
	return s.Features&protonFeatureSecureCore == protonFeatureSecureCore
}

func (s *ProtonLogicals) gateway() bool {
	return s.Features&protonFeatureRestricted == protonFeatureRestricted
}

func (s *ProtonLogicals) offline() bool {
	return s.Status != 1
}

type ProtonWgConfig struct {
	Ed25519PrivBase64 string `json:"Ed25519PrivateKey"`

	UID                 string `json:"UID"`
	SessionAccessToken  string `json:"SessionAccessToken"`
	SessionRefreshToken string `json:"SessionRefreshToken"`

	UserID            string `json:"UserID"`
	CredsAccessToken  string `json:"UserAccessToken"`
	CredsRefreshToken string `json:"UserRefreshToken"`

	CertSerialNumber string `json:"CertSerialNumber"`
	CertExpTime      int    `json:"CertExpTime"`
	CertRefreshTime  int    `json:"CertRefreshTime"`

	CreateTimestamp int64             `json:"CreateTimestamp"`
	RegionalWgConfs []*RegionalWgConf `json:"RegionalWgConfs"`
}

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

	ServerPubKey     string `json:"ServerPubKey"`
	ServerIPPort4    string `json:"ServerIPPort4"`
	ServerIPPort6    string `json:"ServerIPPort6"`
	ServerDomainPort string `json:"ServerDomainPort"`
	AllowedIPs       string `json:"AllowedIPs"` // csv

	WgConf string `json:"WgConf"` // generated
}

func (id *ProtonWgConfig) Json() ([]byte, error) {
	if id == nil {
		return nil, errNoProtonConfig
	}

	var w bytewriter
	if err := id.writeJson(&w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

func (id *ProtonWgConfig) writeJson(w io.Writer) error {
	if id == nil {
		return errNoProtonConfig
	}

	for _, r := range id.RegionalWgConfs {
		r.genWgConf()
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(id)
}

func (id *RegionalWgConf) genWgConf() {
	if id == nil {
		return
	}
	id.WgConf = fmt.Sprintf(`[Interface]
PrivateKey = %s
PublicKey = %s
Address = %s
DNS = %s
[Peer]
PublicKey = %s
Endpoint = %s
Endpoint = %s
AllowedIPs = %s`,
		id.ClientPrivKey,
		id.ClientPubKey,
		id.ClientAddr4,
		id.ClientDNS4,
		id.ServerPubKey,
		id.ServerIPPort4,
		id.ServerDomainPort,
		id.AllowedIPs,
	)
}

type protongw struct {
	http *http.Client
	key  ProtonKey

	servers map[string][]ProtonServer // country => endpoints
	sched   *core.Scheduler

	sess struct { // unauthenticated
		uid          string
		accessToken  string
		refreshToken string
	}
	creds struct { // authenticated
		userid       string
		accessToken  string
		refreshToken string
	}
	cert struct {
		SerialNumber   string
		ExpirationTime int
		RefreshTime    int
	}

	config *ProtonWgConfig
}

func newProtonGw(ctx context.Context, k ProtonKey, logicals []ProtonLogicals, h2 *http.Client) (*protongw, error) {
	if k == nil || len(logicals) <= 0 || h2 == nil {
		return nil, errInvalidProtonGwArgs
	}

	publicKeyPem := k.PublicKeyPKIXPem()
	if len(publicKeyPem) > 16 {
		publicKeyPem = publicKeyPem[6:16]
	}

	m := protonServersByCountry(logicals)

	a := &protongw{
		http:    h2,
		key:     k,
		servers: m, // may be empty
		sched:   core.NewScheduler(ctx),
		sess: struct {
			uid          string
			accessToken  string
			refreshToken string
		}{},
		creds: struct {
			userid       string
			accessToken  string
			refreshToken string
		}{},
		config: nil,
	}

	log.I("proton: gw: new: %s / %d", publicKeyPem, len(m))

	return a, nil
}

func (a *protongw) refreshConf() error {
	pc := a.config
	if pc == nil {
		return errNoProtonConfig
	}
	// key
	if pc.Ed25519PrivBase64 != a.key.PrivateKeyBase64() {
		return errProtonKeyMismatch
	}
	// session info
	if pc.UID != a.sess.uid {
		return errProtonUidMismatch
	}
	// creds info
	if pc.UserID != a.creds.userid {
		return errProtonUserIDMismatch
	}
	if pc.CredsAccessToken != a.creds.accessToken || pc.CredsRefreshToken != a.creds.refreshToken {
		return errProtonCredsMismatch
	}
	// cert info
	if pc.CertSerialNumber != a.cert.SerialNumber {
		log.W("proton: refresh: serial number mismatch conf(%s) != struct(%s)",
			pc.CertSerialNumber, a.cert.SerialNumber)
		// expect it to be the same when the key is the same
	}
	// wg info
	for _, r := range pc.RegionalWgConfs {
		r.genWgConf()
	}
	return nil // ok
}

func (a *protongw) newConf() error {
	a.config = nil // reset

	pc := new(ProtonWgConfig)

	wgkey := a.key.ToX25519()
	clientPrivKey := wgkey.Base64()
	clientPubKey := wgkey.Mult().Base64()

	if len(clientPubKey) < 6 {
		return errNoProtonClientInfo
	}

	rwgConfs := make([]*RegionalWgConf, 0, len(a.servers))
	for cc, ss := range a.servers {
		wc := new(RegionalWgConf)
		wc.CC = cc
		wc.ClientAddr4 = protonClientAddr4
		wc.ClientPrivKey = clientPrivKey
		wc.ClientPubKey = clientPubKey
		wc.ClientDNS4 = protonDNSAddr4

		n := 0
		for _, s := range ss {
			if n > maxPerRegionWgConfs {
				break
			}
			// github.com/ProtonVPN/android-app/blob/b9c6e59de40/app/src/main/java/com/protonvpn/android/utils/ServerManager.kt#L251
			if s.online() && s.wg() {
				n++
				wc.Name = s.Name
				wc.ServerPubKey = s.X25519PublicKey
				wc.ServerIPPort4 = fmt.Sprintf("%s:%d", s.EntryIP, protonPrimaryTcpPort)
				wc.ServerDomainPort = fmt.Sprintf("%s:%d", s.Domain, protonPrimaryTcpPort)
				wc.AllowedIPs = protonAllowedIPs

				rwgConfs = append(rwgConfs, wc)

				log.VV("proton: genconf: %s n:%d, l:%d; x: %s@%s; p: %s@%s",
					s.Name, n, s.Load, wc.ClientAddr4, wc.ClientPubKey[:6], wc.ServerIPPort4, wc.ServerPubKey[:6])
			}
		}
	}

	if len(rwgConfs) < 6 {
		return errNoProtonServerInfo
	}

	// key
	pc.Ed25519PrivBase64 = a.key.PrivateKeyBase64()
	// session info
	pc.UID = a.sess.uid
	pc.SessionAccessToken = a.sess.accessToken
	pc.SessionRefreshToken = a.sess.refreshToken
	// creds info
	pc.UserID = a.creds.userid
	pc.CredsAccessToken = a.creds.accessToken
	pc.CredsRefreshToken = a.creds.refreshToken
	// cert info
	pc.CertSerialNumber = a.cert.SerialNumber
	pc.CertExpTime = a.cert.ExpirationTime
	pc.CertRefreshTime = a.cert.RefreshTime
	// wg info
	pc.RegionalWgConfs = rwgConfs

	pc.CreateTimestamp = time.Now().Unix()

	a.config = pc

	return nil // success
}

func (a *protongw) registerCert() error {
	tries := 0

retryAfterRefresh:
	tries++
	/*
		curl -X POST "https://vpn-api.proton.me/vpn/v1/certificate" \
		-H "Content-Type: application/vnd.protonmail.v1+json" \
		-H "Accept: application/vnd.protonmail.v1+json" \
		-H "x-pm-appversion: android-vpn@5.6.38" \
		-H "x-pm-uid: 6l762bvsidekfmscgk47m7rhsunrw7cr" \
		-H "x-pm-locale: en-US" \
		-H "Authorization: Bearer sj3cuounbeynvie546hsgueibl2tckud" \
		-H "User-Agent: ProtonVPN/5.6.38 (Android 34b5; Google Pixel9)" \
		-d '{
			"ClientPublicKey": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAFJ20p585i6XvHqLRtsCWGbkip5MRmdSNTikbTzToQWw=\n-----END PUBLIC KEY-----",
			"ClientPublicKeyMode": "EC",
			"DeviceName": "Google Pixel 9",
			"Mode": "session", // or "persistent"
			"Features": []
		}'
	*/
	payload := &ProtonCertRequest{
		ClientPublicKey:     a.key.PublicKeyPKIXPem(),
		ClientPublicKeyMode: "EC",
		DeviceName:          "Google Pixel 9",
		Mode:                "session", // or "persistent"
		Features:            []string{},
	}
	payloadJson, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", a.certUrl(), bytes.NewReader(payloadJson))
	if err != nil {
		return err
	}
	protonHeaders(req)
	a.addRegistrationHeaders(req)

	res, err := a.http.Do(req)
	if err != nil || res == nil {
		return core.OneErr(err, errNoApiResponse)
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusUnauthorized && tries <= maxRegisterCertTries {
		err := a.refreshCreds()
		if err == nil {
			log.I("proton: regcert: retrying after creds refresh try# %d", tries)
			goto retryAfterRefresh
		} else {
			log.E("proton: regcert: fail: try# %d, creds refresh status(%d/%s)",
				tries, res.StatusCode, res.Status)
			return err
		}
	}
	if res.StatusCode != http.StatusOK {
		b, rerr := io.ReadAll(res.Body)
		log.E("proton: regcert: fail: status(%d/%s) hdrs(%v) body(%s) err(%v)",
			res.StatusCode, res.Status, res.Header, b, rerr)
		return fmt.Errorf("proton: regcert: err status(%d/%s)", res.StatusCode, res.Status)
	}

	certResponseBytes, err := io.ReadAll(res.Body)
	if err != nil {
		log.E("proton: regcert: readall: %v", err)
		return err
	}

	var certResponse ProtonCertResponse
	if err = json.Unmarshal(certResponseBytes, &certResponse); err != nil {
		log.E("proton: regcert: unmarshal: %v", err)
		return err
	}

	if certResponse.Code != 1000 {
		log.E("proton: regcert: code: %d / raw: %s", certResponse.Code, string(certResponseBytes))
		// TODO: refresh with refresh-token
		return fmt.Errorf("proton: regcert: err %d: %s", certResponse.Code, certResponse.Error)
	}
	// TODO: certResponse.ClientPublicKey == a.key.PublicKeyPKIXPem()

	a.cert.SerialNumber = certResponse.SerialNumber
	a.cert.ExpirationTime = certResponse.ExpirationTime
	a.cert.RefreshTime = certResponse.RefreshTime

	refreshAt := time.Unix(int64(a.cert.RefreshTime), 0)
	// github.com/ProtonVPN/android-app/blob/b9c6e59de40/app/src/main/java/com/protonvpn/android/vpn/CertificateRepository.kt#L183-L188
	a.sched.At(a.cert.SerialNumber, refreshAt, a.registerCert)

	log.I("proton: regcert: success: serial(%s): next refresh(%s)", certResponse.SerialNumber, refreshAt.Format(time.RFC1123))

	return nil
}

func (a *protongw) fetchCreds() error {
	/*
		curl -X POST "https://vpn-api.proton.me/auth/v4/credentialless" \
		-H "Content-Type: application/vnd.protonmail.v1+json" \
		-H "Accept: application/vnd.protonmail.v1+json" \
		-H "x-pm-appversion: android-vpn@5.6.38" \
		-H "x-pm-uid: sessionUid" \
		-H "x-pm-locale: en-US" \
		-H "Authorization: Bearer sessionAccessToken" \
		-H "User-Agent: ProtonVPN/5.6.38 (Android 34b5; Google Pixel9)" \
		-d '{
			"Payload": {
				"product-framePrefix-0": {
					"v": "1.0",
					"appLang": "en-US",
					"timezone": "America/New_York",
					"deviceName": 1234567890,
					"regionCode": "US",
					"timezoneOffset": -300,
					"isJailbreak": false,
					"preferredContentSize": "Medium",
					"storageCapacity": 128.0,
					"isDarkmodeOn": true,
					"keyboards": ["QWERTY", "AZERTY"]
				}
			}
		}'
	*/
	payload := defaultLoginPayload
	payloadJson, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", a.credsUrl(), bytes.NewReader(payloadJson))
	if err != nil {
		return err
	}
	protonHeaders(req)
	a.addSessionHeaders(req)

	res, err := a.http.Do(req)
	if err != nil || res == nil {
		return core.OneErr(err, errNoApiResponse)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		b, rerr := io.ReadAll(res.Body)
		log.E("proton: creds: fail: status(%d/%s) hdrs(%v) body(%s) err(%v)",
			res.StatusCode, res.Status, res.Header, b, rerr)
		return fmt.Errorf("proton: creds: err status(%d/%s)", res.StatusCode, res.Status)
	}

	credResponseBytes, err := io.ReadAll(res.Body)
	if err != nil {
		log.E("proton: creds: readall: %v", err)
		return err
	}

	var credResponse ProtonCredentialResponse
	if err := json.Unmarshal(credResponseBytes, &credResponse); err != nil {
		log.E("proton: creds: unmarshal: %v", err)
		return err
	}

	if credResponse.Code != 1000 {
		log.E("proton: creds: code: %d / raw: %s", credResponse.Code, string(credResponseBytes))
		// TODO: refresh with refresh-token
		return fmt.Errorf("proton: creds: err %d: %s", credResponse.Code, credResponse.Error)
	}
	// todo: credResponse.UID == a.sess.uid
	// todo: credResponse.Scopes contains "vpn"
	// todo: credResponse.TokenType == "Bearer"

	a.creds.userid = credResponse.UserID
	a.creds.accessToken = credResponse.AccessToken
	a.creds.refreshToken = credResponse.RefreshToken

	return nil
}

func (a *protongw) beginSession() error {
	/*
	   curl -X POST "https://vpn-api.proton.me/auth/v4/sessions" \
	   -H "Content-Type: application/vnd.protonmail.v1+json" \
	   -H "Accept: application/vnd.protonmail.v1+json" \
	   -H "x-pm-appversion: android-vpn@5.6.38" \
	   -H "x-pm-locale: en-US" \
	   -H "User-Agent: ProtonVPN/5.6.38 (Android 34b5; Google Pixel9)" \
	   -d '{
	       "Payload": {
	           "product-framePrefix-0": {
	               "v": "1.0",
	               "appLang": "en-US",
	               "timezone": "America/New_York",
	               "deviceName": 1234567890,
	               "regionCode": "US",
	               "timezoneOffset": -300,
	               "isJailbreak": false,
	               "preferredContentSize": "Medium",
	               "storageCapacity": 128.0,
	               "isDarkmodeOn": true,
	               "keyboards": ["QWERTY", "AZERTY"]
	           }
	       }
	   }'
	*/
	payload := defaultLoginPayload
	payloadJson, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", a.sessionUrl(), bytes.NewReader(payloadJson))
	if err != nil {
		return err
	}
	protonHeaders(req)

	res, err := a.http.Do(req)
	if err != nil || res == nil {
		return core.OneErr(err, errNoApiResponse)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		b, rerr := io.ReadAll(res.Body)
		log.E("proton: session: fail: status(%d/%s) hdrs(%v) body(%s) err(%v)",
			res.StatusCode, res.Status, res.Header, b, rerr)
		return fmt.Errorf("proton: session: err status(%d/%s)", res.StatusCode, res.Status)
	}

	sessionResponseBytes, err := io.ReadAll(res.Body)
	if err != nil {
		log.E("proton: session: readall: %v", err)
		return err
	}

	var sessionResponse ProtonLoginResponse
	if err := json.Unmarshal(sessionResponseBytes, &sessionResponse); err != nil {
		log.E("proton: session: unmarshal: %v", err)
		return err
	}

	if sessionResponse.Code != 1000 {
		log.E("proton: session: code: %d / raw: %s", sessionResponse.Code, string(sessionResponseBytes))
		// TODO: refresh with refresh-token
		return fmt.Errorf("proton: session: err %d: %s", sessionResponse.Code, sessionResponse.Error)
	}

	a.sess.uid = sessionResponse.UID
	a.sess.accessToken = sessionResponse.AccessToken
	a.sess.refreshToken = sessionResponse.RefreshToken

	return nil
}

func (a *protongw) refreshCreds() error {
	/*
		curl -X POST "https://vpn-api.proton.me/auth/v4/refresh" \
		-H "Content-Type: application/vnd.protonmail.v1+json" \
		-H "Accept: application/vnd.protonmail.v1+json" \
		-H "x-pm-appversion: android-vpn@5.6.38" \
		-H "User-Agent: ProtonVPN/5.6.38 (Android 34b5; Google Pixel9)" \
		-d '{
		  "UID": "base32 uid / sessionId",
		  "RefreshToken": "authenticated (creds) base32 refresh token",
		  "ResponseType": "token",
		  "GrantType": "refresh_token",
		  "RedirectURI": "http://protonmail.ch"
		}'
	*/
	payload := ProtonRefreshRequest{
		UID:          a.sess.uid,
		RefreshToken: a.creds.refreshToken,
		ResponseType: "token",
		GrantType:    "refresh_token",
		RedirectURI:  "http://protonmail.ch",
	}
	payloadJson, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", a.refreshCredsUrl(), bytes.NewReader(payloadJson))
	if err != nil {
		return err
	}
	protonHeaders(req)

	res, err := a.http.Do(req)
	if err != nil || res == nil {
		return core.OneErr(err, errNoApiResponse)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		b, rerr := io.ReadAll(res.Body)
		log.E("proton: refreshcreds: fail: status(%d/%s) hdrs(%v) body(%s) err(%v)",
			res.StatusCode, res.Status, res.Header, b, rerr)
		return fmt.Errorf("proton: refreshcreds: err status(%d/%s)", res.StatusCode, res.Status)
	}

	refreshCredResponseBytes, err := io.ReadAll(res.Body)
	if err != nil {
		log.E("proton: refreshcreds: readall: %v", err)
		return err
	}

	var refreshCredResponse ProtonRefreshResponse
	if err := json.Unmarshal(refreshCredResponseBytes, &refreshCredResponse); err != nil {
		log.E("proton: refreshcreds: unmarshal: %v", err)
		return err
	}

	if refreshCredResponse.Code != 1000 {
		log.E("proton: refreshcreds: code: %d / raw: %s", refreshCredResponse.Code, string(refreshCredResponseBytes))
		// TODO: refresh with refresh-token
		return fmt.Errorf("proton: refreshcreds: err %d: %s", refreshCredResponse.Code, refreshCredResponse.Error)
	}
	// todo: refreshCredResponse.UID == a.sess.uid
	// todo: refreshCredResponse.Scopes contains "vpn"
	// todo: refreshCredResponse.TokenType == "Bearer"

	a.creds.accessToken = refreshCredResponse.AccessToken
	a.creds.refreshToken = refreshCredResponse.RefreshToken

	return nil
}

func (a *protongw) sessionUrl() string {
	return protonBaseUrl + sessionV4UrlPath
}

func (a *protongw) refreshCredsUrl() string {
	return protonBaseUrl + refreshV4UrlPath
}

func (a *protongw) credsUrl() string {
	return protonBaseUrl + credsV4UrlPath
}

func (a *protongw) certUrl() string {
	return protonBaseUrl + certV1UrlPath
}

func protonLogicalsUrl() string {
	return protonBaseUrl + serversV1UrlPath
}

func protonContentHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/vnd.protonmail.v1+json")
	req.Header.Set("Accept", "application/vnd.protonmail.v1+json")
}

func protonHeaders(req *http.Request) {
	protonContentHeaders(req)
	// using x-pm-appversion with some APIs like logicals
	// will result in 401; but omitting it will work fine
	req.Header.Set("x-pm-appversion", "android-vpn@5.6.38")
	req.Header.Set("x-pm-locale", "en-US")
	req.Header.Set("User-Agent", "ProtonVPN/5.6.38 (Android 34b5; Google Pixel9")
}

func (a *protongw) addSessionHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+a.sess.accessToken)
	req.Header.Set("x-pm-uid", a.sess.uid)
}

func (a *protongw) addRegistrationHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+a.creds.accessToken)
	req.Header.Set("x-pm-uid", a.sess.uid)
}

func protonNetZoneHeaders(req *http.Request) {
	req.Header.Set("x-pm-netzone", "1.1.0.0")
	req.Header.Set("x-pm-country", "us")
	if !protonLogicalsUpdateTime.IsZero() {
		// TODO: modify this to be the last time we fetched the servers
		req.Header.Set("If-Modified-Since", protonLogicalsUpdateTime.Format(time.RFC1123))
	}
}

func (a *protongw) reg() error {
	log.I("proton: reg")

	err := a.beginSession()
	if err != nil {
		return err
	}

	err = a.fetchCreds()
	if err != nil {
		return err
	}

	err = a.registerCert()
	if err != nil {
		return err
	}

	return a.newConf()
}

func (a *protongw) refreshServers() error {
	const nofile = ""

	oldEnough := time.Since(protonLogicalsUpdateTime) > maxProtonLogicalsRefreshThreshold
	missingConfig := a.config == nil || len(a.config.RegionalWgConfs) <= 0
	if oldEnough || missingConfig {
		t := protonLogicalsUpdateTime.Format(time.RFC1123)
		log.I("proton: refresh servers; old(%s)? %t / missing? %t", oldEnough, t, missingConfig)
		a.servers = protonServersByCountry(protonServersFrom(nofile, a.http))
	}

	return nil
}

func (a *protongw) rereg() error {
	if len(a.sess.uid) <= 0 {
		log.W("proton: re-reg: no session; initiating reg")
		return a.reg()
	}

	log.I("proton: re-reg")

	err := a.refreshCreds() // new creds
	if err != nil {
		return err
	}

	err = a.registerCert() // re-register
	if err != nil {
		return err
	}

	return a.refreshConf()
}

func (w *Client) MakeProtonWg(ctx context.Context, allServersFilePath string) (*ProtonWgConfig, error) {
	k, err := newProtonKeyPair()
	if err != nil {
		return nil, err
	}

	svcs := protonServersFrom(allServersFilePath, &w.h2)
	a, err := newProtonGw(ctx, k, svcs, &w.h2)
	if err != nil {
		return nil, err
	}

	err = a.reg()
	if err != nil {
		return nil, err
	}

	return a.config, nil
}

func (w *Client) MakeProtonWgFrom(ctx context.Context, fromConfigJson []byte, allServersFilePath string) (*ProtonWgConfig, error) {
	if len(fromConfigJson) <= 0 {
		return nil, errNoProtonJsonConfig
	}

	var conf ProtonWgConfig
	err := json.Unmarshal(fromConfigJson, &conf)
	if err != nil {
		return nil, err
	}

	if len(conf.Ed25519PrivBase64) <= 0 {
		return nil, errNoProtonClientInfo
	}

	k, err := newProtonKeyPairFrom(conf.Ed25519PrivBase64)
	if err != nil {
		return nil, err
	}

	svcs := protonServersPrebuilt() // refreshed if needed later
	a, err := newProtonGw(ctx, k, svcs, &w.h2)
	if err != nil {
		return nil, err
	}

	err = a.load(&conf)
	if err != nil {
		return nil, err
	}

	err = a.rereg()
	if err != nil {
		return nil, err
	}

	err = a.refreshServers()
	if err != nil {
		return nil, err
	}

	return a.config, nil
}

func (a *protongw) load(conf *ProtonWgConfig) error {
	a.config = conf

	// session info
	a.sess.uid = conf.UID
	a.sess.accessToken = conf.SessionAccessToken
	a.sess.refreshToken = conf.SessionRefreshToken
	// creds info
	a.creds.userid = conf.UserID
	a.creds.accessToken = conf.CredsAccessToken
	a.creds.refreshToken = conf.CredsRefreshToken
	// cert info
	a.cert.SerialNumber = conf.CertSerialNumber
	a.cert.ExpirationTime = conf.CertExpTime
	a.cert.RefreshTime = conf.CertRefreshTime

	protonLogicalsUpdateTime = time.Unix(conf.CreateTimestamp, 0)

	return nil
}

func protonServersByCountry(logicals []ProtonLogicals) map[string][]ProtonServer {
	m := make(map[string][]ProtonServer, 0)
	skips := 0
	tot := 0
	for _, x := range logicals {
		// github.com/ProtonVPN/android-app/blob/b9c6e59de40/app/src/main/java/com/protonvpn/android/utils/ServerManager.kt#L251
		// skip premium or restricted or offline servers
		if x.securecore() || x.gateway() || x.offline() {
			skips++
			continue
		}
		for _, s := range x.Servers {
			s.Load = x.Load
			s.Name = x.Name
		}
		if c, ok := m[x.EntryCountry]; ok {
			m[x.EntryCountry] = append(c, x.Servers...)
		} else {
			m[x.EntryCountry] = x.Servers
		}
		tot += len(x.Servers)
	}
	log.I("proton: servers: sz: l(%d) => [cc(%d) => svcs(%d) / skip: %d]",
		len(logicals), len(m), tot, skips)
	return m
}

func protonServersPrebuilt() []ProtonLogicals {
	var prebuilts []ProtonLogicals
	err := json.Unmarshal(prebuiltProtonServersJson, &prebuilts)
	if err != nil {
		log.E("proton: servers: %d unmarshal: %v", len(prebuiltProtonServersJson), err)
	}
	return prebuilts
}

// go.dev/play/p/9kapzPiG72r
func protonServersFrom(allServersFilePath string, c *http.Client) []ProtonLogicals {
	var all ProtonServerResponse

	prebuilts := protonServersPrebuilt()

	if len(allServersFilePath) > 0 {
		fp := filepath.Clean(allServersFilePath)
		f, err := os.OpenFile(fp, os.O_RDONLY, 0)
		if err != nil {
			log.E("proton: servers: open %s, err: %v", fp, err)
		} else {
			defer f.Close()
			if fi, err := f.Stat(); err != nil {
				log.W("proton: servers: stat %s, err: %v", fp, err)
			} else {
				fmod := fi.ModTime()
				fage := time.Since(fmod)
				if fage > maxProtonLogicalsRefreshThreshold {
					log.W("proton: servers: %s is stale: %v", fp, fage.Hours())
				} else {
					protonLogicalsUpdateTime = fmod
					b, err := io.ReadAll(f)
					if err != nil {
						log.E("proton: servers: readall %s, err: %v", fp, err)
					} else {
						err = json.Unmarshal(b, &all)
						if err != nil {
							log.E("proton: servers: %s unmarshal: %v", string(b), err)
						} else {
							log.I("proton: servers: read from file %s (age: %d): %d",
								fp, fage.Hours(), len(all.R))
						}
					}
				}
			}
		}
	}
	if len(all.R) == 0 {
		// curl -X GET "https://vpn-api.proton.me/vpn/v1/logicals?WithState=true&Tier=2&WithEntriesForProtocols=WireGuard" \
		// -H "Content-Type: application/vnd.protonmail.v1+json" \
		// -H "x-pm-netzone: 1.1.0.0" \
		// -H "x-pm-country: us" \
		// -H "If-Modified-Since: Mon, 9 Dec 2024 07:28:00 GMT" \
		// -H "User-Agent: ProtonVPN/5.6.38 (Android 34b5; Google Pixel9)"
		req, err := http.NewRequest("GET", protonLogicalsUrl(), nil)
		if err != nil {
			log.E("proton: servers: req: %v", err)
		} else {
			// protonHeaders (esp x-pm-appversion) results in 401
			protonContentHeaders(req)
			protonNetZoneHeaders(req)
			res, err := c.Do(req)
			if err != nil || res == nil {
				err = core.OneErr(err, errNoApiResponse)
				log.E("proton: servers: do: %v", err)
			} else {
				defer res.Body.Close()
				if res.StatusCode != http.StatusOK {
					b, rerr := io.ReadAll(res.Body)
					log.E("proton: servers: fail: status(%d/%s) hdrs(%v) body(%s) err(%v)",
						res.StatusCode, res.Status, res.Header, b, rerr)
				} else {
					b, err := io.ReadAll(res.Body)
					if err != nil {
						log.E("proton: servers: readall: %v", err)
					} else {
						err = json.Unmarshal(b, &all)
						if err != nil {
							log.E("proton: servers: %s unmarshal: %v", string(b), err)
						} else {
							log.I("proton: servers: fetched from remote: %d", len(all.R))
							if len(allServersFilePath) > 0 {
								fp := filepath.Clean(allServersFilePath)
								f, err := os.OpenFile(fp, os.O_WRONLY|os.O_CREATE, 0600)
								if err != nil {
									log.E("proton: servers: open rw %s, err: %v", fp, err)
								} else {
									defer f.Close()
									_, err = f.Write(b)
									if err != nil {
										log.E("proton: servers: write %s, err: %v", fp, err)
									} // else: written
								}
							} // else: no-store
							protonLogicalsUpdateTime = time.Now()
						}
					}
				}
			}
		}
	} // else: contains remote servers
	return append(all.R, prebuilts...)
}
