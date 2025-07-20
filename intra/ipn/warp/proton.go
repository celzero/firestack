// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package warp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"time"

	x "github.com/celzero/firestack/intra/backend"
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
	// protonSecondaryPort  = 51820 // for udp and tcp
	// github.com/ProtonVPN/android-app/blob/b9c6e59de40/app/src/main/java/com/protonvpn/android/models/vpn/ConnectionParamsWireguard.kt#L45
	protonClientAddr4 = "10.2.0.2/32"
	protonDNSAddr4    = "10.2.0.1"
	// ipv6: github.com/ProtonVPN/android-app/commit/80ac0af8583f32cc579fab7a012702bff52c83f3
	protonClientAddr6 = "2a07:b944::2:2"
	protonDNSAddr6    = "2a07:b944::2:1"
)

// github.com/ProtonVPN/android-app/blob/b9c6e59de40/app/src/main/java/com/protonvpn/android/models/vpn/Server.kt#L28
const (
	protonFeatureSecureCore = 1
	// protonFeatureTor       = 2
	// protonFeatureP2P       = 4
	// protonFeatureStreaming = 8
	protonFeatureIPv6       = 16
	protonFeatureRestricted = 32
	// protonFeaturePartnerServer = 64
)

var (
	errInvalidProtonGwArgs  = errors.New("proton: cannot make gw; missing args")
	errNoProtonServerInfo   = errors.New("proton: no known server key")
	errNoProtonClientInfo   = errors.New("proton: no client key")
	errNoProtonConfig       = errors.New("proton: no wg config")
	errNoProtonJsonConfig   = errors.New("proton: no json config")
	errNoProtonCcConf       = errors.New("proton: no cc conf")
	errProtonKeyMismatch    = errors.New("proton: key mismatch")
	errProtonUidMismatch    = errors.New("proton: uid mismatch")
	errProtonUserIDMismatch = errors.New("proton: userid mismatch")
	errProtonCredsMismatch  = errors.New("proton: creds mismatch")
)

const (
	maxProtonLogicalsRefreshThreshold = 72 * time.Hour
	maxPerRegionWgConfs               = 3
	maxRegisterCertTries              = 3
)

type apiStatus int

const (
	outcomeOK apiStatus = iota
	outcomeErr
	outcomeTryAnew
)

func (o apiStatus) ok() bool {
	return o == outcomeOK
}

func (o apiStatus) tryNew() bool {
	return o == outcomeTryAnew
}

func (o apiStatus) String() string {
	switch o {
	case outcomeOK:
		return "ok"
	case outcomeErr:
		return "err"
	case outcomeTryAnew:
		return "anew"
	default:
		return "unknown"
	}
}

// mostly ... for tests
const usePrebuiltLogicalsOnly = false

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
	Code         int32    `json:"Code"`
	Error        string   `json:"Error"`
	Details      string   `json:"Details"`
	AccessToken  string   `json:"AccessToken"`
	RefreshToken string   `json:"RefreshToken"`
	TokenType    string   `json:"TokenType"`
	Scopes       []string `json:"Scopes"`
	UID          string   `json:"UID"`
	LocalID      int32    `json:"LocalID"`
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
	DeviceName           int64    `json:"deviceName"`
	RegionCode           string   `json:"regionCode"`
	TimezoneOffset       int32    `json:"timezoneOffset"`
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
//
// or:
//
//	{
//		"Code":2011,
//		"Error":"Session already tied to a user",
//		"Details":{}
//	}
type ProtonCredentialResponse struct {
	Code         int32    `json:"Code"`
	Error        string   `json:"Error"`
	Details      string   `json:"Details"`
	UID          string   `json:"UID"`
	UserID       string   `json:"UserID"`
	LocalID      int32    `json:"LocalID"`
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
//
// or:
//
//	{
//	    "Code":10013,
//	    "Error:"Invalid refresh token",
//	    "Details":{}
//	}
type ProtonRefreshResponse struct {
	Code           int32    `json:"Code"`
	Error          string   `json:"Error"`
	AccessToken    string   `json:"AccessToken"`
	RefreshToken   string   `json:"RefreshToken"`
	ExpiresIn      int64    `json:"ExpiresIn"`
	TokenType      string   `json:"TokenType"`
	Scopes         []string `json:"Scopes"`
	UID            string   `json:"UID"`
	LocalID        int32    `json:"LocalID"`
	RefreshCounter int32    `json:"RefreshCounter"`
}

// github.com/ProtonVPN/android-app/blob/2eb1c4c960a/app/src/main/java/com/protonvpn/android/api/ProtonApiRetroFit.kt#L134
//
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

// github.com/ProtonVPN/android-app/blob/2eb1c4c960a/app/src/main/java/com/protonvpn/android/models/vpn/CertificateResponse.kt#L26
//
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
	Code                 int64    `json:"Code"`
	Error                string   `json:"Error"`
	Details              string   `json:"Details"`
	SerialNumber         string   `json:"SerialNumber"`
	ClientKeyFingerprint string   `json:"ClientKeyFingerprint"`
	ClientKey            string   `json:"ClientKey"`
	Certificate          string   `json:"Certificate"`
	ExpirationTime       int64    `json:"ExpirationTime"` // 24 hours
	RefreshTime          int64    `json:"RefreshTime"`    // 18 hours
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
	Tier         int32   `json:"Tier"`
	Features     int32   `json:"Features"`
	Region       string  `json:"Region"`
	City         string  `json:"City"`
	Score        float64 `json:"Score"`
	HostCountry  string  `json:"HostCountry"`
	Organization string  `json:"OrganizationID"`
	VPNGatewayID string  `json:"VPNGatewayID"`
	ID           string  `json:"ID"`
	Load         int32   `json:"Load"`
	Status       int32   `json:"Status"`

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
	Load               int32  `json:"Load"`
	IPv6               bool   `json:"IPv6"`
	EntryIP            string `json:"EntryIP"`
	ExitIP             string `json:"ExitIP"`
	Domain             string `json:"Domain"`
	ID                 string `json:"ID"`
	Label              string `json:"Label"`
	X25519PublicKey    string `json:"X25519PublicKey"`
	Generation         int32  `json:"Generation"`
	Status             int32  `json:"Status"`
	ServicesDown       int32  `json:"ServicesDown"`
	ServicesDownReason string `json:"ServicesDownReason"`
}

// github.com/ProtonVPN/android-app/blob/b9c6e59de40/app/src/main/java/com/protonvpn/android/models/vpn/Server.kt#L56-L58
func (s *ProtonServer) online() bool {
	return s.Status == 1
}

func (s *ProtonServer) ipv6() bool {
	return s.IPv6
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

func (s *ProtonLogicals) ipv6() bool {
	return s.Features&protonFeatureIPv6 == protonFeatureIPv6
}

type ProtonWgConfig struct {
	Ed25519PrivBase64 string `json:"Ed25519PrivateKey"`

	UID                 string `json:"UID"`
	SessionAccessToken  string `json:"SessionAccessToken"`
	SessionRefreshToken string `json:"SessionRefreshToken"`
	SessionExpTime      int64  `json:"SessionExpTime"`

	UserID            string `json:"UserID"`
	CredsAccessToken  string `json:"UserAccessToken"`
	CredsRefreshToken string `json:"UserRefreshToken"`
	CredsExpTime      int64  `json:"UserExpTime"`

	CertSerialNumber string `json:"CertSerialNumber"`
	CertExpTime      int64  `json:"CertExpTime"`
	CertRefreshTime  int64  `json:"CertRefreshTime"`

	CreateTimestamp int64             `json:"CreateTimestamp"`
	RegionalWgConfs []*RegionalWgConf `json:"RegionalWgConfs"`
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
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(id)
}

type ProtonClient struct {
	RpnMultiCountry

	http *http.Client
	key  ProtonKey

	servers map[string][]ProtonServer // country => endpoints

	sess struct { // unauthenticated
		uid            string
		accessToken    string
		refreshToken   string
		expirationTime int64 // unix secs
	}
	creds struct { // authenticated
		userid         string
		accessToken    string
		refreshToken   string
		expirationTime int64 // unix secs
	}
	cert struct {
		serialNumber   string
		expirationTime int64 // unix secs
		refreshTime    int64 // unix secs
	}

	// external / exported config
	configExt *ProtonWgConfig
}

func newProtonGw(k ProtonKey, logicals []ProtonLogicals, h2 *http.Client) (*ProtonClient, error) {
	if k == nil || len(logicals) <= 0 || h2 == nil {
		return nil, errInvalidProtonGwArgs
	}

	publicKeyPem := k.PublicKeyPKIXPem()
	if len(publicKeyPem) > 16 {
		publicKeyPem = publicKeyPem[6:16]
	}

	m := protonServersByCountry(logicals)

	a := &ProtonClient{
		http:    h2,
		key:     k,
		servers: m, // may be empty
		sess: struct {
			uid            string
			accessToken    string
			refreshToken   string
			expirationTime int64
		}{},
		creds: struct {
			userid         string
			accessToken    string
			refreshToken   string
			expirationTime int64
		}{},
		configExt: nil,
	}

	log.I("proton: gw: new: %s / %d", publicKeyPem, len(m))

	return a, nil
}

func (a *ProtonClient) refreshWgConfig() error {
	pc := a.configExt
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
	if pc.CertSerialNumber != a.cert.serialNumber {
		log.W("proton: refresh: serial number mismatch conf(%s) != struct(%s)",
			pc.CertSerialNumber, a.cert.serialNumber)
		// expect it to be the same when the key is the same
	}
	// wg info
	for _, r := range pc.RegionalWgConfs {
		r.genWgConf()
	}
	return nil // ok
}

func (a *ProtonClient) newConf() error {
	a.configExt = nil // reset

	pc := new(ProtonWgConfig)

	wgkey := a.key.ToX25519()
	clientPrivKey := wgkey.Base64().V()
	clientPubKey := wgkey.Mult().Base64().V()

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
				// github.com/ProtonVPN/android-app/blob/b9c6e59de40/app/src/main/java/com/protonvpn/android/models/vpn/ConnectionParamsWireguard.kt#L96
				wc.AllowedIPs = []string{gw4}

				if s.ipv6() {
					wc.ClientAddr6 = protonClientAddr6
					wc.ClientDNS6 = protonDNSAddr6
					wc.AllowedIPs = append(wc.AllowedIPs, gw6)
				}

				rwgConfs = append(rwgConfs, wc)

				log.VV("proton: genconf: %s n:%d, l:%d; x: %s@%s; p: %s@%s",
					s.Name, n, s.Load, wc.ClientAddr4, wc.ClientPubKey[:6], wc.ServerIPPort4, wc.ServerPubKey[:6])
			}
		}
	}

	if len(rwgConfs) < 6 {
		return errNoProtonServerInfo
	}

	// reverse of restoreConfigFrom()

	// key
	pc.Ed25519PrivBase64 = a.key.PrivateKeyBase64()
	// session info
	pc.UID = a.sess.uid
	pc.SessionAccessToken = a.sess.accessToken
	pc.SessionRefreshToken = a.sess.refreshToken
	pc.SessionExpTime = a.sess.expirationTime
	// creds info
	pc.UserID = a.creds.userid
	pc.CredsAccessToken = a.creds.accessToken
	pc.CredsRefreshToken = a.creds.refreshToken
	pc.CredsExpTime = a.creds.expirationTime
	// cert info
	pc.CertSerialNumber = a.cert.serialNumber
	pc.CertExpTime = a.cert.expirationTime
	pc.CertRefreshTime = a.cert.refreshTime
	// wg info; similar: refreshWgConfig
	for _, c := range rwgConfs {
		c.genWgConf()
	}
	pc.RegionalWgConfs = rwgConfs

	pc.CreateTimestamp = time.Now().Unix()

	// top-level config
	a.configExt = pc

	return nil // success
}

// refresh and register are the same api call:
// github.com/ProtonVPN/android-app/blob/2eb1c4c960a/app/src/main/java/com/protonvpn/android/vpn/CertificateRepository.kt#L183
func (a *ProtonClient) registerCert() (apiStatus, error) {
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
		log.W("proton: regcert: json malformed: %v", err)
		return outcomeTryAnew, err
	}
	req, err := http.NewRequest("POST", a.certUrl(), bytes.NewReader(payloadJson))
	if err != nil {
		return outcomeErr, err
	}
	protonHeaders(req)
	a.addRegistrationHeaders(req)

	res, err := a.http.Do(req)
	if err != nil || res == nil {
		return outcomeErr, core.OneErr(err, errNoApiResponse)
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusUnauthorized && tries <= maxRegisterCertTries {
		outcome, err := a.refreshCreds()
		if err == nil {
			log.I("proton: regcert: retrying after creds refresh try# %d", tries)
			goto retryAfterRefresh
		} else {
			log.E("proton: regcert: fail: try# %d, creds refresh status(%d/%s); outcome? %s; err: %v",
				tries, res.StatusCode, res.Status, outcome, err)
			return outcome, err
		}
	}

	var certResponse ProtonCertResponse
	certResponseBytes, certErr := io.ReadAll(res.Body)
	if certErr == nil {
		certErr = json.Unmarshal(certResponseBytes, &certResponse)
	}

	if res.StatusCode != http.StatusOK {
		log.E("proton: regcert: fail: status(%d/%s) hdrs(%v) body(%s) err(%v)",
			res.StatusCode, res.Status, res.Header, string(certResponseBytes), certErr)
		return outcomeTryAnew, core.JoinErr(fmt.Errorf("proton: regcert: err status(%d/%d/%s)",
			res.StatusCode, certResponse.Code, certResponse.Error), certErr)
	}

	if certErr != nil {
		log.E("proton: regcert: read/unmarshal: %v", certErr)
		return outcomeTryAnew, certErr
	}

	if certResponse.Code != 1000 {
		log.E("proton: regcert: code: %d / raw: %s", certResponse.Code, string(certResponseBytes))
		// TODO: refresh with refresh-token
		return outcomeTryAnew, fmt.Errorf("proton: regcert: err %d: %s", certResponse.Code, certResponse.Error)
	}
	// TODO: certResponse.ClientPublicKey == a.key.PublicKeyPKIXPem()

	extupdated := false
	a.cert.serialNumber = certResponse.SerialNumber
	a.cert.expirationTime = certResponse.ExpirationTime
	a.cert.refreshTime = certResponse.RefreshTime
	if pc := a.configExt; pc != nil {
		extupdated = true
		pc.CertSerialNumber = a.cert.serialNumber
		pc.CertExpTime = a.cert.expirationTime
		pc.CertRefreshTime = a.cert.refreshTime
	}

	refreshAt := time.Unix(int64(a.cert.refreshTime), 0)

	log.I("proton: regcert: success (updated ext? %t): serial(%s): next refresh(%s)",
		extupdated, certResponse.SerialNumber, refreshAt.Format(time.RFC1123))

	return outcomeOK, nil
}

func (a *ProtonClient) refresh() (apiStatus, error) {
	outcome, err := a.rereg(true)
	if !outcome.ok() || err != nil {
		return outcome, err
	}

	err = a.refreshServers()
	if err != nil {
		return outcomeErr, err
	}

	return outcomeOK, a.refreshWgConfig()
}

func (a *ProtonClient) fetchCreds() error {
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

	var credResponse ProtonCredentialResponse
	credResponseBytes, credsErr := io.ReadAll(res.Body)
	if credsErr == nil {
		credsErr = json.Unmarshal(credResponseBytes, &credResponse)
	}

	if res.StatusCode != http.StatusOK {
		log.E("proton: creds: fail: status(%d/%s) hdrs(%v) body(%s) err(%v)",
			res.StatusCode, res.Status, res.Header, string(credResponseBytes), credsErr)
		return core.JoinErr(fmt.Errorf("proton: creds: err status(%d/%d/%s)",
			res.StatusCode, credResponse.Code, credResponse.Error), credsErr)
	}

	if credsErr != nil {
		log.E("proton: creds: read/unmarshal: %v", credsErr)
		return credsErr
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
	a.creds.expirationTime = dayFromNow().Unix()
	// members of a.creds are assigned to a.config by "newConf()"

	return nil
}

func (a *ProtonClient) beginSession() error {
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

	var sessionResponse ProtonLoginResponse
	sessionResponseBytes, sessionErr := io.ReadAll(res.Body)
	if sessionErr == nil {
		sessionErr = json.Unmarshal(sessionResponseBytes, &sessionResponse)
	}

	if res.StatusCode != http.StatusOK {
		log.E("proton: session: fail: status(%d/%s) hdrs(%v) body(%s) err(%v)",
			res.StatusCode, res.Status, res.Header, string(sessionResponseBytes), sessionErr)
		return core.JoinErr(fmt.Errorf("proton: session: err status(%d/%d/%s)",
			res.StatusCode, sessionResponse.Code, sessionResponse.Error), sessionErr)
	}

	if sessionErr != nil {
		log.E("proton: session: read/unmarshal: %v", sessionErr)
		return sessionErr
	}

	if sessionResponse.Code != 1000 {
		log.E("proton: session: code: %d / raw: %s", sessionResponse.Code, string(sessionResponseBytes))
		// TODO: refresh with refresh-token
		return fmt.Errorf("proton: session: err %d: %s", sessionResponse.Code, sessionResponse.Error)
	}

	a.sess.uid = sessionResponse.UID
	a.sess.accessToken = sessionResponse.AccessToken
	a.sess.refreshToken = sessionResponse.RefreshToken
	a.sess.expirationTime = dayFromNow().Unix()

	return nil
}

func (a *ProtonClient) refreshCreds() (apiStatus, error) {
	if len(a.sess.uid) <= 0 {
		return outcomeTryAnew, errNoProtonConfig
	}
	/*
		see: github.com/ProtonMail/protoncore_android/blob/c3598ea9e72/auth/data/src/main/kotlin/me/proton/core/auth/data/repository/AuthRepositoryImpl.kt#L189
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
	// refresh unauthenticated (loginless) session
	unauthenticatedPayload := ProtonRefreshRequest{
		UID:          a.sess.uid,
		RefreshToken: a.sess.refreshToken,
		ResponseType: "token",
		GrantType:    "refresh_token",
		RedirectURI:  "http://protonmail.ch",
	}
	// refresh authenticated (credentials) session
	authenticatedPayload := ProtonRefreshRequest{
		UID:          a.sess.uid, // same as a.creds.userid
		RefreshToken: a.creds.refreshToken,
		ResponseType: "token",
		GrantType:    "refresh_token",
		RedirectURI:  "http://protonmail.ch",
	}

	for what, payload := range []ProtonRefreshRequest{unauthenticatedPayload, authenticatedPayload} {
		payloadJson, err := json.Marshal(payload)
		if err != nil {
			log.E("proton: refreshcreds: #%d marshal: %v", what, err)
			return outcomeTryAnew, err
		}
		req, err := http.NewRequest("POST", a.refreshTokensUrl(), bytes.NewReader(payloadJson))
		if err != nil {
			log.E("proton: refreshcreds: #%d newreq: %v", what, err)
			return outcomeErr, err
		}
		protonHeaders(req)

		res, err := a.http.Do(req)
		if err != nil || res == nil {
			return outcomeErr, core.OneErr(err, errNoApiResponse)
		}
		defer res.Body.Close()

		var refResponse ProtonRefreshResponse
		refreshCredResponseBytes, refreshErr := io.ReadAll(res.Body)
		if refreshErr != nil {
			// todo: outcome to be set to TryAnew instead of Err (see below)?
			refreshErr = json.Unmarshal(refreshCredResponseBytes, &refResponse)
		}

		// E proxies.go:1217>>proton.go:1376>>proton.go:1241>>proton.go:1073: proton: refreshcreds: #0 fail: status(400/400 Bad Request)
		if res.StatusCode != http.StatusOK {
			log.E("proton: refreshcreds: #%d fail: status(%d/%s) hdrs(%v) body(%s) err(%v)",
				what, res.StatusCode, res.Status, res.Header, string(refreshCredResponseBytes), refreshErr)
			return outcomeTryAnew, core.JoinErr(fmt.Errorf("proton: refreshcreds: #%d err status(%d/%d/%s)",
				what, res.StatusCode, refResponse.Code, refResponse.Error), refreshErr)
		}

		if refreshErr != nil {
			log.E("proton: refreshcreds: #%d read/unmarshal: %v", what, refreshErr)
			return outcomeErr, err
		}

		if refResponse.Code != 1000 {
			log.E("proton: refreshcreds: #%d code: %d / raw: %s",
				what, refResponse.Code, string(refreshCredResponseBytes))
			// TODO: refresh with refresh-token
			return outcomeTryAnew, fmt.Errorf("proton: refreshcreds: #%d err %d: %s",
				what, refResponse.Code, refResponse.Error)
		}
		// todo: refreshCredResponse.UID == a.sess.uid
		// todo: refreshCredResponse.Scopes contains "vpn"
		// todo: refreshCredResponse.TokenType == "Bearer"

		expiry := elapsedFromNow(refResponse.ExpiresIn, time.Second)
		extupdated := false
		switch what {
		case 0: // unauthenticated creds
			a.sess.accessToken = refResponse.AccessToken
			a.sess.refreshToken = refResponse.RefreshToken
			a.sess.expirationTime = expiry.Unix()
			// always equal? a.sess.uid = refreshCredResponse.UID
			if pc := a.configExt; pc != nil {
				extupdated = true
				pc.SessionAccessToken = a.sess.accessToken
				pc.SessionRefreshToken = a.sess.refreshToken
				pc.SessionExpTime = a.sess.expirationTime
			}
		case 1: // authenticated creds
			a.creds.accessToken = refResponse.AccessToken
			a.creds.refreshToken = refResponse.RefreshToken
			a.creds.expirationTime = expiry.Unix()
			// always equal? a.creds.userid = refreshCredResponse.UID
			if pc := a.configExt; pc != nil {
				extupdated = true
				pc.CredsAccessToken = a.creds.accessToken
				pc.CredsRefreshToken = a.creds.refreshToken
				pc.CredsExpTime = a.creds.expirationTime
			}
		}

		log.I("proton: refreshcreds: #%d ok (updated ext? %t); new access+refresh tokens #%d until %s",
			what, extupdated, refResponse.RefreshCounter, expiry.Format(time.Stamp))
	}

	return outcomeOK, nil
}

func (a *ProtonClient) sessionUrl() string {
	return protonBaseUrl + sessionV4UrlPath
}

func (a *ProtonClient) refreshTokensUrl() string {
	return protonBaseUrl + refreshV4UrlPath
}

func (a *ProtonClient) credsUrl() string {
	return protonBaseUrl + credsV4UrlPath
}

func (a *ProtonClient) certUrl() string {
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

func (a *ProtonClient) addSessionHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+a.sess.accessToken)
	req.Header.Set("x-pm-uid", a.sess.uid)
}

func (a *ProtonClient) addRegistrationHeaders(req *http.Request) {
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

func (a *ProtonClient) reg() error {
	log.I("proton: reg")

	err := a.beginSession()
	if err != nil {
		return err
	}

	err = a.fetchCreds()
	if err != nil {
		return err
	}

	_, err = a.registerCert()
	if err != nil {
		// todo: on outcomeTryAnew; retry
		return err
	}

	return a.newConf()
}

func (a *ProtonClient) refreshServers() error {
	if usePrebuiltLogicalsOnly {
		log.I("proton: refresh servers: no-op; only prebuilts")
		return nil
	}

	const nofile = ""

	oldEnough := time.Since(protonLogicalsUpdateTime) > maxProtonLogicalsRefreshThreshold
	missingConfig := a.configExt == nil || len(a.configExt.RegionalWgConfs) <= 0
	if oldEnough || missingConfig {
		t := protonLogicalsUpdateTime.Format(time.RFC1123)
		log.I("proton: refresh servers; old(%s)? %t / missing? %t", oldEnough, t, missingConfig)
		a.servers = protonServersByCountry(protonServersFrom(nofile, a.http))
	}

	return nil
}

func (a *ProtonClient) rereg(force bool) (apiStatus, error) {
	hasConf := a.configExt != nil
	hasSess := len(a.sess.uid) > 0

	if !hasConf || !hasSess {
		log.W("proton: re-reg: session? %t; config? %t; new reg...",
			hasSess, hasConf)
		return outcomeTryAnew, errNoProtonConfig
	}

	now := time.Now().Unix()
	certage := a.cert.refreshTime - now
	sessage := a.sess.expirationTime - now
	credsage := a.creds.expirationTime - now
	certok := certage > 0
	sessok := sessage > 0
	credsok := credsage > 0
	log.I("proton: re-reg %s [%s]; cert(age: %s / exp? %t), sess(age: %s / exp? %t), creds (age: %s / exp? %t), force? %t",
		a.Who(), a.cert.serialNumber, core.FmtSecs(certage), !certok, core.FmtSecs(sessage), !sessok, core.FmtSecs(credsage), !credsok, force)

	if !force && certok && sessok && credsok {
		return outcomeOK, nil
	}

	outcome, err := a.refreshCreds() // new access tokens + refreshed certs
	if !outcome.ok() {
		log.I("proton: re-reg: failed; do a new reg")
		return outcome, err
	}

	if err != nil {
		return outcome, err
	}

	return a.registerCert() // re-register
}

// Who implements x.RpnAcc.
func (a *ProtonClient) Who() *x.Gostr {
	if a == nil {
		return nil
	}
	return x.StrOf(a.sess.uid)
}

// ProviderID implements RpnAcc.
func (*ProtonClient) ProviderID() string { return x.RpnPro }

// State implements x.RpnAcc.
func (a *ProtonClient) State() (*x.Gobyte, error) {
	return x.BytesOfFunc(a.configExt.Json)
}

// Created implements x.RpnAcc.
func (a *ProtonClient) Created() int64 {
	cfg := a.configExt
	if cfg == nil {
		return 0
	}
	createdAt := time.Unix(int64(cfg.CreateTimestamp), 0)
	return createdAt.UnixMilli()
}

// Expires implements x.RpnAcc.
func (a *ProtonClient) Expires() int64 {
	cfg := a.configExt
	if cfg == nil {
		return 0
	}

	z := min(cfg.CertRefreshTime, cfg.CredsExpTime, cfg.SessionExpTime)
	// github.com/ProtonVPN/android-app/blob/b9c6e59de40/app/src/main/java/com/protonvpn/android/vpn/CertificateRepository.kt#L183-L188
	refreshAt := time.Unix(z, 0)

	return refreshAt.UnixMilli()
}

// Update implements x.RpnAcc.
func (a *ProtonClient) Update() (newstate *x.Gobyte, err error) {
	outcome, err := a.refresh()
	if err != nil {
		// todo: on outcomeTryAnew; retry
		log.W("proton: update: re-reg failed %s %v", outcome, err)
		return nil, err
	}
	return x.BytesOfFunc(a.configExt.Json)
}

// Conf implements RpnAcc.
func (a *ProtonClient) Conf(cc string) (string, error) {
	cfg := a.configExt
	if cfg == nil {
		return "", errNoProtonConfig
	}
	tot := 0
	c := 0
	out := make([]string, 0, maxPerRegionWgConfs)
	for _, rc := range cfg.RegionalWgConfs {
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

func (w *BaseClient) MakeProtonWg(allServersFilePath string) (*ProtonClient, error) {
	k, err := newProtonKeyPair()
	if err != nil {
		return nil, err
	}

	svcs := protonServersFrom(allServersFilePath, &w.h2)
	a, err := newProtonGw(k, svcs, &w.h2)
	if err != nil {
		return nil, err
	}

	err = a.reg()
	if err != nil {
		return nil, err
	}

	return a, nil
}

func (w *BaseClient) MakeProtonWgFrom(existingConfigJson []byte, allServersFilePath string) (*ProtonClient, error) {
	if len(existingConfigJson) <= 0 {
		return nil, errNoProtonJsonConfig
	}

	var existingConf ProtonWgConfig
	err := json.Unmarshal(existingConfigJson, &existingConf)
	if err != nil {
		return nil, err
	}

	if len(existingConf.Ed25519PrivBase64) <= 0 {
		return nil, errNoProtonClientInfo
	}

	k, err := newProtonKeyPairFrom(existingConf.Ed25519PrivBase64)
	if err != nil {
		return nil, err
	}

	svcs := protonServersPrebuilt() // refreshed if needed later
	a, err := newProtonGw(k, svcs, &w.h2)
	if err != nil {
		return nil, err
	}

	err = a.restoreConfigFrom(&existingConf)
	if err != nil {
		return nil, err
	}

	outcome, err := a.rereg(false)
	if outcome.tryNew() {
		log.I("proton: restore: failed %s %v; making new...", outcome, err)
		return w.MakeProtonWg(allServersFilePath)
	}
	if err != nil {
		return nil, err
	}

	err = a.refreshServers()
	if err != nil {
		return nil, err
	}

	err = a.refreshWgConfig()
	if err != nil {
		return nil, err
	}

	log.I("proton: restored config for %s; from: %s until: %s",
		a.Who(), fmtUnixMillis(a.Created()), fmtUnixMillis(a.Expires()))

	return a, nil
}

func (a *ProtonClient) restoreConfigFrom(conf *ProtonWgConfig) error {
	// top-level config
	a.configExt = conf

	// session info
	a.sess.uid = conf.UID
	a.sess.accessToken = conf.SessionAccessToken
	a.sess.refreshToken = conf.SessionRefreshToken
	a.sess.expirationTime = conf.SessionExpTime
	// creds info
	a.creds.userid = conf.UserID
	a.creds.accessToken = conf.CredsAccessToken
	a.creds.refreshToken = conf.CredsRefreshToken
	a.creds.expirationTime = conf.CredsExpTime
	// cert info
	a.cert.serialNumber = conf.CertSerialNumber
	a.cert.expirationTime = conf.CertExpTime
	a.cert.refreshTime = conf.CertRefreshTime

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
		for i := range x.Servers {
			x.Servers[i].Load = x.Load
			x.Servers[i].Name = x.Name
			x.Servers[i].IPv6 = x.ipv6()
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
// go.dev/play/p/YbhTb6xBwKg
func protonServersFrom(allServersFilePath string, c *http.Client) []ProtonLogicals {
	var all ProtonServerResponse

	prebuilts := protonServersPrebuilt()

	if usePrebuiltLogicalsOnly {
		log.I("proton: servers: using prebuilt servers only")
		return prebuilts
	}

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
						} // may be preloaded all.R
					} // json unmarshaled
				} // file read
			} // file stats
		} // file opened
	} // else: no file

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
							} // else: no file
							protonLogicalsUpdateTime = time.Now()
						} // json may be persisted
					} // json unmarshaled
				} // body read
			} // res ok
		} // req ok
	} // else: preloaded
	return append(all.R, prebuilts...)
}

func elapsedFromNow(until int64, kind time.Duration) time.Time {
	return time.Now().Add(kind * time.Duration(until))
}

func dayFromNow() time.Time {
	return elapsedFromNow(24, time.Hour)
}
