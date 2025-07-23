// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package warp

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
)

var (
	errNoAgwConfig        = errors.New("agw: no config")
	errInvalidRsaKey      = errors.New("agw: invalid RSA key")
	errInvalidRsaPubKey   = errors.New("agw: invalid RSA public key")
	errInvalidPKCSPadding = errors.New("agw: invalid padding size")
	errInvalidPKCSData    = errors.New("agw: invalid padding data")
	errAesCipherLen       = errors.New("agw: len(ciphertext) != x*blockSize")
)

var (
	twentyFourHoursInMillis = (24 * time.Hour).Milliseconds()
	twelveHoursInSecs       = int64((12 * time.Hour).Seconds())
	twentyTwoHours          = 22 * time.Hour
)

const (
	prod = true

	agwAlwaysAllowAllIPs = true

	agwDevUrl          = "http://gw.dev.amzsvc.com/v1/config"
	agwProdUrl         = "http://gw.amnezia.org/v1/config"
	agwDevRsaPublicKey = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwMJbYlGxn3l+0XiGA9I/
BHK8HX/aet7A9GVL817apDUeL6sdISRBdopv5Y0FdrBHSJWSUdWtVxVazJB46J8x
327/5H5pi0nkfRbcgxBGSGxhKOvwRe+WPVb2f81jlkenZK46c9C7dNmX/310rlHY
BwOnZcdw2oKu6hTNDwk3nyUo2v2/leNIMLsv84RlHAX6Tyx5slq8ysewhcmdfv17
WQjF7albq12ZafTSjtXqDcsrk2oF8mfyzxLjSXbxQHKIDHkfz3SUXCs/H9tt1ydK
2Yj6nIxv98HESZ8Ng40OZPhHDex8Ru1NjcWlo2EWNM1xT8IqmBT21PLuyzGjNSwG
Ojnm1V2EcjerVmRNhFTJG70RkURD/i2MDbG+ZKpqPtW1uL8wEt2IkSqNfKcf+TF+
UJZZfm1lDUMpWJ2eWJGrgOUX8/f8v/GB+x4PxUo1m7V/pDLqCUPm3l2dkaM9P0sM
6lO0+jKqfIFnG1zjc3if7r1YbDsZlyl389q9Hrh7t+Lwj/JXkDxFaTnudM8egaXk
GX5YxZiEDmCCLRskRwBBUaYffXIpFbI8sO2Xj0J5/im5xtu7TtfJktcPzDL9uyG1
Ebt8oSA4FTzTid6Zwj55YgDfz0FMnNmXh80T1xMzlbi6y+BCuna+I+7McMRo8yz3
VzzYJ0/J7PpHpXoZv7K1qDsCAwEAAQ==
-----END PUBLIC KEY-----`
	agwProdRsaPublicKey = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAj5mxl/4DL3Sk89ntxs5G
X3JawGQWIoq6rvNkOzNGuNgedNS2+pi6hZl3Izl1Io9om4KiUlMT6mgLO1hTr9q+
s7CYhlvroFA7ErucF+9L+7FCt0Igi0kIK/R2/vxd/2HaUrorn/aSvvutkYwbfxqW
SwtzE+RuBeDWGvEt937OW0oqYONPYv9E4T56Dz/EZ6v2t8ejAnKLbGD/GocMmipK
7etFSiSMAB2RmaztqTq4NleBepfO80XpYlW9pCSXuHcE8wxHczkzxsbyMAMsG/K3
vUQY6qPtohqqzSSBwa/8u2ptNHBeor7l7DdYXeR/Nqcc4z92VUkZ5lOVR4evkS5V
/wQqp5tnOJEj3NjUhEhXFoNEapbZd1bh6iQoUk7jC1TdvKJ/nPKGZAsHRpr0rNKz
fx/N/Oo6lr2yh/+ps6VxTkbPmB6E85WOO3UvjImZUY0XQdBjWle/4iJLdEC77Nr0
jXhdgeypucy6jkB6iBHMeVMlrNMEV7UxoBR/cCNx55zu/8sml5ByiDvCDT7sRomN
NgVt5S/FaVjYuzFUifJ12ToChXFgESKFmuso7WluEaWvMIGREdrMrKQKHfYLOzWF
2B5ZJDqw4o03fU4J/6rw61M1b+rjVpXMjPnzc2A+RgcjTvXv955gfZkwe4lt5wk/
3j8zMVo3+zLrMTAaEeIUM0UCAwEAAQ==
-----END PUBLIC KEY-----`

	agwCountryCode = "ru"
	agwService     = "amnezia-free"
	agwOs          = "android"
	agwVersion     = "4.0.8"
)

type agwuser struct {
	wgpriv, wgpub string // base64 wgkey
	uuid          string // v4
}

type AgwClient struct {
	RpnCountryless
	RpnUpdateless
	*agwuser
	*AmzWgConfig  // may be nil
	http          *http.Client
	key, iv, salt []byte
	rsaPub        *rsa.PublicKey
	btoa          *base64.Encoding
}

type AmzRegResponse struct {
	Config      string `json:"config"`
	ServiceInfo struct {
		Name      string `json:"name"`
		Price     string `json:"price"`
		Region    string `json:"region"`
		Speed     string `json:"speed"`
		Timelimit string `json:"timelimit"`
	} `json:"service_info"`
}

type AmzContainer struct {
	AWG       AmzWg  `json:"awg"`
	Container string `json:"container"`
}

type AmzWg struct {
	Port           string `json:"port"`
	LastConfig     string `json:"last_config"`
	TransportProto string `json:"transport_proto"`
}

type AmzWgApiConfig struct {
	PublicKey struct {
		ExpiresAt string `json:"expires_at"`
	} `json:"public_key"`
}

type AmzWgData struct {
	DNS1             string         `json:"dns1"`
	DNS2             string         `json:"dns2"`
	HostName         string         `json:"hostName"`
	Containers       []AmzContainer `json:"containers"`
	DefaultContainer string         `json:"defaultContainer"`
	APIConfig        AmzWgApiConfig `json:"api_config"`
}

type AmzWgConfig struct {
	H1            string   `json:"H1"`
	H2            string   `json:"H2"`
	H3            string   `json:"H3"`
	H4            string   `json:"H4"`
	Jc            string   `json:"Jc"`
	Jmax          string   `json:"Jmax"`
	Jmin          string   `json:"Jmin"`
	S1            string   `json:"S1"`
	S2            string   `json:"S2"`
	ClientIP      string   `json:"client_ip"`
	ClientPrivKey string   `json:"client_priv_key"`
	ClientPubKey  string   `json:"client_pub_key"`
	Config        string   `json:"config"`
	HostName      string   `json:"hostName"`
	Port          int      `json:"port"`
	PskKey        string   `json:"psk_key"`
	ServerPubKey  string   `json:"server_pub_key"`
	AllowedIPs    []string `json:"allowed_ips"`

	UUID             string `json:"uuid"`              // from agwc
	ExpiresTimestamp int64  `json:"expires_timestamp"` // gen; seconds since epoch
	CreateTimestamp  int64  `json:"create_timestamp"`  // gen; seconds since epoch

	WgConf     string `json:"wgconf"`     // gen
	UapiWgConf string `json:"uapiwgconf"` // gen
}

func (c *AmzWgConfig) genWgConf() {
	if len(c.AllowedIPs) <= 0 || agwAlwaysAllowAllIPs {
		c.AllowedIPs = []string{gw4, gw6}
	}
	server := net.JoinHostPort(c.HostName, fmt.Sprintf("%d", c.Port))
	c.WgConf = fmt.Sprintf(`[Interface]
PrivateKey = %s
PublicKey = %s
Jc = %s
Jmin = %s
Jmax = %s
S1 = %s
S2 = %s
H1 = %s
H2 = %s
H3 = %s
H4 = %s
Address = %s
DNS = %s
DNS = %s
[Peer]
PresharedKey = %s
PublicKey = %s
Endpoint = %s
AllowedIPs = %s`,
		c.ClientPrivKey, // private key always filled by agw
		c.ClientPubKey,
		c.Jc, c.Jmin, c.Jmax, // unused
		c.S1, c.S2,
		c.H1, c.H2, c.H3, c.H4,
		c.ClientIP,
		cfdns4, quad9dns4,
		c.PskKey,
		c.ServerPubKey,
		server,
		strings.Join(c.AllowedIPs, ", "),
		// ignore PersistentKeepalive
	)
	// github.com/WireGuard/wireguard-go/blob/12269c27/device/uapi.go#L180
	c.UapiWgConf = fmt.Sprintf(`private_key=%s
replace_peers=true
jc=%s
jmin=%s
jmax=%s
s1=%s
s2=%s
h1=%s
h2=%s
h3=%s
h4=%s
address=%s
dns=%s,%s
mtu=(auto)
public_key=%s
endpoint=%s`,
		toHex(c.ClientPrivKey),
		c.Jc, c.Jmin, c.Jmax,
		c.S1, c.S2,
		c.H1, c.H2, c.H3, c.H4,
		c.ClientIP,
		cfdns4, quad9dns4,
		toHex(c.ServerPubKey),
		server)
	if len(c.PskKey) > 0 {
		c.UapiWgConf += "\npreshared_key=" + toHex(c.PskKey)
	}
	for _, ip := range c.AllowedIPs {
		c.UapiWgConf += fmt.Sprintf("\nallowed_ip=%s", ip)
	}
}

func (c *AmzWgConfig) writeJson(w io.Writer) error {
	if c == nil {
		return errNoAgwConfig
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(c)
}

func (c *AmzWgConfig) Json() ([]byte, error) {
	if c == nil || len(c.Config) <= 0 {
		return nil, errNoAgwConfig
	}

	var w bytewriter
	if err := c.writeJson(&w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

//	{
//		"dns1": "1.0.0.1",
//		"dns2": "1.1.1.1",
//		"hostName": "57.129.41.71",
//		"containers": [
//		  {
//			"awg": {
//			  "port": "40662",
//			  "last_config": "{
//					\"H1\":\"1718369010\",
//					\"H2\":\"1344957375\",
//					\"H3\":\"1450700745\",
//					\"H4\":\"1835213769\",
//					\"Jc\":\"3\",
//					\"Jmax\":\"50\",
//					\"Jmin\":\"10\",
//					\"S1\":\"23\",
//					\"S2\":\"62\",
//					\"client_ip\":\"10.8.16.207/32\",
//					\"client_priv_key\":\"$WIREGUARD_CLIENT_PRIVATE_KEY\",
//					\"client_pub_key\":\"base/64/=\",
//					\"config\":
//						\"[Interface]\\n
//							Address = 10.8.16.207/32\\n
//							DNS = 1.0.0.1, 1.1.1.1\\n
//							PrivateKey = $WIREGUARD_CLIENT_PRIVATE_KEY\\n
//							Jc = 3\\nJmin = 10\\nJmax = 50\\n
//							S1 = 23\\nS2 = 62\\n
//							H1 = 1070000060\\nH2 = 1004900005\\nH3 = 1000000002\\nH4 = 1800003000\\n\\n
//						[Peer]\\n
//							PublicKey = .../+...+...=\\n
//							PresharedKey = base/64/=\\n
//							AllowedIPs = ... csv 1.0.0.1/32, 1.1.1.1/32, 34.117.59.81/32, ... \\n
//							Endpoint = 57.129.41.71:40662\\n
//							PersistentKeepalive = 25\\n
//						\",
//					\"hostName\":\"57.129.41.71\",
//					\"port\":40662,
//					\"psk_key\":\"base/64/=\",
//					\"server_pub_key\":\".../+...+...=\",
//					\"allowed_ips\": [ ... listof 1.0.0.1/32, 1.1.1.1/32, 34.117.59.81/32, ...]
//				}",
//			"transport_proto": "udp"
//			},
//			"container": "amnezia-awg"
//		  }
//		],
//		"defaultContainer": "amnezia-awg",
//		"api_config": {
//		  "public_key": {
//			"expires_at": "2024-11-28 16:08:36.582729+00:00"
//		  }
//		}
//	}
func (a *AgwClient) unravel(decompressedData []byte) (cfgs []AmzWgConfig, expiresTimestamp int64, err error) {
	var data AmzWgData
	err = json.Unmarshal(decompressedData, &data)
	if err != nil {
		return
	}

	uuid, wgpriv := a.uuid, a.wgpriv

	log.VV("agw: %s unravel: data: %v", uuid, data)

	now := time.Now()
	weekFromNow := now.AddDate(0, 0, 7)
	// go.dev/play/p/IypBxD2Yerp
	// expires_at: 2024-11-28 16:08:36.582729+00:00
	expiresAt, err := time.Parse(time.DateTime+"+00:00", data.APIConfig.PublicKey.ExpiresAt)
	if err != nil || expiresAt.IsZero() || now.Sub(expiresAt) > 0 {
		expiresAt = weekFromNow
	}
	expiresTimestamp = expiresAt.Unix()

	cfgs = make([]AmzWgConfig, 0, len(data.Containers))
	var errs error
	for _, container := range data.Containers {
		var lcfg AmzWgConfig
		err := json.Unmarshal([]byte(container.AWG.LastConfig), &lcfg)
		if err != nil {
			errs = core.JoinErr(errs, err)
			log.W("agw: %s unravel: cfg %s err: %v", uuid, container.AWG.LastConfig, err)
			continue
		}
		lcfg.ClientPrivKey = wgpriv
		lcfg.ExpiresTimestamp = expiresTimestamp
		lcfg.CreateTimestamp = now.Unix()
		lcfg.UUID = uuid
		lcfg.genWgConf()
		cfgs = append(cfgs, lcfg)
	}

	if len(cfgs) <= 0 {
		err = core.OneErr(errs, errNoAgwConfig)
	}
	return
}

func (a *AgwClient) qUncompressVpnUri(data []byte) ([]byte, error) {
	acfg := strings.ReplaceAll(string(data), "vpn://", "")

	decodedData, err := base64.URLEncoding.DecodeString(string(acfg))
	if err != nil {
		return nil, fmt.Errorf("agw: err %s decode base64: %w", acfg, err)
	}

	// stackoverflow.com/a/74796072
	// expected decompressed size from the first 4 bytes
	// Create a reader for the compressed data, skipping the first 4 bytes
	reader := bytes.NewReader(decodedData[4:])

	// Create a zlib reader
	zr, err := zlib.NewReader(reader)
	if err != nil {
		return nil, fmt.Errorf("agw: err zlib reader: %w", err)
	}
	defer zr.Close()

	// Read the decompressed data
	var decompressedData bytes.Buffer
	_, err = io.Copy(&decompressedData, zr)
	if err != nil {
		return nil, fmt.Errorf("agw: err decompress data: %w", err)
	}

	return decompressedData.Bytes(), nil
}

func (a *AgwClient) decodeApiResponse(data []byte) ([]byte, error) {
	// {
	// 	"config": "vpn://<base64url>",
	// 	"service_info": {
	// 		"name": "Amnezia Free Dev",
	// 		"price": "free",
	// 		"region": "Russia",
	// 		"speed": "?",
	// 		"timelimit": "0"
	// 	}
	// }
	var cfg AmzRegResponse
	err := json.Unmarshal(data, &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal data %s: %w", data, err)
	}
	decodedData, err := a.qUncompressVpnUri([]byte(cfg.Config))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 %s: %w", cfg.Config, err)
	}

	return decodedData, nil
}

// uuid4 generates a version 4 UUID.
func uuid4() string {
	// A UUID is 16 bytes (128 bits)
	uuid := make([]byte, 16)
	_, err := rand.Read(uuid)
	if err != nil {
		return ""
	}

	// Set the version to 4 (random UUID)
	uuid[6] = (uuid[6] & 0x0F) | 0x40

	// Set the variant to RFC 4122 (variant 1)
	uuid[8] = (uuid[8] & 0x3F) | 0x80

	// Format the UUID as a string
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4],   // time_low
		uuid[4:6],   // time_mid
		uuid[6:8],   // time_hi_and_version
		uuid[8:10],  // clock_seq_hi_and_reserved and clock_seq_low
		uuid[10:16], // node
	)
}

// wrap encrypts data encryption keys in data using RSA public key.
func (a *AgwClient) wrap(data []byte, typ string) ([]byte, error) {
	switch typ {
	case "oeap":
		return rsa.EncryptOAEP(sha512.New(), rand.Reader, a.rsaPub, data, nil)
	default:
		return rsa.EncryptPKCS1v15(rand.Reader, a.rsaPub, data)
	}
}

// type Reg struct {
// 	ConfigVersion float64 `json:"config_version"`
// 	APIEndpoint   string  `json:"api_endpoint"`
// 	Protocol      string  `json:"protocol"`
// 	Name          string  `json:"name"`
// 	Description   string  `json:"description"`
// 	APIKey        string  `json:"api_key"`
// }
// curl https://13.248.139.44/api/v1/request/awg/ -H "Authorization: Api-Key MeEtQSUr.N9c8ap2D5lPk4jlirWqEwuYaZGVtKRpU" -X POST -H "Content-Type: application/json" -d '{ "installation_uuid": "918afb98-594b-4df4-8dac-26c75d8e461b", "public_key": "lysczjfd4BNnvq7QJ2kIN4xNJ4M9zxrZLMMg5Aq6F2k=", "protocol": "awg", "app_version": "4.0.8", "os_version": "android" }'
// func register(s string) {
// "vpn://eyJjb25maWdfdmVyc2lvbiI6IDEuMCwgImFwaV9lbmRwb2ludCI6ICJodHRwczovLzEzLjI0OC4xMzkuNDQvYXBpL3YxL3JlcXVlc3QvYXdnLyIsICJwcm90b2NvbCI6ICJhd2ciLCAibmFtZSI6ICJBbW5lemlhIEZyZWUgUlUiLCAiZGVzY3JpcHRpb24iOiAiQW1uZXppYSBGcmVlIGZvciBSdXNzaWEiLCAiYXBpX2tleSI6ICJNZUV0UVNVci5OOWM4YXAyRDVsUGs0amxpcldxRXd1WWFaR1Z0S1JwVSJ9"
// {"config_version": 1.0, "api_endpoint": "https://13.248.139.44/api/v1/request/awg/", "protocol": "awg", "name": "Amnezia Free RU", "description": "Amnezia Free for Russia", "api_key": "MeEtQSUr.N9c8ap2D5lPk4jlirWqEwuYaZGVtKRpU"}
//	s, _ = strings.CutPrefix(s, "vpn://")
// convert from base64 to string
//	d, _ := base64.URLEncoding.DecodeString(s)
// convert from string to json
//	var r Reg
//	_ = json.Unmarshal(d, &r)
// }

func newAgwc(wgkey x.WgKey, uuid string, c *http.Client) (*AgwClient, error) {
	// uses the first 16 bytes for the iv but send all 32 bytes to the server
	// salt is unused: github.com/amnezia-vpn/QSimpleCrypto/blob/c99b33f0e08b72/src/sources/QBlockCipher.cpp#L78
	key, iv, salt := csprng(32), csprng(32), csprng(8)
	if len(key) != 32 || len(iv) != 32 || len(salt) != 8 {
		return nil, fmt.Errorf("agw: invalid key/iv/salt length: %d/%d/%d", len(key), len(iv), len(salt))
	}

	publicKey := agwDevRsaPublicKey
	if prod {
		publicKey = agwProdRsaPublicKey
	}
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil, errInvalidRsaKey
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errInvalidRsaPubKey
	}

	return &AgwClient{
		agwuser: &agwuser{
			wgpriv: wgkey.Base64().V(),
			wgpub:  wgkey.Mult().Base64().V(),
			uuid:   uuid,
		},
		http:   c,
		key:    key,
		iv:     iv,
		salt:   salt,
		rsaPub: rsaPub,
		// doc.qt.io/qt-6/qbytearray.html#toBase64
		btoa: base64.StdEncoding,
	}, nil
}

func (a *AgwClient) apiPayload() map[string]string {
	return map[string]string{
		"user_country_code": agwCountryCode,
		"installation_uuid": a.uuid,
		"service_type":      agwService,
		"public_key":        a.wgpub,
		"os_version":        agwOs,
		"app_version":       agwVersion,
		// "protocol":          "awg",
		// "server_country_code": "",
		// "auth_data":           "",
	}
}

// encrypt API payload using AES256 CBC; salt is not used
func (a *AgwClient) encryptApiPayload() ([]byte, error) {
	apiPayloadJSON, _ := json.Marshal(a.apiPayload())
	return a.encryptAesBlockCipher(apiPayloadJSON)
}

func toRune(s string) string {
	if prod {
		return s
	}
	r := make([]rune, 0, len(s))
	for i, w := 0, 0; i < len(s); i += w {
		runev, width := utf8.DecodeRuneInString(s[i:])
		r = append(r, runev)
		w = width
	}
	return string(r)
}

func (a *AgwClient) encryptKeyPayload() ([]byte, error) {
	keyb64 := a.btoa.EncodeToString(a.key)
	ivb64 := a.btoa.EncodeToString(a.iv)
	saltb64 := a.btoa.EncodeToString(a.salt)

	keyPayload := map[string]string{
		"aes_key":  toRune(keyb64),
		"aes_iv":   toRune(ivb64),
		"aes_salt": toRune(saltb64),
	}
	keyPayloadJSON, err := json.Marshal(keyPayload)
	if err != nil {
		return nil, err
	}
	return a.wrap(keyPayloadJSON, "pkcsv15")
}

func (a *AgwClient) url() string {
	if prod {
		return agwProdUrl
	}
	return agwDevUrl
}

// Who implements x.RpnAcc.
func (a *AgwClient) Who() *x.Gostr {
	if a == nil {
		return nil
	}
	return x.StrOf(a.uuid)
}

// ProviderID implements RpnAcc.
func (*AgwClient) ProviderID() string { return x.RpnAmz }

// State implements x.RpnAcc.
func (a *AgwClient) State() (*x.Gobyte, error) {
	return x.BytesOfFunc(a.AmzWgConfig.Json)
}

// Created implements x.RpnAcc.
func (a *AgwClient) Created() int64 {
	cfg := a.AmzWgConfig
	if cfg == nil {
		return 0
	}

	dob := time.Unix(cfg.CreateTimestamp, 0)
	if dob.IsZero() { // if unknown, assume it was created 24h before expiry
		return a.Expires() - twentyFourHoursInMillis
	}
	return dob.UnixMilli()
}

// Expires implements x.RpnAcc.
func (a *AgwClient) Expires() int64 {
	cfg := a.AmzWgConfig
	if cfg == nil {
		return 0
	}
	// 12h before expiry
	newAt := time.Unix(cfg.ExpiresTimestamp-twelveHoursInSecs, 0)
	return newAt.UnixMilli()
}

// Conf implements RpnAcc.
func (a *AgwClient) Conf(cc string) (string, error) {
	if len(cc) > 0 {
		log.D("agw: conf: cc %s ignored", cc)
	}
	return a.UapiWgConf, nil
}

// github.com/amnezia-vpn/amnezia-client/blob/8547de82ea9/client/core/controllers/apiController.cpp#L383
func (a *AgwClient) reg() error {
	a.AmzWgConfig = nil // clean slate

	uuid := a.uuid
	encryptedAPIPayload, err := a.encryptApiPayload()
	if err != nil {
		return err
	}
	encryptedKeyPayload, err := a.encryptKeyPayload()
	if err != nil {
		return err
	}

	log.VV("agw: %s reg: len(key) %d, len(api) %d", uuid, len(encryptedKeyPayload), len(encryptedAPIPayload))

	requestBody := map[string]string{
		"api_payload": toRune(a.btoa.EncodeToString(encryptedAPIPayload)),
		"key_payload": toRune(a.btoa.EncodeToString(encryptedKeyPayload)),
	}
	requestBodyJSON, _ := json.Marshal(requestBody)
	req, err := http.NewRequest("POST", a.url(), bytes.NewReader(requestBodyJSON))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := a.http.Do(req)
	if err != nil || resp == nil {
		return core.OneErr(err, errNoApiResponse)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, rerr := io.ReadAll(resp.Body)
		log.E("agw: %s reg: fail: status(%d/%s) hdrs(%v) body(%s) err(%v)",
			uuid, resp.StatusCode, resp.Status, resp.Header, b, rerr)
		return fmt.Errorf("agw: reg: err status(%d/%s)", resp.StatusCode, resp.Status)
	}

	encryptedResponseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.E("agw: %s reg: read body", uuid, err)
		return err
	}

	decryptedResponseBody, err := a.decryptAesBlockCipher(encryptedResponseBody)
	if err != nil {
		log.E("agw: %s reg: unseal", uuid, err)
		return err
	}

	data, err := a.decodeApiResponse(decryptedResponseBody)
	if err != nil {
		log.E("agw: %s reg: decode", uuid, err)
		return err
	}

	cfgs, expires, err := a.unravel(data)
	if err != nil || len(cfgs) <= 0 {
		log.E("agw: %s reg: cfg", uuid, err)
		return core.OneErr(err, errNoAgwConfig)
	}

	first := &cfgs[0]
	first.genWgConf()
	a.AmzWgConfig = first

	log.I("agw: %s reg: got cfgs %d until %s", uuid, len(cfgs), core.FmtUnixEpochAsPeriod(expires))
	return nil
}

// encryptAesBlockCipher encrypts data using AES with a given mode, key, and IV.
func (a *AgwClient) encryptAesBlockCipher(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, fmt.Errorf("agw: err create cipher: %w", err)
	}

	// gist.github.com/yingray/57fdc3264b19
	paddedData := padPKCS7(data, aes.BlockSize)

	ciphertext := make([]byte, len(paddedData))
	mode := cipher.NewCBCEncrypter(block, a.iv[:aes.BlockSize])
	mode.CryptBlocks(ciphertext, paddedData)

	return ciphertext, nil
}

// padPKCS7 pads the input data to be a multiple of the block size using PKCS7 padding.
func padPKCS7(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// decryptAesBlockCipher decrypts data using AES with a given mode, key, and IV.
func (a *AgwClient) decryptAesBlockCipher(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, fmt.Errorf("agw: err create cipher: %w", err)
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errAesCipherLen
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, a.iv[:aes.BlockSize])
	mode.CryptBlocks(plaintext, ciphertext)

	plaintext, err = unpadPKCS7(plaintext, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("agw: err unpad plaintext: %w", err)
	}

	return plaintext, nil
}

// unpadPKCS7 removes PKCS7 padding from the decrypted data.
func unpadPKCS7(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errInvalidPKCSData
	}

	padding := int(data[len(data)-1])
	if padding > blockSize || padding == 0 {
		return nil, errInvalidPKCSPadding
	}

	for _, p := range data[len(data)-padding:] {
		if int(p) != padding {
			return nil, errInvalidPKCSPadding
		}
	}

	return data[:len(data)-padding], nil
}

func (w *BaseClient) MakeAmzWg() (*AgwClient, error) {
	k, err := x.NewWgPrivateKey()
	if err != nil {
		return nil, err
	}

	uuid := uuid4()
	publicKeyBase64 := k.Mult().Base64().V()
	log.I("agw: make: %s", publicKeyBase64)

	a, err := newAgwc(k, uuid, &w.h2)
	if err != nil {
		return nil, err
	}

	err = a.reg()
	if err != nil {
		return nil, err
	}

	return a, nil
}

func (w *BaseClient) MakeAmzWgFrom(existingStateJson []byte) (*AgwClient, error) {
	log.I("agw: make: from: %d", len(existingStateJson))

	var config AmzWgConfig

	if err := json.Unmarshal(existingStateJson, &config); err != nil {
		return nil, err
	}

	if len(config.UUID) <= 0 {
		log.W("agw: make: from: missing uuid; make new")
		return w.MakeAmzWg()
	}

	now := time.Now().Unix()
	if config.ExpiresTimestamp-now <= 0 {
		log.W("agw: make: from: creds expired; make new")
		return w.MakeAmzWg()
	}

	uuid := config.UUID
	wgkey, err := x.NewWgPrivateKeyOf(config.ClientPrivKey)
	if err != nil {
		return nil, err
	}

	a, err := newAgwc(wgkey, uuid, &w.h2)
	if err != nil {
		return nil, err
	}

	config.genWgConf()
	a.AmzWgConfig = &config

	log.I("agw: make: restored for: %s; from: %s until %s",
		a.Who(), fmtUnixMillis(a.Created()), fmtUnixMillis(a.Expires()))

	return a, nil
}

func fmtUnixMillis(ms int64) string {
	return core.FmtUnixMillisAsTimestamp(ms)
}

func fmtTime(t time.Time) string {
	return core.FmtTimeAsPeriod(t)
}
