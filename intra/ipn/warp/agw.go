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
	"unicode/utf8"

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

const (
	prod = true

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
)

type agwc struct {
	uuid          string
	http          *http.Client
	key, iv, salt []byte
	rsaPub        *rsa.PublicKey
	apiPayload    map[string]string
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
	WgConf        string   `json:"wgconf"` // gen
}

func (c *AmzWgConfig) genWgConf() {
	if len(c.AllowedIPs) <= 0 {
		c.AllowedIPs = []string{"0.0.0.0/0", "::/0"}
	}
	c.WgConf = fmt.Sprintf(`[Interface]
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
		c.ClientPubKey,       // private key to be filled by kt-land
		c.Jc, c.Jmin, c.Jmax, // unused
		c.S1, c.S2,
		c.H1, c.H2, c.H3, c.H4,
		c.ClientIP,
		"1.1.1.1", // developers.cloudflare.com/1.1.1.1/ip-addresses/
		"1.0.0.1",
		c.PskKey,
		c.ServerPubKey,
		net.JoinHostPort(c.HostName, fmt.Sprintf("%d", c.Port)),
		strings.Join(c.AllowedIPs, ", "),
		// ignore PersistentKeepalive
	)
}

func (c *AmzWgConfig) writeJson(w io.Writer) error {
	if c == nil {
		return errNoAgwConfig
	}
	c.genWgConf()
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
func (a *agwc) unravel(decompressedData []byte) ([]AmzWgConfig, error) {
	var data AmzWgData
	err := json.Unmarshal(decompressedData, &data)
	if err != nil {
		return nil, err
	}

	log.VV("agw: %s unravel: data: %v", a.uuid, data)

	cfgs := make([]AmzWgConfig, 0, len(data.Containers))
	var errs error
	for _, container := range data.Containers {
		var lcfg AmzWgConfig
		err := json.Unmarshal([]byte(container.AWG.LastConfig), &lcfg)
		if err != nil {
			errs = core.JoinErr(errs, err)
			log.W("agw: %s unravel: cfg %s err: %v", a.uuid, container.AWG.LastConfig, err)
			continue
		}
		cfgs = append(cfgs, lcfg)
	}

	if len(cfgs) <= 0 {
		return nil, core.OneErr(errs, errNoAgwConfig)
	}
	return cfgs, nil
}

func (a *agwc) qUncompressVpnUri(data []byte) ([]byte, error) {
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

func (a *agwc) decodeApiResponse(data []byte) ([]byte, error) {
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

// prandom generates cryptographically secure prandom bytes of the given length.
func prandom(sz int) ([]byte, error) {
	bytes := make([]byte, sz)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// wrap encrypts data encryption keys in data using RSA public key.
func (a *agwc) wrap(data []byte, typ string) ([]byte, error) {
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

func newAgwc(pubkey string, c *http.Client) (*agwc, error) {
	key, err := prandom(32)
	if err != nil {
		return nil, err
	}
	// use the first 16 bytes for the iv
	// but send all 32 bytes to the server
	iv, err := prandom(32)
	if err != nil {
		return nil, err
	}
	// unused: github.com/amnezia-vpn/QSimpleCrypto/blob/c99b33f0e08b72/src/sources/QBlockCipher.cpp#L78
	salt, err := prandom(8)
	if err != nil {
		return nil, err
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
	uuid, cc, svc, os, ver := uuid4(), "ru", "amnezia-free", "android", "4.0.8"
	apiPayload := map[string]string{
		"user_country_code": cc,
		"installation_uuid": uuid,
		"service_type":      svc,
		"public_key":        pubkey,
		"os_version":        os,
		"app_version":       ver,
		// "protocol":          "awg",
		// "server_country_code": "",
		// "auth_data":           "",
	}
	return &agwc{
		uuid:       uuid,
		http:       c,
		key:        key,
		iv:         iv,
		salt:       salt,
		rsaPub:     rsaPub,
		apiPayload: apiPayload,
		// https://doc.qt.io/qt-6/qbytearray.html#toBase64
		btoa: base64.StdEncoding,
	}, nil
}

// encrypt API payload using AES256 CBC; salt is not used
func (a *agwc) encryptApiPayload() ([]byte, error) {
	apiPayloadJSON, _ := json.Marshal(a.apiPayload)
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

func (a *agwc) encryptKeyPayload() ([]byte, error) {
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

func (a *agwc) url() string {
	if prod {
		return agwProdUrl
	}
	return agwDevUrl
}

// github.com/amnezia-vpn/amnezia-client/blob/8547de82ea9/client/core/controllers/apiController.cpp#L383
func (a *agwc) reg() (*AmzWgConfig, error) {
	encryptedAPIPayload, err := a.encryptApiPayload()
	if err != nil {
		return nil, err
	}
	encryptedKeyPayload, err := a.encryptKeyPayload()
	if err != nil {
		return nil, err
	}

	log.VV("agw: %s reg: len(key) %d, len(api) %d", a.uuid, len(encryptedKeyPayload), len(encryptedAPIPayload))

	requestBody := map[string]string{
		"api_payload": toRune(a.btoa.EncodeToString(encryptedAPIPayload)),
		"key_payload": toRune(a.btoa.EncodeToString(encryptedKeyPayload)),
	}
	requestBodyJSON, _ := json.Marshal(requestBody)
	req, err := http.NewRequest("POST", a.url(), bytes.NewReader(requestBodyJSON))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, rerr := io.ReadAll(resp.Body)
		log.E("agw: %s reg: fail: status(%d/%s) hdrs(%v) body(%s) err(%v)",
			a.uuid, resp.StatusCode, resp.Status, resp.Header, b, rerr)
		return nil, fmt.Errorf("agw: reg: err status(%d/%s)", resp.StatusCode, resp.Status)
	}

	encryptedResponseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.E("agw: %s reg: read body", a.uuid, err)
		return nil, err
	}

	decryptedResponseBody, err := a.decryptAesBlockCipher(encryptedResponseBody)
	if err != nil {
		log.E("agw: %s reg: unseal", a.uuid, err)
		return nil, err
	}

	data, err := a.decodeApiResponse(decryptedResponseBody)
	if err != nil {
		log.E("agw: %s reg: decode", a.uuid, err)
		return nil, err
	}

	cfgs, err := a.unravel(data)
	if err != nil || len(cfgs) <= 0 {
		log.E("agw: %s reg: cfg", a.uuid, err)
		return nil, core.OneErr(err, errNoAgwConfig)
	}

	log.I("agw: %s reg: got cfgs %d", a.uuid, len(cfgs))
	return &cfgs[0], nil
}

// encryptAesBlockCipher encrypts data using AES with a given mode, key, and IV.
func (a *agwc) encryptAesBlockCipher(data []byte) ([]byte, error) {
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
func (a *agwc) decryptAesBlockCipher(ciphertext []byte) ([]byte, error) {
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

func (w *Client) MakeAmzWg(publicKeyBase64 string) (*AmzWgConfig, error) {
	log.I("agw: make: %s", publicKeyBase64)

	a, err := newAgwc(publicKeyBase64, &w.h2)
	if err != nil {
		return nil, err
	}

	return a.reg()
}
