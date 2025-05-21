// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//    SPDX-License-Identifier: MIT

// from: github.com/bepass-org/warp-plus/blob/19ac233cc/warp/api.go

package warp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/celzero/firestack/intra/log"
)

var (
	errNoWgKey       = errors.New("warp: no wg key")
	errNoDialer      = errors.New("warp: no dialer")
	errNoApiResponse = errors.New("ipn: no api response")
	errNoApiData     = errors.New("warp: no api data")
	errZeroIdentity  = errors.New("warp: identity content empty")
	errZeroPeers     = errors.New("warp: no peers")
	errZeroRandomEp  = errors.New("warp: zero random endpoint")
)

/*
	{
		id: '033d94a3-b301-44c8-a184-c374f0444fc2',
		account_type: 'free',
		created: '2023-03-23T21:45:59.470290884Z',
		updated: '2023-03-23T21:45:59.470290884Z',
		premium_data: 0,
		quota: 0,
		usage: 0,
		warp_plus: true,
		referral_count: 0,
		referral_renewal_countdown: 0,
		role: 'child',
		license: 'dB0Z9S52-2d7rK60b-Y39JT8w6'
	}
*/
type IdentityAccount struct {
	Created                  string `json:"created"`
	Updated                  string `json:"updated"`
	License                  string `json:"license"`
	PremiumData              int64  `json:"premium_data"`
	WarpPlus                 bool   `json:"warp_plus"`
	AccountType              string `json:"account_type"`
	ReferralRenewalCountdown int64  `json:"referral_renewal_countdown"`
	Role                     string `json:"role"`
	ID                       string `json:"id"`
	Quota                    int64  `json:"quota"`
	Usage                    int64  `json:"usage"`
	ReferralCount            int64  `json:"referral_count"`
	TTL                      string `json:"ttl"`
}

type IdentityConfigPeerEndpoint struct {
	V4    string   `json:"v4"`
	V6    string   `json:"v6"`
	Host  string   `json:"host"`
	Ports []uint16 `json:"ports"`
}

type IdentityConfigPeer struct {
	PublicKey string                     `json:"public_key"`
	Endpoint  IdentityConfigPeerEndpoint `json:"endpoint"`
}

type IdentityConfigInterfaceAddresses struct {
	V4 string `json:"v4"`
	V6 string `json:"v6"`
}

type IdentityConfigInterface struct {
	Addresses IdentityConfigInterfaceAddresses `json:"addresses"`
}
type IdentityConfigServices struct {
	HTTPProxy string `json:"http_proxy"`
}

/*
	{
		client_id: 'GH58',
		peers: [ [Object] ],
		interface: { addresses: [Object] },
		services: { http_proxy: '172.16.0.1:2480' }
	}
*/
type IdentityConfig struct {
	Peers     []IdentityConfigPeer    `json:"peers"`
	Interface IdentityConfigInterface `json:"interface"`
	Services  IdentityConfigServices  `json:"services"`
	ClientID  string                  `json:"client_id"`
}

/*
	{
	  id: '2ae0dbd9-30b0-4542-a5fa-4cbea46d2f7e',
	  type: 'a',
	  model: 'Xiaomi POCO X2',
	  name: '',
	  key: '0Vr/JZDAve8q+kmNVmiw4KdKiXc//M0EGOY6K9C11nw=',
	  account: { ... },
	  config: { ... },
	  token: '291d3fd8-ed35-41c4-bc71-ea045718d4e4',
	  warp_enabled: true,
	  waitlist_enabled: false,
	  created: '2023-03-23T21:45:58.993726274Z',
	  updated: '2023-03-23T21:45:58.993726274Z',
	  tos: '2023-03-23T21:45:58.692+08:00',
	  place: 0,
	  locale: 'en-US',
	  enabled: true,
	  install_id: '0ulb6zzst99',
	  fcm_token: '0ulb6zzst99:APA91bjkjrid9a0rc3l19z8s9wgip3h5kam6oy1ew1ppld1arpv0xysk0wqtavcpr9gwtaj90yc873om8kwa0359gnphhr5349y9ggasp6e6sj56mjyxtfxa4ygf0vfydhj445x2g54z'
	}

# OR

	{
	  result: null,
	  success: false,
	  errors: [ { code: 1001, message: 'Invalid public key' } ],
	  messages: []
	}
*/
type Identity struct {
	PrivateKey      string          `json:"private_key"`
	Key             string          `json:"key"`
	Account         IdentityAccount `json:"account"`
	Place           int64           `json:"place"`
	FCMToken        string          `json:"fcm_token"`
	Name            string          `json:"name"`
	TOS             string          `json:"tos"`
	Locale          string          `json:"locale"`
	InstallID       string          `json:"install_id"`
	WarpEnabled     bool            `json:"warp_enabled"`
	Type            string          `json:"type"`
	Model           string          `json:"model"`
	Config          IdentityConfig  `json:"config"`
	Token           string          `json:"token"` // authToken
	Enabled         bool            `json:"enabled"`
	ID              string          `json:"id"` // deviceID
	Created         string          `json:"created"`
	Updated         string          `json:"updated"`
	WaitlistEnabled bool            `json:"waitlist_enabled"`

	Result   string   `json:"result"`
	Success  bool     `json:"success"`
	Errors   []string `json:"errors"`
	Messages []string `json:"messages"`

	// generated
	WgConf     string `json:"wgconf"`
	UapiWgConf string `json:"uapiwgconf"`
}

type IdentityDevice struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Model     string `json:"model"`
	Created   string `json:"created"`
	Activated string `json:"updated"`
	Active    bool   `json:"active"`
	Role      string `json:"role"`
}

type License struct {
	License string `json:"license"`
}

type bytewriter struct {
	b []byte
}

var _ io.WriteCloser = (*bytewriter)(nil)

func (w *bytewriter) Write(p []byte) (n int, err error) {
	w.b = append(w.b, p...)
	return len(p), nil
}

func (w *bytewriter) Close() error {
	w.b = nil
	return nil
}

func (w *bytewriter) Bytes() []byte {
	return w.b
}

func (id *Identity) Json() ([]byte, error) {
	if id == nil || len(id.ID) <= 0 {
		return nil, errZeroIdentity
	}

	var w bytewriter
	if err := id.writeJson(&w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

func (id *Identity) writeJson(w io.Writer) error {
	if id == nil || len(id.ID) <= 0 {
		return errZeroIdentity
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(id)
}

// Expires returns the time when the identity expires.
// Fixed at 22 hours from the time of creation.
func (id *Identity) Expires() (zz time.Time) {
	if id == nil {
		return
	}

	if t := id.Since(); t.IsZero() {
		return
	} else {
		return t.Add(twentyTwoHours)
	}
}

func (id *Identity) Since() (zz time.Time) {
	if id == nil {
		return
	}

	// go.dev/play/p/I2SYDu_8bOx
	// created: "2023-03-23T21:45:58.993726274Z"
	t, err := time.Parse(time.RFC3339Nano, id.Created)
	if err != nil {
		return
	}

	return t
}

func (id *Identity) genWgConf() {
	if id == nil || len(id.Config.Peers) < 1 {
		return
	}

	id.WgConf = fmt.Sprintf(`[Interface]
PrivateKey = %s
PublicKey = %s
ClientID = %s
Address = %s
Address = %s
DNS = %s
DNS = %s
[Peer]
PublicKey = %s
Endpoint = %s
Endpoint = %s
Endpoint = %s
AllowedIPs = %s
AllowedIPs = %s`,
		id.PrivateKey,
		id.Key,
		id.Config.ClientID,
		id.Config.Interface.Addresses.V4,
		id.Config.Interface.Addresses.V6,
		cfdns4,
		cfdns6,
		id.Config.Peers[0].PublicKey,
		id.Config.Peers[0].Endpoint.V4,
		id.Config.Peers[0].Endpoint.V6,
		id.Config.Peers[0].Endpoint.Host,
		gw4,
		gw6,
	)

	// github.com/WireGuard/wireguard-android/blob/4ba87947ae/tunnel/src/main/java/com/wireguard/config/Config.java#L179
	// github.com/WireGuard/wireguard-android/blob/4ba87947ae/tunnel/src/main/java/com/wireguard/config/Interface.java#L257
	// not added: listen_port, persistent_keepalive_interval, preshared_key
	id.UapiWgConf = fmt.Sprintf(`private_key=%s
replace_peers=true
client_id=%s
address=%s,%s
dns=%s,%s
mtu=(auto)
public_key=%s
allowed_ip=%s
allowed_ip=%s
endpoint=%s
endpoint=%s
endpoint=%s`,
		toHex(id.PrivateKey),
		id.Config.ClientID,
		id.Config.Interface.Addresses.V4, id.Config.Interface.Addresses.V6,
		cfdns4, cfdns6,
		toHex(id.Key),
		gw4,
		gw6,
		id.Config.Peers[0].Endpoint.V4,
		id.Config.Peers[0].Endpoint.V6,
		id.Config.Peers[0].Endpoint.Host)
}

func Load(b []byte) (Identity, error) {
	var id Identity
	err := json.Unmarshal(b, &id)
	if err != nil {
		return Identity{}, err
	}

	p := len(id.Config.Peers)
	if p < 1 {
		return Identity{}, errZeroPeers
	}
	log.I("warp: loaded %s (peers: %d)", id.Key, p)
	return id, nil
}
