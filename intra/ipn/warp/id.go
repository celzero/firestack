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

	"github.com/celzero/firestack/intra/log"
)

var (
	errNoApiResponse = errors.New("warp: no api response")
	errNoApiData     = errors.New("warp: no api data")
	errZeroIdentity  = errors.New("warp: identity content empty")
	errZeroPeers     = errors.New("warp: no peers")
)

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

type IdentityConfig struct {
	Peers     []IdentityConfigPeer    `json:"peers"`
	Interface IdentityConfigInterface `json:"interface"`
	Services  IdentityConfigServices  `json:"services"`
	ClientID  string                  `json:"client_id"`
}

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
	Token           string          `json:"token"`
	Enabled         bool            `json:"enabled"`
	ID              string          `json:"id"`
	Created         string          `json:"created"`
	Updated         string          `json:"updated"`
	WaitlistEnabled bool            `json:"waitlist_enabled"`
	WgConf          string          `json:"wgconf"`
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
	id.genWgConf()
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(id)
}

func (id *Identity) genWgConf() {
	if id == nil || len(id.Config.Peers) < 1 {
		return
	}
	id.WgConf = fmt.Sprintf(`[Interface]
PublicKey = %s
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
		id.Key,
		id.Config.Interface.Addresses.V4,
		id.Config.Interface.Addresses.V6,
		// developers.cloudflare.com/1.1.1.1/ip-addresses/
		"1.1.1.1",
		"2606:4700:4700::1001",
		id.Config.Peers[0].PublicKey,
		id.Config.Peers[0].Endpoint.V4,
		id.Config.Peers[0].Endpoint.V6,
		id.Config.Peers[0].Endpoint.Host,
		"0.0.0.0/0",
		"::/0",
	)
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
