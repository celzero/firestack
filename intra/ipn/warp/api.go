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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
)

type Client struct {
	c http.Client
	d *protect.RDial
}

func NewWarpClient(ctx context.Context, ctl protect.Controller) *Client {
	d := protect.MakeNsRDial("warpclient", ctl)
	w := &Client{
		d: d,
	}
	w.c.Transport = &http.Transport{
		DialTLSContext: w.utlsDial,
	}
	return w
}

func (w *Client) utlsDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ip, err := core.RandomIPFromPrefix(cfip141)
	if err != nil {
		return nil, err
	}
	ipp := netip.AddrPortFrom(ip, uint16(443))
	return dialers.DialWithUTls(w.d, dialers.NewUTLSCfg(host), network, ipp.String())
}

func (w *Client) GetAcct(tok, deviceID string) (IdentityAccount, error) {
	reqUrl := fmt.Sprintf("%s/reg/%s/account", apiBase, deviceID)
	method := "GET"

	req, err := http.NewRequest(method, reqUrl, nil)
	if err != nil {
		return IdentityAccount{}, err
	}

	for k, v := range defaultHeaders {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := w.c.Do(req)
	if err != nil || resp == nil {
		if err == nil {
			err = errNoApiResponse
		}
		return IdentityAccount{}, err
	}
	defer core.Close(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return IdentityAccount{}, fmt.Errorf("API request failed with status: %s", resp.Status)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil || len(b) == 0 {
		if err == nil {
			err = errNoApiData
		}
		return IdentityAccount{}, err
	}

	var ia = IdentityAccount{}
	if err := json.Unmarshal(b, &ia); err != nil {
		return IdentityAccount{}, err
	}

	return ia, nil
}

func (w *Client) reg(publicKey string) (Identity, error) {
	reqUrl := fmt.Sprintf("%s/reg", apiBase)
	method := "POST"

	data := map[string]interface{}{
		"install_id":   "",
		"fcm_token":    "",
		"tos":          time.Now().Format(time.RFC3339Nano),
		"key":          publicKey,
		"type":         "Android",
		"model":        "PC",
		"locale":       "en_US",
		"warp_enabled": true,
	}

	jsonBody, err := json.Marshal(data)
	if err != nil {
		return Identity{}, err
	}

	req, err := http.NewRequest(method, reqUrl, bytes.NewBuffer(jsonBody))
	if err != nil {
		return Identity{}, err
	}

	for k, v := range defaultHeaders {
		req.Header.Set(k, v)
	}

	resp, err := w.c.Do(req)
	if err != nil || resp == nil {
		if err == nil {
			err = errNoApiResponse
		}
		return Identity{}, err
	}
	defer core.Close(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Identity{}, fmt.Errorf("API request failed with status: %s", resp.Status)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil || len(b) == 0 {
		if err == nil {
			err = errNoApiData
		}
		return Identity{}, err
	}

	var id = Identity{}
	if err := json.Unmarshal(b, &id); err != nil {
		return Identity{}, err
	}

	return id, nil
}

func (w *Client) ResetLicense(authToken, deviceID string) (License, error) {
	reqUrl := fmt.Sprintf("%s/reg/%s/account/license", apiBase, deviceID)
	method := "POST"

	req, err := http.NewRequest(method, reqUrl, nil)
	if err != nil {
		return License{}, err
	}

	for k, v := range defaultHeaders {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+authToken)

	resp, err := w.c.Do(req)
	if err != nil || resp == nil {
		if err == nil {
			err = errNoApiResponse
		}
		return License{}, err
	}
	defer core.Close(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return License{}, fmt.Errorf("API request failed with response: %s", resp.Status)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil || len(b) == 0 {
		if err == nil {
			err = errNoApiData
		}
		return License{}, err
	}

	var lc = License{}
	if err := json.Unmarshal(b, &lc); err != nil {
		return License{}, err
	}

	return lc, nil
}

func (w *Client) UpdateAcct(authToken, deviceID, license string) (IdentityAccount, error) {
	reqUrl := fmt.Sprintf("%s/reg/%s/account", apiBase, deviceID)
	method := "PUT"

	jsonBody, err := json.Marshal(map[string]interface{}{"license": license})
	if err != nil {
		return IdentityAccount{}, err
	}

	req, err := http.NewRequest(method, reqUrl, bytes.NewBuffer(jsonBody))
	if err != nil {
		return IdentityAccount{}, err
	}

	for k, v := range defaultHeaders {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+authToken)

	resp, err := w.c.Do(req)
	if err != nil || resp == nil {
		if err == nil {
			err = errNoApiResponse
		}
		return IdentityAccount{}, err
	}
	defer core.Close(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return IdentityAccount{}, fmt.Errorf("API request failed with status: %s", resp.Status)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil || len(b) == 0 {
		if err == nil {
			err = errNoApiData
		}
		return IdentityAccount{}, err
	}

	var ia = IdentityAccount{}
	if err := json.Unmarshal(b, &ia); err != nil {
		return IdentityAccount{}, err
	}

	return ia, nil
}

// from: github.com/bepass-org/warp-plus/blob/19ac233cc/warp/account.go

func (w *Client) Load(id Identity, license string) (*Identity, error) {
	if license != "" && id.Account.License != license {
		log.I("updating account license key")
		_, err := w.UpdateAcct(id.Token, id.ID, license)
		if err != nil {
			return nil, err
		}

		iAcc, err := w.GetAcct(id.Token, id.ID)
		if err != nil {
			return nil, err
		}
		id.Account = iAcc
	}

	log.I("successfully loaded warp identity")
	return &id, nil
}

func (w *Client) Make(pub, license string) (*Identity, error) {
	log.I("creating new identity %s", pub)
	id, err := w.reg(pub)
	if err != nil {
		return nil, err
	}

	if license != "" {
		log.I("updating account license key for %s", pub)
		_, err := w.UpdateAcct(id.Token, id.ID, license)
		if err != nil {
			return nil, err
		}

		ac, err := w.GetAcct(id.Token, id.ID)
		if err != nil {
			return nil, err
		}
		id.Account = ac
	}

	return &id, nil
}
