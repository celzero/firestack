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

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
)

type Client struct {
	d  *protect.RDial
	h2 http.Client
}

type warpclient struct {
	k  x.WgKey
	h  http.Client
	d  *protect.RDial
	id *Identity
}

func newWarpClient(k x.WgKey, d *protect.RDial, id *Identity) (*warpclient, error) {
	if k == nil || core.IsNil(k) {
		return nil, errNoWgKey
	}
	if d == nil {
		return nil, errNoDialer
	}

	pub := k.Mult().Base64()
	log.I("warp: make: client for %s; new? %t", pub, id == nil)

	// if id == nil, reg() creates identity
	wc := &warpclient{
		k:  k,
		d:  d,
		id: id,
	}

	wc.h.Transport = &http.Transport{
		DialTLSContext: wc.utlsDial,
	}

	return wc, nil
}

func NewExtClient(ctx context.Context, c protect.Controller) *Client {
	d := protect.MakeNsRDial("extclient", ctx, c)
	w := &Client{d: d}
	w.h2.Transport = &http.Transport{
		Dial:                  d.Dial,
		ForceAttemptHTTP2:     true,
		ResponseHeaderTimeout: 15 * time.Second,
		IdleConnTimeout:       30 * time.Second,
	}
	return w
}

func (w *warpclient) utlsDial(ctx context.Context, network, addr string) (net.Conn, error) {
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

// unused
func (w *warpclient) GetAcct() error {
	id := w.id
	if id == nil {
		return errZeroIdentity
	}

	tok := id.Token
	deviceID := id.ID

	reqUrl := fmt.Sprintf("%s/reg/%s/account", warpApiUrl, deviceID)
	method := "GET"

	req, err := http.NewRequest(method, reqUrl, nil)
	if err != nil {
		return err
	}

	for k, v := range defaultHeaders {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := w.h.Do(req)
	if err != nil || resp == nil {
		err = core.OneErr(err, errNoApiResponse)
		return err
	}
	defer core.Close(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("warp: api request failed: %s", resp.Status)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil || len(b) == 0 {
		err = core.OneErr(err, errNoApiData)
		return err
	}

	var ia = IdentityAccount{}
	if err := json.Unmarshal(b, &ia); err != nil {
		return err
	}

	id.Account = ia

	log.I("warp: get acct successful %s @ %s", deviceID, id.Account.ID)

	return nil
}

func (w *warpclient) reg() error {
	if w.id != nil { // registered; call update/get/reset?
		return nil
	}

	reqUrl := fmt.Sprintf("%s/reg", warpApiUrl)
	method := "POST"
	publicKey := w.k.Mult().Base64()

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
	if err != nil { // unlikely
		return err
	}

	req, err := http.NewRequest(method, reqUrl, bytes.NewBuffer(jsonBody))
	if err != nil { // unlikely
		log.E("warp: reg: creating req %v", err)
		return err
	}

	for k, v := range defaultHeaders {
		req.Header.Set(k, v)
	}

	resp, err := w.h.Do(req)
	if err != nil || resp == nil { // unlikely
		err = core.OneErr(err, errNoApiResponse)
		log.E("warp: reg: no res %v", err)
		return err
	}
	defer core.Close(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.E("warp: reg: api err %s %d", resp.Status, resp.StatusCode)
		return fmt.Errorf("warp: api request failed: %s", resp.Status)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil || len(b) == 0 {
		err = core.OneErr(err, errNoApiData)
		log.E("warp: reg: no api data %v", err)
		return err
	}

	w.id = &Identity{}
	if err := json.Unmarshal(b, &w.id); err != nil { // unlikely
		log.E("warp: reg: unmarshal res %v", err)
		return err
	}

	w.id.PrivateKey = w.k.Base64()

	log.I("warp: reg: successful %s for %s", w.id.Created, w.id.ID)

	return nil
}

// unused
func (w *warpclient) ResetLicense() error {
	id := w.id
	if id == nil {
		return errZeroIdentity
	}

	authToken := id.Token
	deviceID := id.ID

	reqUrl := fmt.Sprintf("%s/reg/%s/account/license", warpApiUrl, deviceID)
	method := "POST"

	req, err := http.NewRequest(method, reqUrl, nil)
	if err != nil {
		return err
	}

	for k, v := range defaultHeaders {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+authToken)

	resp, err := w.h.Do(req)
	if err != nil || resp == nil {
		err = core.OneErr(err, errNoApiResponse)
		return err
	}
	defer core.Close(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("warp: api request failed: %s", resp.Status)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil || len(b) == 0 {
		err = core.OneErr(err, errNoApiData)
		return err
	}

	var lc = License{}
	if err := json.Unmarshal(b, &lc); err != nil {
		return err
	}

	id.Account.License = lc.License

	log.I("warp: reset license successful %s @ %s", deviceID, id.Account.ID)

	return nil
}

// unused
func (w *warpclient) UpdateAcct(license string) error {
	id := w.id
	if id == nil {
		return errZeroIdentity
	}

	authToken := id.Token
	deviceID := id.ID
	if len(license) <= 0 || id.Account.License != license {
		license = id.Account.License
	}

	reqUrl := fmt.Sprintf("%s/reg/%s/account", warpApiUrl, deviceID)
	method := "PUT"

	jsonBody, err := json.Marshal(map[string]interface{}{"license": license})
	if err != nil {
		return err
	}

	req, err := http.NewRequest(method, reqUrl, bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}

	for k, v := range defaultHeaders {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+authToken)

	resp, err := w.h.Do(req)
	if err != nil || resp == nil {
		err = core.OneErr(err, errNoApiResponse)
		return err
	}
	defer core.Close(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("warp: api request failed: %s", resp.Status)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil || len(b) == 0 {
		err = core.OneErr(err, errNoApiData)
		return err
	}

	var ia = IdentityAccount{}
	if err := json.Unmarshal(b, &ia); err != nil {
		return err
	}

	id.Account = ia

	log.I("warp: update: successful %s @ %s", deviceID, id.Account.ID)

	return nil
}

// from: github.com/bepass-org/warp-plus/blob/19ac233cc/warp/account.go

func (w *Client) MakeWarp() (*Identity, error) {
	k, err := x.NewWgPrivateKey()
	if err != nil {
		return nil, err
	}

	wc, err := newWarpClient(k, w.d, nil)
	if err != nil {
		return nil, err
	}

	err = wc.reg()
	if err != nil {
		return nil, err
	}

	id := wc.id
	if id == nil {
		return nil, errZeroIdentity
	}

	return id, nil
}

func (w *Client) MakeWarpFrom(existingStateJson []byte) (*Identity, error) {
	var id Identity
	err := json.Unmarshal(existingStateJson, &id)
	if err != nil {
		log.W("warp: make: restore failed %v; new warp ...", err)
		return w.MakeWarp()
	}

	if len(id.ID) <= 0 {
		log.W("warp: make: no device-id %v; new warp ...", err)
		return w.MakeWarp()
	}

	// test key sanity
	_, err = x.NewWgPrivateKeyOf(id.PrivateKey)
	if err != nil {
		log.E("warp: make: restore key failed %v; new warp ...", err)
		return w.MakeWarp()
	}

	return &id, nil
}
