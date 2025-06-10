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
	"errors"
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

var (
	errRpnStateless  = errors.New("rpn has no state or config")
	errRpnUpdateless = errors.New("rpn cannot be updated only registered")
)

type RpnAcc interface {
	x.RpnAcc
	ProviderID() string // x.RpnWg, x.RpnPro, x.RpnAmz
	MultiCountry() bool
	Conf(key string) (string, error)
}

var _ RpnAcc = (*AgwClient)(nil)
var _ RpnAcc = (*ProtonClient)(nil)
var _ RpnAcc = (*WarpClient)(nil)

type Client struct {
	d  *protect.RDial
	h2 http.Client
}

var dob = time.Now()
var neverEver = time.Date(5253, time.March, 6, 0, 0, 0, 0, time.UTC)

type RpnForever struct{}

func (RpnForever) Created() int64 { return dob.UnixMilli() }
func (RpnForever) Expires() int64 { return neverEver.UnixMilli() }

type RpnMultiCountry struct{}

func (RpnMultiCountry) MultiCountry() bool { return true }

type RpnCountryless struct{}

func (c RpnCountryless) MultiCountry() bool { return false }

type RpnStateless struct {
	RpnUpdateless
}

func (RpnStateless) State() (*x.Gobyte, error)      { return nil, errRpnStateless }
func (RpnStateless) Conf(cc string) (string, error) { return "", errRpnStateless }

type RpnUpdateless struct{}

func (RpnUpdateless) Update() (*x.Gobyte, error) { return nil, errRpnUpdateless }

type WarpClient struct {
	RpnCountryless
	RpnUpdateless
	*Identity
	k x.WgKey
	h http.Client
	d *protect.RDial
}

func newWarpClient(d *protect.RDial, id *Identity) (wc *WarpClient, err error) {
	if d == nil {
		return nil, errNoDialer
	}

	restoring := false

	var k x.WgKey
	if id == nil || len(id.PrivateKey) <= 0 {
		k, err = x.NewWgPrivateKey()
	} else if len(id.PrivateKey) > 0 {
		restoring = true
		k, err = x.NewWgPrivateKeyOf(id.PrivateKey)
	} else {
		return nil, errNoWgKey
	}

	if err != nil {
		return nil, err
	}

	// if id == nil, reg() creates identity
	wc = &WarpClient{
		k:        k,
		d:        d,
		Identity: id,
	}

	log.I("warp: make: client for %s; new? %t; from: %s until: %s",
		wc.Who(), id == nil, fmtUnixMillis(wc.Created()), fmtUnixMillis(wc.Expires()))

	wc.h.Transport = &http.Transport{
		DialTLSContext: wc.utlsDial,
	}

	if restoring {
		wc.genWgConf()
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

func (w *WarpClient) utlsDial(ctx context.Context, network, addr string) (net.Conn, error) {
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
func (w *WarpClient) GetAcct() error {
	id := w.Identity
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

	for k, v := range warpDefaultHeaders {
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

func (w *WarpClient) reg() error {
	if w.Identity != nil { // registered; call update/get/reset?
		return nil
	}

	reqUrl := fmt.Sprintf("%s/reg", warpApiUrl)
	method := "POST"
	publicKey := w.k.Mult().Base64().V()

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

	for k, v := range warpDefaultHeaders {
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

	w.Identity = &Identity{}
	if err := json.Unmarshal(b, &w.Identity); err != nil { // unlikely
		log.E("warp: reg: unmarshal res %v", err)
		return err
	}

	w.Identity.PrivateKey = w.k.Base64().V()
	w.Identity.genWgConf()

	log.I("warp: reg: successful %s for %s", w.Identity.Created, w.Identity.ID)

	return nil
}

// unused
func (w *WarpClient) ResetLicense() error {
	id := w.Identity
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

	for k, v := range warpDefaultHeaders {
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
func (w *WarpClient) UpdateAcct(license string) error {
	id := w.Identity
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

	for k, v := range warpDefaultHeaders {
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

// Who implements x.RpnAcc.
func (w *WarpClient) Who() *x.Gostr {
	if w == nil {
		return nil
	}
	if id := w.Identity; id != nil {
		return x.StrOf(id.ID)
	}
	return nil
}

// Provider implements RpnAcc.
func (*WarpClient) ProviderID() string { return x.RpnWg }

// State implements x.RpnAcc.
func (w *WarpClient) State() (*x.Gobyte, error) {
	return x.BytesOfFunc(w.Identity.Json)
}

// Created implements x.RpnAcc.
func (w *WarpClient) Created() int64 {
	return w.Identity.Since().UnixMilli()
}

// Expires implements x.RpnAcc.
func (w *WarpClient) Expires() int64 {
	return w.Identity.Expires().UnixMilli()
}

// Conf implements RpnAcc.
func (w *WarpClient) Conf(cc string) (string, error) {
	id := w.Identity
	if id == nil {
		return "", errZeroIdentity
	}
	if len(cc) > 0 {
		log.D("warp: conf: cc %s ignored", cc)
	}
	return id.UapiWgConf, nil
}

// from: github.com/bepass-org/warp-plus/blob/19ac233cc/warp/account.go

func (w *Client) MakeWarp() (*WarpClient, error) {
	wc, err := newWarpClient(w.d, nil)
	if err != nil {
		return nil, err
	}

	err = wc.reg()
	if err != nil {
		return nil, err
	}

	if wc.Identity == nil {
		return nil, errZeroIdentity
	}

	return wc, nil
}

func (w *Client) MakeWarpFrom(existingStateJson []byte) (*WarpClient, error) {
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

	if exp := id.Expires(); exp.IsZero() || exp.Before(time.Now()) {
		log.W("warp: make: expired %s; new warp ...", exp.Format(time.Stamp))
		return w.MakeWarp()
	}

	return newWarpClient(w.d, &id)
}
