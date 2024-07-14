// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     Copyright 2016 Michal Witkowski. All Rights Reserved.

package h1

import "encoding/base64"

// code adopted from: github.com/mwitkow/go-http-dialer/blob/378f744fb2/auth.go#L1

const (
	hdrProxyAuthResp = "Proxy-Authorization"
	hdrProxyAuthReq  = "Proxy-Authenticate"
)

// ProxyAuthorization allows for plugging in arbitrary implementations of the "Proxy-Authorization" handler.
type ProxyAuthorization interface {
	// Type represents what kind of Authorization, e.g. "Bearer", "Token", "Digest".
	Type() string

	// Initial allows you to specify an a-priori "Proxy-Authenticate" response header, attached to first request,
	// so you don't need to wait for an additional challenge. If empty string is returned, "Proxy-Authenticate"
	// header is added.
	InitialResponse() string

	// ChallengeResponse returns the content of the "Proxy-Authenticate" response header, that has been chose as
	// response to "Proxy-Authorization" request header challenge.
	ChallengeResponse(challenge string) string
}

type basicAuth struct {
	username string
	password string
}

// AuthBasic returns a ProxyAuthorization that implements "Basic" protocol while ignoring realm challenges.
func AuthBasic(username string, password string) *basicAuth {
	return &basicAuth{username: username, password: password}
}

func (b *basicAuth) Type() string {
	return "Basic"
}

func (b *basicAuth) InitialResponse() string {
	return b.authString()
}

func (b *basicAuth) ChallengeResponse(challenge string) string {
	// challenge can be realm="proxy.com"
	// TODO(mwitkow): Implement realm lookup in AuthBasicWithRealm.
	return b.authString()
}

func (b *basicAuth) authString() string {
	resp := b.username + ":" + b.password
	return base64.StdEncoding.EncodeToString([]byte(resp))
}
