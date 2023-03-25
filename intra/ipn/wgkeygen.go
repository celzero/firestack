// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     SPDX-License-Identifier: MIT
//
//     Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.

package ipn

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// from: github.com/WireGuard/wireguard-windows/blob/dcc0eb72a/conf/parser.go#L121

const klen = 32

type (
	eckey [klen]byte
)

var _ Key = (*eckey)(nil)

type Key interface {
	// IsZero returns true if the key is all zeros.
	IsZero() bool
	// Base64 returns the key as a base64-encoded string.
	Base64() string
	// Mult returns the key multiplied by the basepoint (curve25519).
	Mult() Key
}

func (k *eckey) Base64() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

func (k *eckey) IsZero() bool {
	var zeros eckey
	return subtle.ConstantTimeCompare(zeros[:], k[:]) == 1
}

func (k *eckey) Mult() Key {
	var p [klen]byte
	curve25519.ScalarBaseMult(&p, (*[klen]byte)(k))
	return (*eckey)(&p)
}

func newPresharedKey() (*eckey, error) {
	var k [klen]byte
	_, err := rand.Read(k[:])
	if err != nil {
		return nil, err
	}
	return (*eckey)(&k), nil
}

func NewPrivateKey() (Key, error) {
	k, err := newPresharedKey()
	if err != nil {
		return nil, err
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return k, nil
}

func parseKeyBase64(s string) (*eckey, error) {
	k, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("Invalid key: %v", err)
	}
	if len(k) != klen {
		return nil, errors.New("Keys must decode to exactly 32 bytes")
	}
	var key eckey
	copy(key[:], k)
	return &key, nil
}

func NewPrivateKeyOf(b64 string) (Key, error) {
	return parseKeyBase64(b64)
}
