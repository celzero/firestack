// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"time"

	"github.com/celzero/firestack/intra/log"
	"github.com/cloudflare/circl/blindsign"
	"github.com/cloudflare/circl/blindsign/blindrsa"
)

const delim = ":"

// "pip-v0-golang-circl-msg-rsa-pss-384" 35 bytes
var fixedmsg []byte = []byte{
	112, 105, 112, 45, 118, 48, 45, 103, 111, 108, 97, 110, 103, 45, 99, 105, 114, 99, 108, 45, 109, 115, 103, 45, 114, 115, 97, 45, 112, 115, 115, 45, 51, 56, 52,
}

type (
	Message []byte
)

type PipKey interface {
	// Generates blindMsg:blindingFactor:salt
	Blind() (string, error)
	// Returns msg:sig for a finalized blind-signature
	Finalize(blindSig string) string
}

//	{
//	  kty: "RSA",
//	  alg: "PS384",
//	  n: "lSFviqAqSHpPOtVgm7...",
//	  e: "AQAB",
//	  key_ops: [ "verify" ],
//	  ext: true
//	}
type pubKeyJwk struct {
	Kty    string   `json:"kty"`           // key type: RSA
	Alg    string   `json:"alg,omitempty"` // algorithm: PS384
	N      string   `json:"n"`             // modulus
	E      string   `json:"e"`             // exponent
	KeyOps []string `json:"key_ops"`       // key operations: verify
	Ext    bool     `json:"ext"`           // extractable: true
}

type pipkey struct {
	pubkey      *rsa.PublicKey
	rsavp1      *blindrsa.RSAVerifier
	rsavp1state blindsign.VerifierState
	blindMsg    []byte
	hasher      crypto.Hash
	when        time.Time
}

func NewPipKey(pubjwk string, existingState string) (PipKey, error) {
	jwk := &pubKeyJwk{}
	pubbytes := []byte(pubjwk)
	json.Unmarshal(pubbytes, jwk)
	// base64 decode modulus and exponent into a big.Int
	n, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	bn := big.NewInt(0)
	bn.SetBytes(n)
	e, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}
	be := big.NewInt(0)
	be.SetBytes(e)
	// create rsa.PublicKey
	pub := &rsa.PublicKey{
		N: bn,
		E: int(be.Int64()),
	}
	hfn := crypto.SHA384
	v := blindrsa.NewRSAVerifier(pub, hfn)
	k := &pipkey{
		pubkey: pub,
		rsavp1: &v,
		hasher: hfn,
		when:   time.Now(),
	}
	if existingState != "" {
		// blindMsg + delim + r + delim + salt
		parts := strings.Split(existingState, delim)
		k.blindMsg = hex2byte(parts[0])
		r := hex2byte(parts[1])
		salt := hex2byte(parts[2])
		if bmsg, state, err := k.rsavp1.FixedBlind(fixedmsg, r, salt); err != nil {
			return nil, err
		} else {
			k.rsavp1state = state
			if !bytes.Equal(k.blindMsg, bmsg) {
				return nil, blindrsa.ErrInvalidBlind
			}
		}
	}
	return k, nil
}

func (k *pipkey) Blind() (string, error) {
	if k.rsavp1state != nil {
		log.E("pipkey: blind: already blinded")
		return "", blindrsa.ErrInvalidBlind
	}
	blindMsg, verifierState, err := k.rsavp1.Blind(rand.Reader, fixedmsg)
	if err != nil {
		log.E("pipkey: blind: %v", err)
		return "", err
	}
	r := verifierState.CopyBlind()
	salt := verifierState.CopySalt()
	return byte2hex(blindMsg) + delim + byte2hex(r) + delim + byte2hex(salt), nil
}

func (k *pipkey) Finalize(blindSig string) string {
	blindsigbytes := hex2byte(blindSig)
	sigbytes, err := k.rsavp1state.Finalize(blindsigbytes)
	if err != nil {
		log.E("pipkey: finalize: %v", err)
		return ""
	}
	err = k.rsavp1.Verify(fixedmsg, sigbytes)
	if err != nil {
		log.E("pipkey: verify: %v", err)
		return ""
	}
	return byte2hex(fixedmsg) + delim + byte2hex(sigbytes)
}
