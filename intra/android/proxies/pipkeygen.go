// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package android

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"time"

	"github.com/celzero/firestack/intra/log"
	"github.com/cloudflare/circl/blindsign"
	"github.com/cloudflare/circl/blindsign/blindrsa"
)

const delim = ":"
const msgsize = 32
const tokensize = 32

type PipKey interface {
	// Generates a 32 byte randomized token (auths dataplane ops)
	Token() string
	// Generates blindMsg:blindingFactor:salt
	Blind() (string, error)
	// Returns msg:sig for a finalized blind-signature
	Finalize(blindSig string) (string, error)
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
	id          []byte // 64 bytes id derived from blindMsg
	msg         []byte // 32 bytes random msg specific to this key
	blindMsg    []byte // 32 bytes blindMsg derived from msg, r, salt
	hasher      crypto.Hash
	when        time.Time
}

func NewPipKey(pubjwk string, msgOrExistingState string) (PipKey, error) {
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
	if msgOrExistingState != "" {
		// blindMsg + delim + r + delim + salt
		parts := strings.Split(msgOrExistingState, delim)
		if len(parts) == 1 {
			// if there's only one part, it's the message
			// todo: check if len(msg bytes) == 32
			k.msg = hex2byte(parts[0])
			return k, nil
		}
		if len(parts) != 5 {
			// if there's more than one part, it's the state
			// and so we at least 4 parts
			return nil, blindrsa.ErrInvalidMessageLength
		}
		k.id = hex2byte(parts[0])
		k.blindMsg = hex2byte(parts[1])
		r := hex2byte(parts[2])
		salt := hex2byte(parts[3])
		k.msg = hex2byte(parts[4])
		if bmsg, state, err := k.rsavp1.FixedBlind(k.msg, r, salt); err != nil {
			return nil, err
		} else {
			k.rsavp1state = state
			if !bytes.Equal(k.blindMsg, bmsg) {
				return nil, blindrsa.ErrInvalidBlind
			}
		}
	} else {
		k.msg = make([]byte, msgsize)
		if _, err := rand.Read(k.msg); err != nil {
			return nil, err
		}
	}
	return k, nil
}

func (k *pipkey) Blind() (string, error) {
	if k.rsavp1state != nil {
		log.E("pipkey: blind: already blinded")
		return "", blindrsa.ErrInvalidBlind
	}

	blindMsg, verifierState, err := k.rsavp1.Blind(rand.Reader, k.msg)
	if err != nil {
		log.E("pipkey: blind: %v", err)
		return "", err
	}

	r := verifierState.CopyBlind()
	salt := verifierState.CopySalt()

	k.blindMsg = blindMsg
	k.id = hmac256(k.blindMsg, k.pubkey.N.Bytes())
	k.rsavp1state = verifierState

	return byte2hex(k.id) +
		delim + byte2hex(blindMsg) +
		delim + byte2hex(r) +
		delim + byte2hex(salt) +
		delim + byte2hex(k.msg), nil
}

func (k *pipkey) Finalize(blindSig string) (msgsighash string, err error) {
	if k.rsavp1state == nil {
		log.E("pipkey: finalize: not blinded")
		err = blindrsa.ErrInvalidBlind
		return
	}
	var sigbytes []byte
	blindsigbytes := hex2byte(blindSig)
	sigbytes, err = k.rsavp1state.Finalize(blindsigbytes)
	if err != nil {
		log.E("pipkey: finalize: %v", err)
		return
	}
	err = k.rsavp1.Verify(k.msg, sigbytes)
	if err != nil {
		log.E("pipkey: verify: %v", err)
		return
	}
	hashedsigbytes := sha256sum(sigbytes)

	msgsighash = byte2hex(k.msg) +
		delim + byte2hex(sigbytes) +
		delim + byte2hex(hashedsigbytes)
	return
}

func (k *pipkey) Token() string {
	nonce := make([]byte, tokensize)
	_, err := rand.Read(nonce)
	if err != nil {
		log.W("pipkey: no token; err: %v", err)
		return ""
	}
	return byte2hex(nonce)
}

func hex2byte(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		log.E("piph2: hex2byte: err %v", err)
	}
	return b
}

func byte2hex(b []byte) string {
	return hex.EncodeToString(b)
}

func sha256sum(m []byte) []byte {
	digest := sha256.Sum256(m)
	return digest[:]
}

func hmac256(m, k []byte) []byte {
	mac := hmac.New(sha256.New, k)
	mac.Write(m)
	return mac.Sum(nil)
}
