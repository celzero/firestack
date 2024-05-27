// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package backend

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
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	brsa "github.com/celzero/firestack/intra/core/brsa"
	"github.com/celzero/firestack/intra/log"
	// "github.com/cloudflare/circl/blindsign/blindrsa"
)

const (
	delim      = ":"
	minmsgsize = 32            // min msg size in bytes; >= pipkey.c.prefixLen
	tokensize  = 32            // token size in bytes
	hashfn     = crypto.SHA384 // 48 byte hash fn for RSA-PSS
)

type PipKey interface {
	// Token gnerates a 32 byte randomized token (auths dataplane ops; see: tokensize)
	Token() string
	// Blind generates id:blindMsg:blindingFactor:salt:msg
	// id is a 64 byte hmac tying blindMsg to the public key
	// blindMsg is a 256 byte blinded message
	// blindingFactor is upto 256 byte random blinding factor
	// salt is 48 bytes random salt (see: hashfn)
	// msg is a 32 byte random message (see: msgsize)
	Blind() (string, error)
	// Finalize returns msg:sig for a finalized blind-signature
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
//
// github.com/serverless-proxy/serverless-proxy/blob/5d209e85/src/webcrypto/blindrsa.js#L6-L15
type pubKeyJwk struct {
	Kty    string   `json:"kty"`           // key type: RSA
	Alg    string   `json:"alg,omitempty"` // algorithm: PS384
	N      string   `json:"n"`             // modulus (2048 bits)
	E      string   `json:"e"`             // exponent
	KeyOps []string `json:"key_ops"`       // key operations: verify
	Ext    bool     `json:"ext"`           // extractable: true
}

// pipkey is a struct that implements the PipKey interface.
type pipkey struct {
	pubkey   *rsa.PublicKey
	v        *brsa.Verifier
	state    *brsa.State
	c        *brsa.Client
	id       []byte // 64 bytes id derived from hmac(m=blindMsg, k=pubkey)
	msg      []byte // min 32 bytes random msg specific to this key
	blindMsg []byte // 256 bytes blindMsg derived from msg, r, salt
}

// NewPipKey creates a new PipKey instance.
// pubjwk: JWK string of the public key of the RSA-PSS signer (for which modulus must be 2048 bits, and hash-fn must be SHA384).
// msgOrExistingState: if empty, a new PipKey is created with a random message, if not empty, it's the state of an existing PipKey.
func NewPipKey(pubjwk string, msgOrExistingState string) (PipKey, error) {
	jwk := &pubKeyJwk{}
	pubbytes := []byte(pubjwk)
	err := json.Unmarshal(pubbytes, jwk)
	if err != nil {
		return nil, fmt.Errorf("cannot unmarshal public key: %v", err)
	}
	// base64 decode modulus and exponent into a big.Int
	n, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("cannot decode key modulus: %v", err)
	}
	bn := big.NewInt(0)
	bn.SetBytes(n)
	// base64 decode exponent into an int
	e, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("cannot decode key exponent: %v", err)
	}
	be := big.NewInt(0)
	be.SetBytes(e)
	// create rsa.PublicKey
	pub := &rsa.PublicKey{
		N: bn,
		E: int(be.Int64()),
	}
	// brsa.SHA384PSSDeterministic does not prepend random 32 bytes prefix to k.msg,
	// whilst brsa.SHA384PSSRandomized does. ref: brsa.Prepare() which is unused here.
	c, err1 := brsa.NewClient(brsa.SHA384PSSDeterministic, pub)
	v, err2 := brsa.NewVerifier(brsa.SHA384PSSDeterministic, pub)
	if err1 != nil || err2 != nil {
		err := errors.Join(err1, err2)
		log.E("pipkey: new: sha384-pss-det verifier err %v", err)
		return nil, err
	}
	k := &pipkey{
		pubkey: pub,
		v:      &v,
		c:      &c,
	}
	if msgOrExistingState != "" {
		// id : blindMsg : r : salt : msg
		parts := strings.Split(msgOrExistingState, delim)
		if len(parts) == 1 {
			// if there's only one part, it's the message
			// todo: check if len(msg bytes) == 32
			k.msg = hex2byte(parts[0])
			if len(k.msg) < minmsgsize {
				log.E("pipkey: new: invalid msg size; min %d; got %d", minmsgsize, len(k.msg))
				return nil, brsa.ErrUnexpectedSize
			}
			return k, nil
		}
		if len(parts) != 5 {
			// if there's more than one part, it's the state
			// and so we at least 4 parts
			return nil, brsa.ErrInvalidMessageLength
		}
		k.id = hex2byte(parts[0]) // unique id; hmac(msg, pubkey)
		k.blindMsg = hex2byte(parts[1])
		r := hex2BigInt(parts[2]) // blinding factor
		rInv, err := modInv(r, k.pubkey.N)
		if err != nil {
			log.E("pipkey: new: invalid r/rInv; %v", err)
			return nil, err
		}
		salt := hex2byte(parts[3])
		k.msg = hex2byte(parts[4]) // no need to k.c.Prepare() if SHA384PSSDeterministic
		if bmsg, state, err := k.c.FixedBlind(k.msg, salt, r, rInv); err != nil {
			return nil, err
		} else {
			k.state = &state
			if !bytes.Equal(k.blindMsg, bmsg) { // sanity check
				log.E("pipkey: new: invalid blindMsg")
				return nil, brsa.ErrInvalidBlind
			}
		}
	} else {
		k.msg = make([]byte, minmsgsize)
		// k.c.Prepare() is unused for SHA384PSSDeterministic
		if _, err := io.ReadFull(rand.Reader, k.msg); err != nil {
			log.E("pipkey: new: gen err, %v", err)
			return nil, err
		}
	}
	return k, nil
}

// Implements PipKey.
func (k *pipkey) Blind() (string, error) {
	if k.state != nil {
		log.E("pipkey: blind: already blinded")
		return "", brsa.ErrInvalidBlind
	}

	blindMsg, verifierState, err := k.c.Blind(rand.Reader, k.msg)
	if err != nil {
		log.E("pipkey: blind: %v", err)
		return "", err
	}

	r := verifierState.Factor()
	salt := verifierState.Salt() // nil for SHA384PSSZeroDeterministic/SHA384PSSZeroRandomized

	if r == nil {
		log.E("pipkey: blind: invalid r")
		return "", brsa.ErrInvalidBlind
	}

	k.blindMsg = blindMsg
	k.id = hmac256(k.blindMsg, k.pubkey.N.Bytes()) // must match with server-side impl
	k.state = &verifierState

	// existing state; id : blindMsg : r : salt : msg
	return byte2hex(k.id) +
		delim + byte2hex(blindMsg) +
		delim + bigInt2hex(r) +
		delim + byte2hex(salt) +
		delim + byte2hex(k.msg), nil
}

// Implements PipKey.
func (k *pipkey) Finalize(blindSig string) (msgsighash string, err error) {
	if k.state == nil {
		log.E("pipkey: finalize: not blinded")
		err = brsa.ErrInvalidBlind
		return
	}
	var sigbytes []byte
	// unblind using r and salt
	sigbytes, err = k.c.Finalize(*k.state, hex2byte(blindSig))
	if err != nil {
		log.E("pipkey: finalize: %v", err)
		return
	}
	// verify the unblinded sig using the public key
	err = k.v.Verify(k.msg, sigbytes)
	if err != nil {
		log.E("pipkey: finalize: verify: %v", err)
		return
	}
	hashedsigbytes := sha256sum(sigbytes)

	msgsighash = byte2hex(k.msg) +
		delim + byte2hex(sigbytes) +
		delim + byte2hex(hashedsigbytes)
	return
}

// Implements PipKey.
func (k *pipkey) Token() string {
	nonce := make([]byte, tokensize)
	_, err := rand.Read(nonce)
	if err != nil {
		log.W("pipkey: no token; err: %v", err)
		return ""
	}
	return byte2hex(nonce)
}

// hex2byte returns the byte slice represented by the hex string s.
func hex2byte(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		log.E("piph2: hex2byte: err %v", err)
	}
	return b
}

// byte2hex returns the hex representation of the byte slice b.
func byte2hex(b []byte) string {
	return hex.EncodeToString(b)
}

func hex2BigInt(s string) *big.Int {
	b, err := hex.DecodeString(s)
	if err != nil {
		log.E("piph2: hex2BigInt: err %v", err)
	}
	return new(big.Int).SetBytes(b)
}

func bigInt2hex(b *big.Int) (h string) {
	return hex.EncodeToString(b.Bytes())
}

// sha256sum returns the SHA256 digest (32 byte) of the message m.
func sha256sum(m []byte) []byte {
	digest := sha256.Sum256(m)
	return digest[:]
}

// hmac256 returns the HMAC-SHA256 (32 byte) of the message m using the key k.
func hmac256(m, k []byte) []byte {
	mac := hmac.New(sha256.New, k)
	mac.Write(m)
	return mac.Sum(nil)
}

func modInv(g *big.Int, n *big.Int) (z *big.Int, err error) {
	z = new(big.Int).ModInverse(g, n)
	if z == nil {
		err = brsa.ErrInvalidBlind
	}
	return
}
