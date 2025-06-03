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

	"github.com/celzero/firestack/intra/core"
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

var errEmptyPipKeyState = errors.New("pipkey: empty pip key state")

type PipKeyProvider interface {
	// Blind generates id:blindMsg:blindingFactor:salt:msg
	// id is a 64 byte hmac tying blindMsg to the public key
	// blindMsg is a 256 byte blinded message
	// blindingFactor is upto 256 byte random blinding factor
	// salt is 48 bytes random salt (see: hashfn)
	// msg is a 32 byte random message (see: msgsize)
	Blind() (*PipKeyState, error)
	// Finalize calculates actual signature for given blingSig blind signature.
	Finalize(blingSig *Gostr) (*PipKey, error)
}

type PipToken Gostr

type PipKey struct {
	// hex encoded 32 byte msg (random)
	Msg *Gostr
	// hex encoded 256 byte sig (unblinded signature)
	Sig *Gostr
	// hex encoded 32 byte sha256(sig) (msg signature hash)
	Hsig *Gostr
}

type PipKeyState struct {
	// hex encoded 64 byte id, tied to Msg and pubjwk.
	Id *Gostr
	// hex encoded 256 byte blind(Msg)
	BlindMsg *Gostr
	// hex encoded blinding factor (up to 256 bytes)
	R *Gostr
	// hex encoded 48 byte salt (random)
	Salt *Gostr
	// hex encoded 32 byte (client) msg (usually, random)
	Msg *Gostr
}

func newPipKeyState(id, blindMsg, r, salt, msg *Gostr) *PipKeyState {
	return &PipKeyState{
		Id:       id,
		BlindMsg: blindMsg,
		R:        r,
		Salt:     salt,
		Msg:      msg,
	}
}

func NewPipKeyStateFrom(v *Gostr) (*PipKeyState, error) {
	if v == nil {
		return nil, errEmptyPipKeyState
	}
	state := v.V()
	if state == "" {
		return nil, errEmptyPipKeyState
	}

	// id:blindMsg:r:salt:msg
	parts := strings.Split(state, delim)
	if len(parts) == 1 {
		// if there's only one part, it's the message
		return &PipKeyState{
			Msg: StrOf(parts[0]),
		}, nil
	} else if len(parts) == 5 {
		return &PipKeyState{
			Id:       StrOf(parts[0]),
			BlindMsg: StrOf(parts[1]),
			R:        StrOf(parts[2]),
			Salt:     StrOf(parts[3]),
			Msg:      StrOf(parts[4]),
		}, nil

	}

	log.E("pipkey: fromv: expected either 1 or 5 parts, got %d", len(parts))
	return nil, brsa.ErrInvalidMessageLength
}

func (p *PipKeyState) V() *Gostr {
	if p == nil {
		return nil
	}

	return StrOf(p.v())
}

func (p *PipKeyState) v() string {
	if p == nil {
		return ""
	}

	if len(p.BlindMsg.V()) != 256 {
		return p.Msg.V() // may be empty, but that's ok
	}

	return strings.Join([]string{
		p.Id.V(),
		p.BlindMsg.V(),
		p.R.V(),
		p.Salt.V(),
		p.Msg.V(),
	},
		delim,
	)
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

// pkgen is a struct that implements the PipKeyProvider interface.
type pkgen struct {
	pubkey   *rsa.PublicKey
	v        *brsa.Verifier
	state    *brsa.State
	c        *brsa.Client
	id       []byte // 64 bytes id derived from hmac(m=blindMsg, k=pubkey)
	msg      []byte // min 32 bytes random msg specific to this key
	blindMsg []byte // 256 bytes blindMsg derived from msg, r, salt
}

// NewPipKeyProvider creates a new PipKeyProvider instance.
// pubjwk: JWK string of the public key of the RSA-PSS signer (for which modulus must be 2048 bits, and hash-fn must be SHA384).
// msgOrExistingState: if empty, a new PipKeyProvider is created with a random message, if not empty, it's the state of an existing PipKey.
// Typically, msgOrExistingState is got from PipKeyState.V()
func NewPipKeyProvider(pubjwk *Gobyte, msgOrExistingState *Gostr) (PipKeyProvider, error) {
	return newPipKey(pubjwk.V(), msgOrExistingState.V())
}

func newPipKey(bjwk []byte, msgOrExistingState string) (PipKeyProvider, error) {
	jwk := &pubKeyJwk{}
	err := json.Unmarshal(bjwk, jwk)
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
		E: int(be.Int64()), // may overflow on 32-bit
	}
	// brsa.SHA384PSSDeterministic does not prepend random 32 bytes prefix to k.msg,
	// whilst brsa.SHA384PSSRandomized does. ref: brsa.Prepare() which is unused here.
	c, err1 := brsa.NewClient(brsa.SHA384PSSDeterministic, pub)
	v, err2 := brsa.NewVerifier(brsa.SHA384PSSDeterministic, pub)
	if err1 != nil || err2 != nil {
		err := core.JoinErr(err1, err2)
		log.E("pipkey: new: sha384-pss-det verifier err %v", err)
		return nil, err
	}
	k := &pkgen{
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
func (k *pkgen) Blind() (*PipKeyState, error) {
	if k.state != nil {
		log.E("pipkey: blind: already blinded")
		return nil, brsa.ErrInvalidBlind
	}

	blindMsg, verifierState, err := k.c.Blind(rand.Reader, k.msg)
	if err != nil {
		log.E("pipkey: blind: %v", err)
		return nil, err
	}

	r := verifierState.Factor()
	salt := verifierState.Salt() // nil for SHA384PSSZeroDeterministic/SHA384PSSZeroRandomized

	if r == nil {
		log.E("pipkey: blind: invalid r")
		return nil, brsa.ErrInvalidBlind
	}

	k.blindMsg = blindMsg
	k.id = hmac256(k.blindMsg, k.pubkey.N.Bytes()) // must match with server-side impl
	k.state = &verifierState

	if len(k.id) != 64 || len(k.blindMsg) != 256 || len(r.Bytes()) > 256 || len(salt) != 48 || len(k.msg) != 32 {
		log.E("pipkey: blind: invalid state; id %d, blindMsg %d, r %d, salt %d, msg %d",
			len(k.id), len(k.blindMsg), len(r.Bytes()), len(salt), len(k.msg))
		return nil, brsa.ErrUnexpectedSize
	}

	// existing state; id : blindMsg : r : salt : msg
	return newPipKeyState(
		StrOf(byte2hex(k.id)),
		StrOf(byte2hex(blindMsg)),
		StrOf(bigInt2hex(r)),
		StrOf(byte2hex(salt)),
		StrOf(byte2hex(k.msg)),
	), nil
}

// Implements PipKey.
func (k *pkgen) Finalize(blindSig *Gostr) (*PipKey, error) {
	return k.finalize(blindSig.V())
}

func (k *pkgen) finalize(blindSig string) (*PipKey, error) {
	if k.state == nil {
		log.E("pipkey: finalize: not blinded")
		return nil, brsa.ErrInvalidBlind
	}
	var sigbytes []byte
	// unblind using r and salt
	sigbytes, err := k.c.Finalize(*k.state, hex2byte(blindSig))
	if err != nil {
		log.E("pipkey: finalize: %v", err)
		return nil, err
	}
	// verify the unblinded sig using the public key
	err = k.v.Verify(k.msg, sigbytes)
	if err != nil {
		log.E("pipkey: finalize: verify: %v", err)
		return nil, err
	}
	hashedsigbytes := sha256sum(sigbytes)

	return &PipKey{
		Msg:  StrOf(byte2hex(k.msg)),
		Sig:  StrOf(byte2hex(sigbytes)),
		Hsig: StrOf(byte2hex(hashedsigbytes)),
	}, nil
}

// Token gnerates a 32 byte random as hex (auths dataplane ops)
func Token() *PipToken {
	tok := PipToken(*StrOf(token()))
	return &tok
}

func token() string {
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
