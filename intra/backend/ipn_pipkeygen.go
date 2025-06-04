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
	"sync"

	"github.com/celzero/firestack/intra/core"
	brsa "github.com/celzero/firestack/intra/core/brsa"
	"github.com/celzero/firestack/intra/log"
	// "github.com/cloudflare/circl/blindsign/blindrsa"
)

const (
	delim      = ":"
	minmsgsize = 32            // min msg size in bytes; >= pipkey.c.prefixLen
	tokensize  = 32            // token size in bytes
	bidsize    = 64            // blind id size in bytes; hmac(msg, pubkey)
	blindsize  = 256           // blinded message size in bytes
	hashfn     = crypto.SHA384 // 48 byte hash fn for RSA-PSS

	pipkeyOpaqueCtx = "pipkey-message-opaque" // context for opaque messages
)

var (
	errEmptyPipKeyState = errors.New("pipkey: empty pip key state")
	errTokenCreat       = errors.New("pipkey: cannot create token")
)

type PipKeyProvider interface {
	// Bid uniquely identifies a blinded PipKeyProvider.
	// PipKeyProviders created from same blinded PipKeyState have the same identity.
	// If this PipKeyProvider is not yet blinded, it returns nil.
	Bid() *Gostr
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

// nb: PipToken inherits fields from Gostr but not its methods.

// PipToken is a 32 byte random token for bespoke auth.
type PipToken Gostr

type PipMsg Gostr

func pipmsgof(s string) *PipMsg {
	if len(s) < minmsgsize {
		log.E("pipkey: msgof: invalid msg size; min %d; got %d", minmsgsize, len(s))
		return nil
	}
	// TODO: s must be hex encoded 32 byte string
	return &PipMsg{S: s}
}

func (p *PipMsg) v() string {
	if p == nil {
		return ""
	}
	return p.S
}

// Opaque returns a 32 byte hex derived from the PipMsg.
func (p *PipMsg) Opaque() *Gostr {
	oq := hmac256([]byte(pipkeyOpaqueCtx), hex2byte(p.S))
	return StrOf(byte2hex(oq))
}

type PipKey struct {
	// hex encoded 32 byte msg (random)
	Msg *PipMsg
	// hex encoded 256 byte sig (unblinded signature)
	Sig string
	// hex encoded 32 byte sha256(sig) (msg signature hash)
	SigHash string
}

type PipKeyState struct {
	// hex encoded 64 byte id that identifies BlindMsg.
	Bid string
	// hex encoded 256 byte blind(Msg)
	BlindMsg string
	// hex encoded blinding factor (up to 256 bytes)
	R string
	// hex encoded 48 byte salt (random)
	Salt string
	// hex encoded 32 byte (client) msg (usually, random)
	Msg *PipMsg
}

func newPipKeyState(id, blindMsg, r, salt, msg string) *PipKeyState {
	return &PipKeyState{
		Bid:      id,
		BlindMsg: blindMsg,
		R:        r,
		Salt:     salt,
		Msg:      pipmsgof(msg),
	}
}

func NewPipKeyStateFrom(v *Gostr) (*PipKeyState, error) {
	if v == nil {
		return nil, errEmptyPipKeyState
	}
	state := v.V()
	if len(state) <= 0 {
		return nil, errEmptyPipKeyState
	}

	// id:blindMsg:r:salt:msg
	parts := strings.Split(state, delim)
	if len(parts) == 1 {
		// if there's only one part, it's the message
		return &PipKeyState{
			Msg: pipmsgof(parts[0]),
		}, nil
	} else if len(parts) == 5 {
		return &PipKeyState{
			Bid:      parts[0],
			BlindMsg: parts[1],
			R:        parts[2],
			Salt:     parts[3],
			Msg:      pipmsgof(parts[4]),
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

	if len(p.BlindMsg) != blindsize {
		return p.Msg.v()
	}

	return strings.Join([]string{
		p.Bid,
		p.BlindMsg,
		p.R,
		p.Salt,
		p.Msg.v(),
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
	mu sync.Mutex // protects all fields below

	pubkey *rsa.PublicKey

	v     *brsa.Verifier
	state *brsa.State
	c     *brsa.Client

	id       []byte // 64 bytes id derived from hmac(m=blindMsg, k=pubkey)
	msg      []byte // min 32 bytes random msg specific to this key
	blindMsg []byte // 256 bytes blindMsg derived from msg, r, salt
}

var _ PipKeyProvider = (*pkgen)(nil)

// NewPipKeyProvider creates a new PipKeyProvider instance.
// pubjwk: JWK string of the public key of the RSA-PSS signer (for which modulus must be 2048 bits, and hash-fn must be SHA384).
// msgOrExistingState: if empty, a new PipKeyProvider is created with a random message, if not empty, it's the state of an existing PipKey.
// Typically, msgOrExistingState is got from PipKeyState.V()
func NewPipKeyProvider(pubjwk *Gobyte, msgOrExistingState *Gostr) (PipKeyProvider, error) {
	return newPipKey(pubjwk.V(), msgOrExistingState.V(), false)
}

// NewPipKeyProviderFromMsg creates a new PipKeyProvider instance from a JWK and a msg hex string.
// Generating Blind() for the same msg with the same JWK will NOT result in the same PipKeyState.
// To restore a previous state, use NewPipKeyProvider() with the PipKeyState.V() string.
func NewPipKeyProviderFromMsg(pubjwk *Gobyte, msg *Gostr) (PipKeyProvider, error) {
	return newPipKey(pubjwk.V(), msg.V(), true)
}

func newPipKey(bjwk []byte, msgOrExistingState string, msgOnly bool) (PipKeyProvider, error) {
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
		if msgOnly || len(parts) != 5 {
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

// Bid implements PipKeyProvider.
func (k *pkgen) Bid() *Gostr {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.id == nil {
		log.E("pipkey: who: not blinded")
		return nil
	}

	if len(k.id) != 64 {
		log.E("pipkey: who: invalid id size %d", len(k.id))
		return nil
	}

	return StrOf(byte2hex(k.id))
}

// Blind implements PipKeyProvider.
func (k *pkgen) Blind() (*PipKeyState, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

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

	if len(k.id) != bidsize || len(k.blindMsg) != blindsize || len(r.Bytes()) > 256 || len(salt) != 48 || len(k.msg) != minmsgsize {
		log.E("pipkey: blind: invalid state; id %d, blindMsg %d, r %d, salt %d, msg %d",
			len(k.id), len(k.blindMsg), len(r.Bytes()), len(salt), len(k.msg))
		return nil, brsa.ErrUnexpectedSize
	}

	// existing state; id : blindMsg : r : salt : msg
	return newPipKeyState(
		byte2hex(k.id),
		byte2hex(blindMsg),
		bigInt2hex(r),
		byte2hex(salt),
		byte2hex(k.msg),
	), nil
}

// Finalize implements PipKeyProvider.
func (k *pkgen) Finalize(blindSig *Gostr) (*PipKey, error) {
	return k.finalize(blindSig.V())
}

func (k *pkgen) finalize(blindSig string) (*PipKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

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
		Msg:     pipmsgof(byte2hex(k.msg)),
		Sig:     byte2hex(sigbytes),
		SigHash: byte2hex(hashedsigbytes),
	}, nil
}

// Token gnerates a 32 byte random as hex (auths dataplane ops)
func Token() (*PipToken, error) {
	if tokstr := StrOf(token()); tokstr != nil && tokstr.Len() > 0 {
		tok := PipToken(*tokstr)
		return &tok, nil
	}
	return nil, errTokenCreat
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
