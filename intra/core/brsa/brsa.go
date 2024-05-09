// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//    BSD-3-Clause License
//
//    Copyright (c) 2019 Cloudflare. All rights reserved.
//    Copyright (c) 2009 The Go Authors. All rights reserved.
//    Use of this source code is governed by a BSD-style
//    license that can be found in the LICENSE file.

// from: https://github.com/cloudflare/circl/tree/v1.3.7/blindsign

// Package blindrsa implements the RSA Blind Signature Protocol as defined in [RFC9474].
//
// The RSA Blind Signature protocol, and its variant RSABSSA
// (RSA Blind Signature Scheme with Appendix) is a two-party protocol
// between a Client and Server where they interact to compute
//
//	sig = Sign(sk, input_msg),
//
// where `input_msg = Prepare(msg)` is a prepared version of a private
// message `msg` provided by the Client, and `sk` is the private signing
// key provided by the server.
//
// # Supported Variants
//
// This package is compliant with the [RFC-9474] document
// and supports the following variants:
//   - RSABSSA-SHA384-PSS-Deterministic
//   - RSABSSA-SHA384-PSSZERO-Deterministic
//   - RSABSSA-SHA384-PSS-Randomized
//   - RSABSSA-SHA384-PSSZERO-Randomized
//
// [RFC-9474]: https://www.rfc-editor.org/info/rfc9474
package blindrsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"math/big"
)

type Variant int

const (
	SHA384PSSRandomized    Variant = iota // RSABSSA-SHA384_PSS_Randomized
	SHA384PSSDeterministic                // RSABSSA-SHA384_PSS_Deterministic
)

func (v Variant) String() string {
	switch v {
	case SHA384PSSRandomized, SHA384PSSDeterministic:
		return "RSABSSA-SHA384-PSS-Randomized"
	default:
		return "invalid RSABSSA variant"
	}
}

// Client is a type that implements the client side of the blind RSA
// protocol, described in https://www.rfc-editor.org/rfc/rfc9474.html#name-rsabssa-variants
type Client struct {
	v         Verifier
	prefixLen int
}

func NewClient(v Variant, pk *rsa.PublicKey) (Client, error) {
	verif, err := NewVerifier(v, pk)
	if err != nil {
		return Client{}, err
	}
	var prefixLen int
	switch v {
	case SHA384PSSDeterministic:
		prefixLen = 0
	case SHA384PSSRandomized:
		prefixLen = 32
	default:
		return Client{}, ErrInvalidVariant
	}

	return Client{verif, prefixLen}, nil
}

type State struct {
	// The hashed and encoded message being signed
	encodedMsg []byte
	// Blinding factor produced by the Verifier
	r *big.Int
	// Inverse of the blinding factor produced by the Verifier
	rInv *big.Int
	// Salt used in the encoding of the message
	salt []byte
}

func (s State) Salt() []byte     { return s.salt }
func (s State) Factor() *big.Int { return s.r }

// Prepare is the process by which the message to be signed and
// verified is prepared for input to the blind signing protocol.
func (c Client) Prepare(random io.Reader, message []byte) ([]byte, error) {
	if random == nil {
		return nil, ErrInvalidRandomness
	}

	prefix := make([]byte, c.prefixLen)
	_, err := io.ReadFull(random, prefix)
	if err != nil {
		return nil, err
	}

	return append(append([]byte{}, prefix...), message...), nil
}

// Blind initializes the blind RSA protocol using an input message and source of randomness.
// This function fails if randomness was not provided.
func (c Client) Blind(random io.Reader, preparedMessage []byte) (blindedMsg []byte, state State, err error) {
	if random == nil {
		return nil, State{}, ErrInvalidRandomness
	}

	salt := make([]byte, c.v.SaltLength)
	_, err = io.ReadFull(random, salt)
	if err != nil {
		return nil, State{}, err
	}

	r, rInv, err := GenerateBlindingFactor(random, c.v.pk.N)
	if err != nil {
		return nil, State{}, err
	}

	return c.FixedBlind(preparedMessage, salt, r, rInv)
}

func (c Client) FixedBlind(message, salt []byte, r, rInv *big.Int) (blindedMsg []byte, state State, err error) {
	encodedMsg, err := EncodeMessageEMSAPSS(message, c.v.pk.N, c.v.Hash.New(), salt)
	if err != nil {
		return nil, State{}, err
	}

	m := new(big.Int).SetBytes(encodedMsg)

	bigE := big.NewInt(int64(c.v.pk.E))
	x := new(big.Int).Exp(r, bigE, c.v.pk.N)
	z := new(big.Int).Set(m)
	z.Mul(z, x)
	z.Mod(z, c.v.pk.N)

	kLen := (c.v.pk.N.BitLen() + 7) / 8
	blindedMsg = make([]byte, kLen)
	z.FillBytes(blindedMsg)

	return blindedMsg, State{encodedMsg, r, rInv, salt}, nil
}

func (c Client) Finalize(state State, blindedSig []byte) ([]byte, error) {
	kLen := (c.v.pk.N.BitLen() + 7) / 8
	if len(blindedSig) != kLen {
		return nil, ErrUnexpectedSize
	}

	z := new(big.Int).SetBytes(blindedSig)
	s := new(big.Int).Set(state.rInv)
	s.Mul(s, z)
	s.Mod(s, c.v.pk.N)

	sig := make([]byte, kLen)
	s.FillBytes(sig)

	err := VerifyBlindSignature(NewBigPublicKey(c.v.pk), state.encodedMsg, sig)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// Verify verifies the input (message, signature) pair and produces an error upon failure.
func (c Client) Verify(message, signature []byte) error { return c.v.Verify(message, signature) }

type Verifier struct {
	// Public key of the Signer
	pk *rsa.PublicKey
	rsa.PSSOptions
}

func NewVerifier(v Variant, pk *rsa.PublicKey) (Verifier, error) {
	switch v {
	case SHA384PSSRandomized, SHA384PSSDeterministic:
		return Verifier{pk, rsa.PSSOptions{Hash: crypto.SHA384, SaltLength: crypto.SHA384.Size()}}, nil
	default:
		return Verifier{}, ErrInvalidVariant
	}
}

// Verify verifies the input (message, signature) pair and produces an error upon failure.
func (v Verifier) Verify(message, signature []byte) error {
	return VerifyMessageSignature(message, signature, v.SaltLength, NewBigPublicKey(v.pk), v.Hash)
}

// Signer structure represents the signing server in the blind RSA protocol.
// It carries the raw RSA private key used for signing blinded messages.
type Signer struct {
	// An RSA private key
	sk *rsa.PrivateKey
}

// NewSigner creates a new Signer for the blind RSA protocol using an RSA private key.
func NewSigner(sk *rsa.PrivateKey) Signer {
	return Signer{
		sk: sk,
	}
}

// BlindSign blindly computes the RSA operation using the Signer's private key on the blinded
// message input, if it's of valid length, and returns an error should the function fail.
//
// See the specification for more details:
// https://www.rfc-editor.org/rfc/rfc9474.html#name-blindsign
func (signer Signer) BlindSign(data []byte) ([]byte, error) {
	kLen := (signer.sk.N.BitLen() + 7) / 8
	if len(data) != kLen {
		return nil, ErrUnexpectedSize
	}

	m := new(big.Int).SetBytes(data)
	if m.Cmp(signer.sk.N) > 0 {
		return nil, ErrInvalidMessageLength
	}

	s, err := DecryptAndCheck(rand.Reader, NewBigPrivateKey(signer.sk), m)
	if err != nil {
		return nil, err
	}

	blindSig := make([]byte, kLen)
	s.FillBytes(blindSig)

	return blindSig, nil
}

var (
	// ErrInvalidVariant is the error used if the variant request does not exist.
	ErrInvalidVariant = errors.New("blindsign/blindrsa: invalid variant requested")

	// ErrUnexpectedSize is the error used if the size of a parameter does not match its expected value.
	ErrUnexpectedSize = errors.New("blindsign/blindrsa: unexpected input size")

	// ErrInvalidMessageLength is the error used if the size of a protocol message does not match its expected value.
	ErrInvalidMessageLength = errors.New("blindsign/blindrsa: invalid message length")

	// ErrInvalidBlind is the error used if the blind generated by the Verifier fails.
	ErrInvalidBlind = errors.New("blindsign/blindrsa: invalid blind")

	// ErrInvalidRandomness is the error used if caller did not provide randomness to the Blind() function.
	ErrInvalidRandomness = errors.New("blindsign/blindrsa: invalid random parameter")

	// ErrUnsupportedHashFunction is the error used if the specified hash is not supported.
	ErrUnsupportedHashFunction = errors.New("blindsign/blindrsa: unsupported hash function")
)
