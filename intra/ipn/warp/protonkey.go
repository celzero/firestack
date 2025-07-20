// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package warp

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/log"
)

var (
	errPrivateKeySize = errors.New("proton: invalid private key size")
)

// from: github.com/ProtonVPN/go-vpn-lib/blob/e9da03adf0758/ed25519/constants.go#L24
// prefixEd25519PKIXPub  = []byte{0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00}
// prefixEd25519PKIXPriv = []byte{0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20}

type ProtonKey interface {
	PrivateKeyBase64() string
	PublicKeyPKIXPem() string
	Clear()
	ToX25519() x.WgKey
}

type protonKeyPair struct {
	private ed25519.PrivateKey
}

var _ ProtonKey = (*protonKeyPair)(nil)

// newProtonKeyPair generates new ED25519 key pair.
func newProtonKeyPair() (*protonKeyPair, error) {
	return newProtonKeyPairOf(nil)
}

// newProtonKeyPair generates new ED25519 key pair seeding from rand.
func newProtonKeyPairOf(rand io.Reader) (*protonKeyPair, error) {
	_, pri, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	return &protonKeyPair{pri}, nil
}

func newProtonKeyPairFrom(privateKeyBase64 string) (*protonKeyPair, error) {
	private, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return nil, err
	}
	if len(private) != ed25519.SeedSize {
		return nil, errPrivateKeySize
	}
	return &protonKeyPair{ed25519.NewKeyFromSeed(private)}, nil
}

// Clear clears memory storing key pair
func (key *protonKeyPair) Clear() {
	for i := range key.private {
		key.private[i] = 0
	}
}

func (key *protonKeyPair) PrivateKeyBase64() string {
	return base64.StdEncoding.EncodeToString(key.PrivateKeyBytes())
}

func (key *protonKeyPair) PrivateKeyBytes() []byte {
	// publickey: return key.private[ed25519.SeedSize:]
	return key.private.Seed()
}

// publicKeyPKIX returns public key in PKIX, ASN.1 DER format
func (key *protonKeyPair) publicKeyPKIX() ([]byte, error) {
	// privatekey: return append(prefixEd25519PKIXPriv[:], key.PrivateKeyBytes()...)
	return x509.MarshalPKIXPublicKey(key.private.Public())
}

// PublicKeyPKIXPem returns public key in ASN.1 DER representation as PEM
func (key *protonKeyPair) PublicKeyPKIXPem() string {
	// privatekey: return toPEM(key.privateKeyPKIX(), "PRIVATE KEY")
	bytes, err := key.publicKeyPKIX()
	if err != nil {
		return ""
	}
	return toPEM(bytes, "PUBLIC KEY")
}

// ToX25519 converts to X25519 secret key.
func (key *protonKeyPair) ToX25519() x.WgKey {
	prandom := sha512.Sum512(key.PrivateKeyBytes())
	return x.NewWgPrivateKeyFrom([ed25519.SeedSize]byte(prandom[:32]))
}

func toPEM(bytes []byte, header string) string {
	encoded := pem.EncodeToMemory(
		&pem.Block{
			Type:  header,
			Bytes: bytes,
		},
	)
	return string(encoded)
}

func hmac256(m, k []byte) []byte {
	mac := hmac.New(sha256.New, k)
	mac.Write(m)
	return mac.Sum(nil)
}

func sha(p string) []byte {
	digest := sha256.Sum256([]byte(p))
	return digest[:]
}

func hex2byte(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		log.E("hex2byte: err %v", err)
	}
	return b
}

func byte2hex(b []byte) string {
	return hex.EncodeToString(b)
}
