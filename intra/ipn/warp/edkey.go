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

type EdKey interface {
	PrivateKeyBase64() string
	PublicKeyPKIXPem() string
	Clear()
	ToX25519() x.WgKey
}

type edKeyPair struct {
	private ed25519.PrivateKey
}

var _ EdKey = (*edKeyPair)(nil)

// newProtonKeyPair generates new ED25519 key pair seeding from rand.
func newEdKeyPairOf(rand io.Reader) (*edKeyPair, error) {
	_, pri, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	return &edKeyPair{pri}, nil
}

func NewEdKeyPairFrom(privateKeyBase64 string) (*edKeyPair, error) {
	private, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return nil, err
	}
	if len(private) != ed25519.SeedSize {
		return nil, errPrivateKeySize
	}
	return &edKeyPair{ed25519.NewKeyFromSeed(private)}, nil
}

// Clear clears memory storing key pair
func (key *edKeyPair) Clear() {
	for i := range key.private {
		key.private[i] = 0
	}
}

func (key *edKeyPair) PrivateKeyBase64() string {
	return base64.StdEncoding.EncodeToString(key.PrivateKeyBytes())
}

func (key *edKeyPair) PrivateKeyBytes() []byte {
	// publickey: return key.private[ed25519.SeedSize:]
	return key.private.Seed()
}

// publicKeyPKIX returns public key in PKIX, ASN.1 DER format
func (key *edKeyPair) publicKeyPKIX() ([]byte, error) {
	// privatekey: return append(prefixEd25519PKIXPriv[:], key.PrivateKeyBytes()...)
	return x509.MarshalPKIXPublicKey(key.private.Public())
}

// PublicKeyPKIXPem returns public key in ASN.1 DER representation as PEM
func (key *edKeyPair) PublicKeyPKIXPem() string {
	// privatekey: return toPEM(key.privateKeyPKIX(), "PRIVATE KEY")
	bytes, err := key.publicKeyPKIX()
	if err != nil {
		return ""
	}
	return toPEM(bytes, "PUBLIC KEY")
}

// ToX25519 converts to X25519 secret key.
func (key *edKeyPair) ToX25519() x.WgKey {
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
	return shab([]byte(p))
}

func shab(b []byte) []byte {
	digest := sha256.Sum256(b)
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
