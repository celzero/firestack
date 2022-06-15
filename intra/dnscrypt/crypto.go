// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//    ISC License
//
//    Copyright (c) 2018-2021
//    Frank Denis <j at pureftpd dot org>

package dnscrypt

import (
	"bytes"
	crypto_rand "crypto/rand"
	"errors"
	"math/rand"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/xdns"

	"github.com/jedisct1/xsecretbox"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	// NonceSize is what the name suggests
	NonceSize = 24
	// TagSize is what the name suggests
	TagSize          = 16
	HalfNonceSize    = NonceSize / 2
	PublicKeySize    = 32
	QueryOverhead    = xdns.ClientMagicLen + PublicKeySize + HalfNonceSize + TagSize
	ResponseOverhead = len(xdns.ServerMagic) + NonceSize + TagSize
)

func pad(packet []byte, minSize int) []byte {
	packet = append(packet, 0x80)
	for len(packet) < minSize {
		packet = append(packet, 0)
	}
	return packet
}

func unpad(packet []byte) ([]byte, error) {
	for i := len(packet); ; {
		if i == 0 {
			return nil, errors.New("Invalid padding (short packet)")
		}
		i--
		if packet[i] == 0x80 {
			return packet[:i], nil
		} else if packet[i] != 0x00 {
			return nil, errors.New("Invalid padding (delimiter not found)")
		}
	}
}

func ComputeSharedKey(cryptoConstruction xdns.CryptoConstruction, secretKey *[32]byte, serverPk *[32]byte, providerName *string) (sharedKey [32]byte) {
	if cryptoConstruction == xdns.XChacha20Poly1305 {
		var err error
		sharedKey, err = xsecretbox.SharedKey(*secretKey, *serverPk)
		if err != nil {
			log.Warnf("[%v] Weak public key", providerName)
		}
	} else {
		box.Precompute(&sharedKey, serverPk, secretKey)
	}
	return
}

func (proxy *Proxy) Encrypt(serverInfo *ServerInfo, packet []byte, proto string) (sharedKey *[32]byte, encrypted []byte, clientNonce []byte, err error) {
	nonce, clientNonce := make([]byte, NonceSize), make([]byte, HalfNonceSize)
	crypto_rand.Read(clientNonce)
	copy(nonce, clientNonce)
	var publicKey *[PublicKeySize]byte

	sharedKey = &serverInfo.SharedKey
	publicKey = &proxy.proxyPublicKey

	minQuestionSize := QueryOverhead + len(packet)
	var xpad [1]byte
	rand.Read(xpad[:])
	minQuestionSize += int(xpad[0])
	paddedLength := xdns.Min(xdns.MaxDNSUDPPacketSize, (xdns.Max(minQuestionSize, QueryOverhead)+1+63) & ^63)

	// was: serverInfo.RelayUDAddr
	if serverInfo.RelayTCPAddr != nil && proto == "tcp" {
		paddedLength = xdns.MaxDNSPacketSize
	}
	if QueryOverhead+len(packet)+1 > paddedLength {
		err = errors.New("Question too large; cannot be padded")
		return
	}
	encrypted = append(serverInfo.MagicQuery[:], publicKey[:]...)
	encrypted = append(encrypted, nonce[:HalfNonceSize]...)
	padded := pad(packet, paddedLength-QueryOverhead)
	if serverInfo.CryptoConstruction == xdns.XChacha20Poly1305 {
		encrypted = xsecretbox.Seal(encrypted, nonce, padded, sharedKey[:])
	} else {
		var xsalsaNonce [24]byte
		copy(xsalsaNonce[:], nonce)
		encrypted = secretbox.Seal(encrypted, padded, &xsalsaNonce, sharedKey)
	}
	return
}

func (proxy *Proxy) Decrypt(serverInfo *ServerInfo, sharedKey *[32]byte, encrypted []byte, nonce []byte) ([]byte, error) {
	serverMagicLen := len(xdns.ServerMagic)
	responseHeaderLen := serverMagicLen + NonceSize
	if len(encrypted) < responseHeaderLen+TagSize+int(xdns.MinDNSPacketSize) ||
		len(encrypted) > responseHeaderLen+TagSize+int(xdns.MaxDNSPacketSize) ||
		!bytes.Equal(encrypted[:serverMagicLen], xdns.ServerMagic[:]) {
		return encrypted, errors.New("Invalid message size or prefix")
	}
	serverNonce := encrypted[serverMagicLen:responseHeaderLen]
	if !bytes.Equal(nonce[:HalfNonceSize], serverNonce[:HalfNonceSize]) {
		return encrypted, errors.New("Unexpected nonce")
	}
	var packet []byte
	var err error
	if serverInfo.CryptoConstruction == xdns.XChacha20Poly1305 {
		packet, err = xsecretbox.Open(nil, serverNonce, encrypted[responseHeaderLen:], sharedKey[:])
	} else {
		var xsalsaServerNonce [24]byte
		copy(xsalsaServerNonce[:], serverNonce)
		var ok bool
		packet, ok = secretbox.Open(nil, encrypted[responseHeaderLen:], &xsalsaServerNonce, sharedKey)
		if !ok {
			err = errors.New("Incorrect tag")
		}
	}
	if err != nil {
		return encrypted, err
	}
	packet, err = unpad(packet)
	if err != nil || len(packet) < xdns.MinDNSPacketSize {
		return encrypted, errors.New("Incorrect padding")
	}
	return packet, nil
}
