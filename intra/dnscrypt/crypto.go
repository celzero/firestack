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
		if i == 0 { // short packet
			return nil, errIncorrectPad
		}
		i--
		if packet[i] == 0x80 {
			return packet[:i], nil
		} else if packet[i] != 0x00 { // delimiter not found
			return nil, errIncorrectPad
		}
	}
}

func ComputeSharedKey(cryptoConstruction xdns.CryptoConstruction, secretKey *[32]byte, serverPk *[32]byte, providerName *string) (sharedKey [32]byte) {
	if cryptoConstruction == xdns.XChacha20Poly1305 {
		var err error
		sharedKey, err = xsecretbox.SharedKey(*secretKey, *serverPk)
		if err != nil {
			log.W("dnscrypt: [%v] Weak public key", providerName)
		}
	} else {
		box.Precompute(&sharedKey, serverPk, secretKey)
	}
	return
}

func Encrypt(
	serverInfo *ServerInfo,
	packet []byte,
	useudp bool,
) (sharedKey *[32]byte, encrypted []byte, clientNonce []byte, err error) {
	nonce := make([]byte, NonceSize)
	clientNonce = make([]byte, HalfNonceSize)
	crypto_rand.Read(clientNonce)
	copy(nonce, clientNonce)

	var publicKey *[PublicKeySize]byte

	sharedKey = &serverInfo.SharedKey
	publicKey = serverInfo.ClientPubKey

	var paddedLength int
	if useudp { // using udp
		paddedLength = xdns.MaxDNSUDPSafePacketSize
	} else if serverInfo.RelayTCPAddr != nil { // tcp, with relay
		paddedLength = xdns.MaxDNSPacketSize
	} else { // tcp, without relay
		minQuestionSize := QueryOverhead + len(packet)
		// random pad if tcp without relay
		var xpad [1]byte
		crypto_rand.Read(xpad[:])
		minQuestionSize += int(xpad[0])
		paddedLength = xdns.Min(xdns.MaxDNSUDPPacketSize, (xdns.Max(minQuestionSize, QueryOverhead)+1+63) & ^63)
	}

	if QueryOverhead+len(packet)+1 > paddedLength {
		err = errQueryTooLarge
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

func Decrypt(serverInfo *ServerInfo, sharedKey *[32]byte, encrypted []byte, nonce []byte) ([]byte, error) {
	serverMagicLen := len(xdns.ServerMagic)
	responseHeaderLen := serverMagicLen + NonceSize
	if len(encrypted) < responseHeaderLen+TagSize+int(xdns.MinDNSPacketSize) ||
		len(encrypted) > responseHeaderLen+TagSize+int(xdns.MaxDNSPacketSize) ||
		!bytes.Equal(encrypted[:serverMagicLen], xdns.ServerMagic[:]) {
		return encrypted, errInvalidResponse
	}
	serverNonce := encrypted[serverMagicLen:responseHeaderLen]
	if !bytes.Equal(nonce[:HalfNonceSize], serverNonce[:HalfNonceSize]) {
		return encrypted, errNonceUnexpected
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
			err = errIncorrectTag
		}
	}

	if err != nil {
		return encrypted, err
	}
	if len(packet) <= 0 {
		return encrypted, errInvalidResponse
	}

	packet, err = unpad(packet)
	if err != nil || len(packet) < xdns.MinDNSPacketSize {
		return encrypted, errIncorrectPad
	}
	return packet, nil
}
