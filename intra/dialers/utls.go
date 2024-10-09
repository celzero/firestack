// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//    SPDX-License-Identifier: MIT

// from: github.com/bepass-org/warp-plus/blob/19ac233cc/warp/tlsdial.go

package dialers

import (
	"io"
	"net"

	"github.com/celzero/firestack/intra/core"

	utls "github.com/refraction-networking/utls"
)

const utlsExtSniCurveId uint16 = 0x15
const sniCurveSize = 1200
const utlsVer = utls.VersionTLS12

var utlsDefaultCypherSuites = []uint16{
	utls.GREASE_PLACEHOLDER,
	utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	utls.TLS_AES_128_GCM_SHA256, // tls 1.3
	utls.FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	utls.TLS_RSA_WITH_AES_256_CBC_SHA,
}

var utlsDefaultExt = []utls.TLSExtension{
	&sniCurveExt{
		curvelen: sniCurveSize,
		pad:      true,
	},
	&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519, utls.CurveP256}},
	&utls.SupportedPointsExtension{SupportedPoints: []byte{0}}, // uncompressed
	&utls.SessionTicketExtension{},
	&utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
	&utls.SignatureAlgorithmsExtension{
		SupportedSignatureAlgorithms: []utls.SignatureScheme{
			utls.ECDSAWithP256AndSHA256,
			utls.ECDSAWithP384AndSHA384,
			utls.ECDSAWithP521AndSHA512,
			utls.PSSWithSHA256,
			utls.PSSWithSHA384,
			utls.PSSWithSHA512,
			utls.PKCS1WithSHA256,
			utls.PKCS1WithSHA384,
			utls.PKCS1WithSHA512,
			utls.ECDSAWithSHA1,
			utls.PKCS1WithSHA1,
		},
	},
	&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
		{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
		{Group: utls.X25519},
	}},
	&utls.PSKKeyExchangeModesExtension{Modes: []uint8{1}}, // pskModeDHE
}

// sniCurveExt implements SNICurve (0x15) extension
type sniCurveExt struct {
	*utls.GenericExtension
	curvelen int
	pad      bool // enabled if true
}

// Len returns the length of the SNICurveExtension.
func (e *sniCurveExt) Len() int {
	if e.pad {
		return 4 + e.curvelen
	} // extension disabled
	return 0
}

// Read reads the SNICurveExtension.
func (e *sniCurveExt) Read(b []byte) (n int, err error) {
	if !e.pad { // extension disabled
		return 0, io.EOF
	}
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	// https://tools.ietf.org/html/rfc7627
	b[0] = byte(utlsExtSniCurveId >> 8)
	b[1] = byte(utlsExtSniCurveId)
	b[2] = byte(e.curvelen >> 8)
	b[3] = byte(e.curvelen)

	bptr := core.Alloc()
	buf := *bptr
	buf = buf[:cap(buf)]
	defer func() {
		*bptr = buf
		core.Recycle(bptr)
	}()

	copy(b[4:], buf)
	return e.Len(), io.EOF
}

// utlsHello creates a TLS hello packet with SNICurve.
func utlsHello(conn net.Conn, config *utls.Config, sni string) (*utls.UConn, error) {
	uconn := utls.UClient(conn, config, utls.HelloCustom)
	spec := utls.ClientHelloSpec{
		TLSVersMax:   utlsVer,
		TLSVersMin:   utlsVer,
		CipherSuites: utlsDefaultCypherSuites,
		Extensions:   utlsDefaultExt,
		GetSessionID: nil,
	}
	spec.Extensions = append(spec.Extensions, &utls.SNIExtension{ServerName: sni})
	err := uconn.ApplyPreset(&spec)
	if err != nil {
		return nil, err
	}

	err = uconn.Handshake()
	if err != nil {
		return nil, err
	}

	return uconn, nil
}
