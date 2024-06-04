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
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/log"
	"github.com/miekg/dns"
	"golang.org/x/crypto/ed25519"

	"github.com/celzero/firestack/intra/xdns"
)

type certinfo struct {
	ServerPk           [32]byte
	SharedKey          [32]byte
	MagicQuery         [xdns.ClientMagicLen]byte
	CryptoConstruction xdns.CryptoConstruction
	ForwardSecurity    bool
}

type dnsExchangeResponse struct {
	response *dns.Msg
	rtt      time.Duration
	priority int
	err      error
}

var errCancelled = errors.New("cancelled")

func fetchCurrentDNSCryptCert(proxy *DcMulti, serverName *string, pk ed25519.PublicKey, serverAddress string, providerName string) (certinfo, error) {
	if len(pk) != ed25519.PublicKeySize {
		return certinfo{}, errors.New("invalid public key length")
	}
	if !strings.HasSuffix(providerName, ".") {
		providerName = providerName + "."
	}
	if serverName == nil {
		serverName = &providerName
	}
	query := dns.Msg{}
	query.SetQuestion(providerName, dns.TypeTXT)
	if !strings.HasPrefix(providerName, "2.dnscrypt-cert.") {
		log.W("dnscrypt: [%v] is not v2, ('%v' doesn't start with '2.dnscrypt-cert.')", *serverName, providerName)
	}
	log.I("dnscrypt: [%v] Fetching DNSCrypt certificate for [%s] at [%v]", *serverName, providerName, serverAddress)
	in, rtt, err := dnsExchange(proxy, &query, serverAddress, serverName)
	if err != nil {
		log.W("dnscrypt: [%s] TIMEOUT %v", *serverName, err)
		return certinfo{}, err
	}
	now := uint32(time.Now().Unix())
	certInfo := certinfo{CryptoConstruction: xdns.UndefinedConstruction}
	highestSerial := uint32(0)
	var certCountStr string
	for _, answerRr := range in.Answer {
		var txt string
		if t, ok := answerRr.(*dns.TXT); !ok {
			log.I("dnscrypt: [%v] Extra record of type [%v] found in certificate", *serverName, answerRr.Header().Rrtype)
			continue
		} else {
			txt = strings.Join(t.Txt, "")
		}
		binCert := packTxtString(txt)
		if len(binCert) < 124 {
			log.W("dnscrypt: [%v] Certificate too short", *serverName)
			continue
		}
		if !bytes.Equal(binCert[:4], xdns.CertMagic[:4]) {
			log.W("dnscrypt: [%v] Invalid cert magic", *serverName)
			continue
		}
		cryptoConstruction := xdns.CryptoConstruction(0)
		switch esVersion := binary.BigEndian.Uint16(binCert[4:6]); esVersion {
		case 0x0001:
			cryptoConstruction = xdns.XSalsa20Poly1305
		case 0x0002:
			cryptoConstruction = xdns.XChacha20Poly1305
		default:
			log.W("dnscrypt: [%v] Unsupported crypto construction", *serverName)
			continue
		}
		signature := binCert[8:72]
		signed := binCert[72:]
		if !ed25519.Verify(pk, signed, signature) {
			log.W("dnscrypt: [%v] Incorrect signature for provider name: [%v]", *serverName, providerName)
			continue
		}
		serial := binary.BigEndian.Uint32(binCert[112:116])
		tsBegin := binary.BigEndian.Uint32(binCert[116:120])
		tsEnd := binary.BigEndian.Uint32(binCert[120:124])
		if tsBegin >= tsEnd {
			log.W("dnscrypt: [%v] certificate ends before it starts (%v >= %v)", *serverName, tsBegin, tsEnd)
			continue
		}
		ttl := tsEnd - tsBegin
		if ttl > 86400*7 {
			log.I("dnscrypt: [%v] the key validity period for this server is excessively long (%d days), significantly reducing reliability and forward security.", *serverName, ttl/86400)
			daysLeft := (tsEnd - now) / 86400
			if daysLeft < 1 {
				log.W("dnscrypt: [%v] certificate will expire today -- Switch to a different resolver as soon as possible", *serverName)
			} else if daysLeft <= 7 {
				log.W("dnscrypt: [%v] certificate is about to expire -- if you don't manage this server, tell the server operator about it", *serverName)
			} else if daysLeft <= 30 {
				log.I("dnscrypt: [%v] certificate will expire in %d days", *serverName, daysLeft)
			}
			certInfo.ForwardSecurity = false
		} else {
			certInfo.ForwardSecurity = true
		}
		if !proxy.certIgnoreTimestamp {
			if now > tsEnd || now < tsBegin {
				log.W("dnscrypt: [%v] Certificate not valid at the current date (now: %v is not in [%v..%v])", *serverName, now, tsBegin, tsEnd)
				continue
			}
		}
		if serial < highestSerial {
			log.W("dnscrypt: [%v] Superseded by a previous certificate", *serverName)
			continue
		}
		if serial == highestSerial {
			if cryptoConstruction < certInfo.CryptoConstruction {
				log.W("dnscrypt: [%v] Keeping the previous, preferred crypto construction", *serverName)
				continue
			} else {
				log.W("dnscrypt: [%v] Upgrading the construction from %v to %v", *serverName, certInfo.CryptoConstruction, cryptoConstruction)
			}
		}
		if cryptoConstruction != xdns.XChacha20Poly1305 && cryptoConstruction != xdns.XSalsa20Poly1305 {
			log.W("dnscrypt: [%v] Cryptographic construction %v not supported", *serverName, cryptoConstruction)
			continue
		}
		var serverPk [32]byte
		copy(serverPk[:], binCert[72:104])
		sharedKey := computeSharedKey(cryptoConstruction, &proxy.proxySecretKey, &serverPk, &providerName)
		certInfo.SharedKey = sharedKey
		highestSerial = serial
		certInfo.CryptoConstruction = cryptoConstruction
		copy(certInfo.ServerPk[:], serverPk[:])
		copy(certInfo.MagicQuery[:], binCert[104:112])
		log.I("dnscrypt: [%s] OK (DNSCrypt) - rtt: %dms%s", *serverName, rtt.Nanoseconds()/1000000, certCountStr)
		certCountStr = " - additional certificate"
	}
	if certInfo.CryptoConstruction == xdns.UndefinedConstruction {
		return certInfo, errors.New("no useable cert found")
	}
	return certInfo, nil
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func dddToByte(s []byte) byte {
	return byte((s[0]-'0')*100 + (s[1]-'0')*10 + (s[2] - '0'))
}

func packTxtString(s string) []byte {
	bs := make([]byte, len(s))
	msg := make([]byte, 0)
	copy(bs, s)
	for i := 0; i < len(bs); i++ {
		if bs[i] == '\\' {
			i++
			if i == len(bs) {
				break
			}
			if i+2 < len(bs) && isDigit(bs[i]) && isDigit(bs[i+1]) && isDigit(bs[i+2]) {
				msg = append(msg, dddToByte(bs[i:]))
				i += 2
			} else if bs[i] == 't' {
				msg = append(msg, '\t')
			} else if bs[i] == 'r' {
				msg = append(msg, '\r')
			} else if bs[i] == 'n' {
				msg = append(msg, '\n')
			} else {
				msg = append(msg, bs[i])
			}
		} else {
			msg = append(msg, bs[i])
		}
	}
	return msg
}

func dnsExchange(proxy *DcMulti, query *dns.Msg, serverAddress string, serverName *string) (*dns.Msg, time.Duration, error) {

	// always use udp to fetch certs since most servers like adguard, cleanbrowsing
	// don't support fetching certs over tcp
	proto := "udp"

	// add padding to ensure that the cert txt response is large enough
	minsz := 480
	cancelChannel := make(chan struct{})
	channel := make(chan dnsExchangeResponse)
	var err error
	options := 0

	for tries := 0; tries < 4; tries++ {
		queryCopy := query.Copy()
		queryCopy.Id += uint16(options)
		timeout := time.Duration(200*tries) * time.Millisecond
		core.Go2("cert.dnsExchange", func(query *dns.Msg, delay time.Duration) {

			if proto == "udp" {
				proto = "tcp"
			} else {
				proto = "udp"
			}
			option := dnsExchangeResponse{err: errCancelled}
			time.Sleep(delay)
			select {
			case <-cancelChannel:
				return
			default:
				option = _dnsExchange(proxy, proto, query, serverAddress, minsz)
			}
			option.priority = 0
			channel <- option
		}, queryCopy, timeout)
		options++
	}
	deadline := time.NewTimer(30 * time.Second)
	var bestOption *dnsExchangeResponse
	for i := 0; i < options; i++ {
		select {
		case res := <-channel:
			if res.err == nil {
				if bestOption == nil {
					bestOption = &res
				} else if res.rtt < bestOption.rtt {
					bestOption = &res
					close(cancelChannel)
					i = options // break
				}
			} else {
				err = res.err
			}
		case <-deadline.C:
			i = options // break
		}
	}
	if bestOption != nil {
		log.D("dnscrypt: cert retrieval for [%v] succeeded via relay?", *serverName)
		return bestOption.response, bestOption.rtt, nil
	}

	log.I("dnscrypt: no cert, ignoring server: [%v] proto: [%v]", *serverName, proto)

	if err == nil {
		err = errors.New("unable to reach server to fetch certs")
	}

	return nil, 0, err
}

func _dnsExchange(proxy *DcMulti, proto string, query *dns.Msg, serverAddress string, paddedLen int) dnsExchangeResponse {
	var packet []byte
	var rtt time.Duration

	// FIXME: udp relays do not support fetching certs over relays, and
	// doing so leaks client's identity to the actual dns-crypt server!
	log.V("dnscrypt: [%s] relay is not used when fetching certs", proto)
	if proto == "udp" {
		qNameLen, padding := len(query.Question[0].Name), 0
		if qNameLen < paddedLen {
			padding = paddedLen - qNameLen
		}
		if padding > 0 {
			opt := new(dns.OPT)
			opt.Hdr.Name = "."
			ext := new(dns.EDNS0_PADDING)
			ext.Padding = make([]byte, padding)
			opt.Option = append(opt.Option, ext)
			query.Extra = []dns.RR{opt}
		}
		binQuery, err := query.Pack()
		if err != nil {
			return dnsExchangeResponse{err: err}
		}

		now := time.Now()
		pc, err := dialers.Dial(proxy.dialer, "udp", serverAddress)
		if err != nil {
			return dnsExchangeResponse{err: err}
		} else if pc == nil || core.IsNil(pc) {
			return dnsExchangeResponse{err: errNoConn}
		}

		defer clos(pc)
		if derr := pc.SetDeadline(time.Now().Add(timeout8s)); derr != nil {
			return dnsExchangeResponse{err: derr}
		}
		if _, werr := pc.Write(binQuery); werr != nil {
			return dnsExchangeResponse{err: werr}
		}
		packet = make([]byte, xdns.MaxDNSPacketSize)
		length, err := pc.Read(packet)
		if err != nil {
			return dnsExchangeResponse{err: err}
		}
		rtt = time.Since(now)
		packet = packet[:length]
	} else {
		binQuery, err := query.Pack()
		if err != nil {
			return dnsExchangeResponse{err: err}
		}
		// FIXME: for time-being, tcp validation is used only
		// when relay addresses are nil. Uncomment the code
		// below when udp transport for dnscrypt-proxy is ready.
		/*
			if relayTCPAddr != nil && relayForCerts {
				proxy.prepareForRelay(tcpAddr.IP, tcpAddr.Port, &binQuery)
				upstreamAddr = relayTCPAddr
			}
		*/
		now := time.Now()
		var pc net.Conn
		pc, err = dialers.Dial(proxy.dialer, "tcp", serverAddress)
		if err != nil {
			return dnsExchangeResponse{err: err}
		} else if pc == nil || core.IsNil(pc) {
			return dnsExchangeResponse{err: errNoConn}
		}

		defer clos(pc)
		if derr := pc.SetDeadline(time.Now().Add(timeout8s)); derr != nil {
			return dnsExchangeResponse{err: derr}
		}
		binQuery, err = xdns.PrefixWithSize(binQuery)
		if err != nil {
			return dnsExchangeResponse{err: err}
		}
		if _, werr := pc.Write(binQuery); werr != nil {
			return dnsExchangeResponse{err: werr}
		}
		packet, err = xdns.ReadPrefixed(&pc)
		if err != nil {
			return dnsExchangeResponse{err: err}
		}
		rtt = time.Since(now)
	}
	msg := dns.Msg{}
	if err := msg.Unpack(packet); err != nil {
		return dnsExchangeResponse{err: err}
	}
	return dnsExchangeResponse{response: &msg, rtt: rtt, err: nil}
}

func clos(c net.Conn) {
	core.CloseConn(c)
}
