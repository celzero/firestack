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

	"golang.org/x/crypto/ed25519"

	"github.com/Jigsaw-Code/outline-go-tun2socks/intra/xdns"
	"github.com/eycorsican/go-tun2socks/common/log"

	"github.com/miekg/dns"
)

type CertInfo struct {
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

func FetchCurrentDNSCryptCert(proxy *Proxy, serverName *string, proto string, pk ed25519.PublicKey,
	serverAddress string, providerName string, isNew bool, relayTCPAddr *net.TCPAddr) (CertInfo, *net.TCPAddr, error) {
	if len(pk) != ed25519.PublicKeySize {
		return CertInfo{}, nil, errors.New("Invalid public key length")
	}
	if !strings.HasSuffix(providerName, ".") {
		providerName = providerName + "."
	}
	if serverName == nil {
		serverName = &providerName
	}
	query := dns.Msg{}
	query.SetQuestion(providerName, dns.TypeTXT)
	var relayForCerts bool = true
	if !strings.HasPrefix(providerName, "2.dnscrypt-cert.") {
		log.Warnf("[%v] is not v2, ('%v' doesn't start with '2.dnscrypt-cert.')", *serverName, providerName)
		relayForCerts = false
	}
	in, rtt, relayTCPAddr, err := dnsExchange(proxy, proto, &query, serverAddress, relayTCPAddr, serverName, relayForCerts)
	if err != nil {
		log.Warnf("[%s] TIMEOUT %v", *serverName, err)
		return CertInfo{}, nil, err
	}
	now := uint32(time.Now().Unix())
	certInfo := CertInfo{CryptoConstruction: xdns.UndefinedConstruction}
	highestSerial := uint32(0)
	var certCountStr string
	for _, answerRr := range in.Answer {
		var txt string
		if t, ok := answerRr.(*dns.TXT); !ok {
			log.Infof("[%v] Extra record of type [%v] found in certificate", *serverName, answerRr.Header().Rrtype)
			continue
		} else {
			txt = strings.Join(t.Txt, "")
		}
		binCert := packTxtString(txt)
		if len(binCert) < 124 {
			log.Warnf("[%v] Certificate too short", *serverName)
			continue
		}
		if !bytes.Equal(binCert[:4], xdns.CertMagic[:4]) {
			log.Warnf("[%v] Invalid cert magic", *serverName)
			continue
		}
		cryptoConstruction := xdns.CryptoConstruction(0)
		switch esVersion := binary.BigEndian.Uint16(binCert[4:6]); esVersion {
		case 0x0001:
			cryptoConstruction = xdns.XSalsa20Poly1305
		case 0x0002:
			cryptoConstruction = xdns.XChacha20Poly1305
		default:
			log.Warnf("[%v] Unsupported crypto construction", *serverName)
			continue
		}
		signature := binCert[8:72]
		signed := binCert[72:]
		if !ed25519.Verify(pk, signed, signature) {
			log.Warnf("[%v] Incorrect signature for provider name: [%v]", *serverName, providerName)
			continue
		}
		serial := binary.BigEndian.Uint32(binCert[112:116])
		tsBegin := binary.BigEndian.Uint32(binCert[116:120])
		tsEnd := binary.BigEndian.Uint32(binCert[120:124])
		if tsBegin >= tsEnd {
			log.Warnf("[%v] certificate ends before it starts (%v >= %v)", *serverName, tsBegin, tsEnd)
			continue
		}
		ttl := tsEnd - tsBegin
		if ttl > 86400*7 {
			log.Infof("[%v] the key validity period for this server is excessively long (%d days), significantly reducing reliability and forward security.", *serverName, ttl/86400)
			daysLeft := (tsEnd - now) / 86400
			if daysLeft < 1 {
				log.Warnf("[%v] certificate will expire today -- Switch to a different resolver as soon as possible", *serverName)
			} else if daysLeft <= 7 {
				log.Warnf("[%v] certificate is about to expire -- if you don't manage this server, tell the server operator about it", *serverName)
			} else if daysLeft <= 30 {
				log.Infof("[%v] certificate will expire in %d days", *serverName, daysLeft)
			}
			certInfo.ForwardSecurity = false
		} else {
			certInfo.ForwardSecurity = true
		}
		if !proxy.certIgnoreTimestamp {
			if now > tsEnd || now < tsBegin {
				log.Warnf("[%v] Certificate not valid at the current date (now: %v is not in [%v..%v])", *serverName, now, tsBegin, tsEnd)
				continue
			}
		}
		if serial < highestSerial {
			log.Warnf("[%v] Superseded by a previous certificate", *serverName)
			continue
		}
		if serial == highestSerial {
			if cryptoConstruction < certInfo.CryptoConstruction {
				log.Warnf("[%v] Keeping the previous, preferred crypto construction", *serverName)
				continue
			} else {
				log.Warnf("[%v] Upgrading the construction from %v to %v", *serverName, certInfo.CryptoConstruction, cryptoConstruction)
			}
		}
		if cryptoConstruction != xdns.XChacha20Poly1305 && cryptoConstruction != xdns.XSalsa20Poly1305 {
			log.Warnf("[%v] Cryptographic construction %v not supported", *serverName, cryptoConstruction)
			continue
		}
		var serverPk [32]byte
		copy(serverPk[:], binCert[72:104])
		sharedKey := ComputeSharedKey(cryptoConstruction, &proxy.proxySecretKey, &serverPk, &providerName)
		certInfo.SharedKey = sharedKey
		highestSerial = serial
		certInfo.CryptoConstruction = cryptoConstruction
		copy(certInfo.ServerPk[:], serverPk[:])
		copy(certInfo.MagicQuery[:], binCert[104:112])
		if isNew {
			log.Infof("[%s] OK (DNSCrypt) - rtt: %dms%s", *serverName, rtt.Nanoseconds()/1000000, certCountStr)
		} else {
			log.Infof("[%s] OK (DNSCrypt) - rtt: %dms%s", *serverName, rtt.Nanoseconds()/1000000, certCountStr)
		}
		certCountStr = " - additional certificate"
	}
	if certInfo.CryptoConstruction == xdns.UndefinedConstruction {
		return certInfo, nil, errors.New("No useable certificate found")
	}
	if relayTCPAddr == nil {
		log.Warnf("relays for %v not supported.", *serverName)
	}
	return certInfo, relayTCPAddr, nil
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

func dnsExchange(proxy *Proxy, proto string, query *dns.Msg, serverAddress string,
	relayTCPAddr *net.TCPAddr, serverName *string, relayForCerts bool) (*dns.Msg, time.Duration, *net.TCPAddr, error) {

	// dnscrypt-relay forwards queries over udp only and so fragmentation support
	// is a must otherwise larger queries simply won't work with the server
	// over relays destinted for such "buggy" dnscrypt servers. So, when a
	// relay-address is set, fetch certs over UDP. When not, it is okay to
	// only rely on TCP to fetch certs as proxy supports TCP transport only
	// which has no problems with larger queries even with "buggy" servers.
	// flow: client ---[tcp|udp]---> relay ---[always-udp]---> server
	if relayTCPAddr == nil {
		// if there are no relays, use tcp to validate the servers
		// since we do not care about large query support over udp.
		proto = "tcp"
	} else {
		// if there's a relay set, check if the server can handle
		// large queries by fetching certs over udp instead.
		proto = "udp"
	}

	cancelChannel := make(chan struct{})
	channel := make(chan dnsExchangeResponse)
	var err error
	options := 0

	for tries := 0; tries < 3; tries++ {
		queryCopy := query.Copy()
		queryCopy.Id += uint16(options)
		go func(query *dns.Msg, delay time.Duration) {
			option := _dnsExchange(proxy, proto, query, serverAddress, relayTCPAddr, 1500, relayForCerts)
			option.priority = 0
			channel <- option
			time.Sleep(delay)
			select {
			case <-cancelChannel:
				return
			default:
			}
		}(queryCopy, time.Duration(200*tries)*time.Millisecond)
		options++
	}
	var bestOption *dnsExchangeResponse
	for i := 0; i < options; i++ {
		if dnsExchangeResponse := <-channel; dnsExchangeResponse.err == nil {
			if bestOption == nil || dnsExchangeResponse.rtt < bestOption.rtt {
				bestOption = &dnsExchangeResponse
				close(cancelChannel)
				break
			}
		} else {
			err = dnsExchangeResponse.err
		}
	}
	if bestOption != nil {
		log.Debugf("Certificate retrieval for [%v] succeeded via relay?", *serverName, relayForCerts)
		return bestOption.response, bestOption.rtt, relayTCPAddr, nil
	}

	log.Infof("no certificate, ignoring server: [%v] relay: [%v] proto: [%v]", *serverName, relayTCPAddr, proto)

	if err == nil {
		err = errors.New("unable to reach server to fetch certs")
	}

	return nil, 0, nil, err
}

func _dnsExchange(proxy *Proxy, proto string, query *dns.Msg, serverAddress string,
	relayTCPAddr *net.TCPAddr, paddedLen int, relayForCerts bool) dnsExchangeResponse {
	var packet []byte
	var rtt time.Duration

	if proto == "udp" {
		if relayForCerts {
			// FIXME: udp relays do not support fetching certs over relays, and
			// doing so leaks client's identity to the actual dns-crypt server!
			log.Warnf("relay will not be used when fetching certs over udp")
		}
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
		upstreamAddr, err := net.ResolveUDPAddr("udp", serverAddress)
		if err != nil {
			return dnsExchangeResponse{err: err}
		}
		now := time.Now()
		pc, err := net.DialUDP("udp", nil, upstreamAddr)
		if err != nil {
			return dnsExchangeResponse{err: err}
		}
		defer pc.Close()
		if err := pc.SetDeadline(time.Now().Add(proxy.timeout)); err != nil {
			return dnsExchangeResponse{err: err}
		}
		if _, err := pc.Write(binQuery); err != nil {
			return dnsExchangeResponse{err: err}
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
		tcpAddr, err := net.ResolveTCPAddr("tcp", serverAddress)
		if err != nil {
			return dnsExchangeResponse{err: err}
		}
		upstreamAddr := tcpAddr
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
		pc, err = net.DialTCP("tcp", nil, upstreamAddr)
		if err != nil {
			return dnsExchangeResponse{err: err}
		}
		defer pc.Close()
		if err := pc.SetDeadline(time.Now().Add(proxy.timeout)); err != nil {
			return dnsExchangeResponse{err: err}
		}
		binQuery, err = xdns.PrefixWithSize(binQuery)
		if err != nil {
			return dnsExchangeResponse{err: err}
		}
		if _, err := pc.Write(binQuery); err != nil {
			return dnsExchangeResponse{err: err}
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
