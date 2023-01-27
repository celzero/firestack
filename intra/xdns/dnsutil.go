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

package xdns

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/celzero/firestack/intra/log"
	"github.com/miekg/dns"
)

func Request4FromResponse6(msg6 *dns.Msg) *dns.Msg {
	msg4 := &dns.Msg{
		Compress: true,
	}
	msg4.SetQuestion(QName(msg6), dns.TypeA)
	msg4.RecursionDesired = true
	msg4.CheckingDisabled = false
	msg4.AuthenticatedData = false
	msg4.Authoritative = false
	msg4.Id = msg6.Id
	return msg4
}

func Request4FromRequest6(msg6 *dns.Msg) *dns.Msg {
	msg4 := msg6.Copy()
	msg4.SetQuestion(QName(msg6), dns.TypeA)
	return msg4
}

func EmptyResponseFromMessage(srcMsg *dns.Msg) *dns.Msg {
	dstMsg := dns.Msg{
		MsgHdr:   srcMsg.MsgHdr,
		Compress: true,
	}
	dstMsg.Question = srcMsg.Question
	dstMsg.Response = true
	if srcMsg.RecursionDesired {
		dstMsg.RecursionAvailable = true
	}
	dstMsg.RecursionDesired = false
	dstMsg.CheckingDisabled = false
	dstMsg.AuthenticatedData = false
	if edns0 := srcMsg.IsEdns0(); edns0 != nil {
		dstMsg.SetEdns0(edns0.UDPSize(), edns0.Do())
	}
	return &dstMsg
}

func TruncatedResponse(packet []byte) ([]byte, error) {
	srcMsg := dns.Msg{}
	if err := srcMsg.Unpack(packet); err != nil {
		return nil, err
	}
	dstMsg := EmptyResponseFromMessage(&srcMsg)
	dstMsg.Truncated = true
	return dstMsg.Pack()
}

func HasTCFlag(packet []byte) bool {
	return packet[2]&2 == 2
}

func QName(msg *dns.Msg) string {
	if msg != nil && len(msg.Question) > 0 {
		return msg.Question[0].Name
	}
	return ""
}

func Targets(msg *dns.Msg) []string {
	var targets []string
	if qname, err := NormalizeQName(QName(msg)); err == nil {
		targets = append(targets, qname)
	}
	for _, a := range msg.Answer {
		var target string
		switch r := a.(type) {
		case *dns.A:
			target = r.Header().Name
		case *dns.AAAA:
			target = r.Header().Name
		case *dns.CNAME:
			target = r.Target
		case *dns.SVCB:
			if r.Priority == 0 {
				target = r.Target
			}
		case *dns.HTTPS:
			if r.Priority == 0 {
				target = r.Target
			}
		default:
			// no-op
		}
		if len(target) <= 0 {
			continue
		} else if target, err := NormalizeQName(target); err == nil {
			targets = append(targets, target)
		}
	}
	return targets
}

func NormalizeQName(str string) (string, error) {
	if len(str) == 0 || str == "." {
		return ".", nil
	}
	hasUpper := false
	str = strings.TrimSuffix(str, ".")
	strLen := len(str)
	for i := 0; i < strLen; i++ {
		c := str[i]
		if c >= utf8.RuneSelf {
			return str, errors.New("Query name is not an ASCII string")
		}
		hasUpper = hasUpper || ('A' <= c && c <= 'Z')
	}
	if !hasUpper {
		return str, nil
	}
	var b strings.Builder
	b.Grow(len(str))
	for i := 0; i < strLen; i++ {
		c := str[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String(), nil
}

func RemoveEDNS0Options(msg *dns.Msg) bool {
	edns0 := msg.IsEdns0()
	if edns0 == nil {
		return false
	}
	edns0.Option = []dns.EDNS0{}
	return true
}

func AddEDNS0PaddingIfNoneFound(msg *dns.Msg, unpaddedPacket []byte, paddingLen int) ([]byte, error) {
	edns0 := msg.IsEdns0()
	if edns0 == nil {
		msg.SetEdns0(uint16(MaxDNSPacketSize), false)
		edns0 = msg.IsEdns0()
		if edns0 == nil {
			return unpaddedPacket, nil
		}
	}
	for _, option := range edns0.Option {
		if option.Option() == dns.EDNS0PADDING {
			return unpaddedPacket, nil
		}
	}
	ext := new(dns.EDNS0_PADDING)
	padding := make([]byte, paddingLen)
	for i := range padding {
		padding[i] = 'X'
	}
	ext.Padding = padding[:paddingLen]
	edns0.Option = append(edns0.Option, ext)
	return msg.Pack()
}

func BlockResponseFromMessage(q []byte) (*dns.Msg, error) {
	r := &dns.Msg{}
	if err := r.Unpack(q); err != nil {
		return r, err
	}
	return RefusedResponseFromMessage(r)
}

func RefusedResponseFromMessage(srcMsg *dns.Msg) (dstMsg *dns.Msg, err error) {
	if srcMsg == nil {
		return nil, errors.New("empty source dns message")
	}
	dstMsg = EmptyResponseFromMessage(srcMsg)
	dstMsg.Rcode = dns.RcodeSuccess
	ttl := BlockTTL

	questions := srcMsg.Question
	if len(questions) == 0 {
		return
	}

	question := questions[0]
	sendHInfoResponse := true

	if question.Qtype == dns.TypeA {
		rr := new(dns.A)
		rr.Hdr = dns.RR_Header{
			Name:   question.Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		}
		rr.A = ip4.To4()
		if rr.A != nil {
			dstMsg.Answer = []dns.RR{rr}
			sendHInfoResponse = false
		}
	} else if question.Qtype == dns.TypeAAAA {
		rr := new(dns.AAAA)
		rr.Hdr = dns.RR_Header{
			Name:   question.Name,
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		}
		rr.AAAA = ip6.To16()
		if rr.AAAA != nil {
			dstMsg.Answer = []dns.RR{rr}
			sendHInfoResponse = false
		}
	} else if question.Qtype == dns.TypeHTTPS || question.Qtype == dns.TypeSVCB {
		rrh := new(dns.HTTPS)
		rrh.Hdr = dns.RR_Header{
			Name:   question.Name,
			Rrtype: dns.TypeHTTPS,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		}
		// TODO: instead use a self-referential "."?
		// some random 63-char string
		rrh.Target = fakedomain
		rra := new(dns.A)
		rra.Hdr = dns.RR_Header{
			Name:   fakedomain,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		}
		rra.A = ip4.To4()
		dstMsg.Answer = []dns.RR{rrh, rra}
		sendHInfoResponse = false
	}

	if sendHInfoResponse {
		hinfo := new(dns.HINFO)
		hinfo.Hdr = dns.RR_Header{
			Name:   question.Name,
			Rrtype: dns.TypeHINFO,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		}
		hinfo.Cpu = "These are not the queries you are"
		hinfo.Os = "looking for"
		dstMsg.Answer = []dns.RR{hinfo}
	}

	return
}

func HasRcodeSuccess(msg *dns.Msg) bool {
	return msg.Rcode == dns.RcodeSuccess
}

func HasAnyAnswer(msg *dns.Msg) bool {
	return len(msg.Answer) > 0
}

func HasAAnswer(msg *dns.Msg) bool {
	for _, answer := range msg.Answer {
		if answer.Header().Rrtype == dns.TypeA {
			rec, ok := answer.(*dns.A)
			if ok && len(rec.A) >= net.IPv4len {
				return true
			}
		}
	}
	return false
}

func HasAAAAAnswer(msg *dns.Msg) bool {
	for _, answer := range msg.Answer {
		if answer.Header().Rrtype == dns.TypeAAAA {
			rec, ok := answer.(*dns.AAAA)
			if ok && len(rec.AAAA) == net.IPv6len {
				return true
			}
		}
	}
	return false
}

func AAnswer(msg *dns.Msg) []*netip.Addr {
	a4 := []*netip.Addr{}
	for _, answer := range msg.Answer {
		if answer.Header().Rrtype == dns.TypeA {
			if rec, ok := answer.(*dns.A); ok {
				if ipaddr, ok := netip.AddrFromSlice(rec.A); ok {
					a4 = append(a4, &ipaddr)
				}
			}
		}
	}
	return a4
}

func AAAAAnswer(msg *dns.Msg) []*netip.Addr {
	a6 := []*netip.Addr{}
	for _, answer := range msg.Answer {
		if answer.Header().Rrtype == dns.TypeAAAA {
			if rec, ok := answer.(*dns.AAAA); ok {
				if ipaddr, ok := netip.AddrFromSlice(rec.AAAA); ok {
					a6 = append(a6, &ipaddr)
				}
			}
		}
	}
	return a6
}

func HasAAAAQuestion(msg *dns.Msg) bool {
	q := msg.Question[0]
	return q.Qclass == dns.ClassINET && q.Qtype == dns.TypeAAAA
}

func HasAQuestion(msg *dns.Msg) bool {
	q := msg.Question[0]
	return q.Qclass == dns.ClassINET && q.Qtype == dns.TypeA
}

func HasAQuadAQuestion(msg *dns.Msg) bool {
	return HasAAAAQuestion(msg) || HasAQuestion(msg)
}

func MakeARecord(qname string, ip4 string, expiry int) dns.RR {
	if len(ip4) <= 0 || len(qname) <= 0 {
		return nil
	}
	ttl := uint32(expiry)

	b := net.ParseIP(ip4)
	if len(b) <= 0 {
		return nil
	}

	rec := new(dns.A)
	rec.Hdr = dns.RR_Header{
		Name:   qname,
		Rrtype: dns.TypeA,
		Class:  dns.ClassINET,
		Ttl:    ttl,
	}
	rec.A = b
	return rec
}

func MakeAAAARecord(qname string, ip6 string, expiry int) dns.RR {
	if len(ip6) <= 0 || len(qname) <= 0 {
		return nil
	}
	ttl := uint32(expiry)

	b := net.ParseIP(ip6)
	if len(b) <= 0 {
		return nil
	}

	rec := new(dns.AAAA)
	rec.Hdr = dns.RR_Header{
		Name:   qname,
		Rrtype: dns.TypeAAAA,
		Class:  dns.ClassINET,
		Ttl:    ttl,
	}
	rec.AAAA = b
	return rec
}

func MaybeToQuadA(answer dns.RR, prefix *net.IPNet) dns.RR {
	header := answer.Header()
	if header.Rrtype != dns.TypeA {
		return answer
	}
	ipv4 := answer.(*dns.A).A.To4()
	// TODO: refuse to translate bogons
	if ipv4 == nil {
		return nil
	}
	ttl := uint32(300) // 5 minutes
	if ttl > header.Ttl {
		ttl = header.Ttl
	}

	ipv6 := ip4to6(prefix, ipv4)

	trec := new(dns.AAAA)
	trec.Hdr = dns.RR_Header{
		Name:   header.Name,
		Rrtype: dns.TypeAAAA,
		Class:  header.Class,
		Ttl:    ttl,
	}
	trec.AAAA = ipv6
	return trec
}

func ToIp6Hint(answer dns.RR, prefix *net.IPNet) dns.RR {
	header := answer.Header()
	var kv []dns.SVCBKeyValue
	if header.Rrtype == dns.TypeHTTPS {
		kv = answer.(*dns.HTTPS).Value
	} else if header.Rrtype == dns.TypeSVCB {
		kv = answer.(*dns.SVCB).Value
	} else {
		log.Warnf("toIp6Hint: Not a svcb/https record/1")
		return nil
	}

	if len(kv) <= 0 {
		return nil
	}
	ttl := uint32(300) // 5 minutes

	hint4 := make([]string, 0)
	rest := make([]dns.SVCBKeyValue, 0)
	for _, x := range kv {
		if x.Key() == dns.SVCB_IPV6HINT {
			// ipv6hint found, no need to translate ipv4s
			return nil
		} else if x.Key() == dns.SVCB_IPV4HINT {
			ipstr := x.String()
			if len(ipstr) <= 0 {
				continue
			}
			hint4 = append(hint4, strings.Split(ipstr, ",")...)
		} else {
			rest = append(rest, x)
		}
	}

	hint6 := new(dns.SVCBIPv6Hint)
	for _, x := range hint4 {
		ip4 := net.ParseIP(x)
		if ip4 == nil {
			log.Warnf("dnsutil: invalid https/svcb ipv4hint %s", x)
			continue
		}
		hint6.Hint = append(hint6.Hint, ip4to6(prefix, ip4))
	}

	if header.Rrtype == dns.TypeSVCB {
		trec := new(dns.SVCB)
		trec.Hdr = dns.RR_Header{
			Name:   header.Name,
			Rrtype: header.Rrtype,
			Class:  header.Class,
			Ttl:    ttl,
		}
		trec.Value = append(rest, hint6)
		return trec
	} else if header.Rrtype == dns.TypeHTTPS {
		trec := new(dns.HTTPS)
		trec.Hdr = dns.RR_Header{
			Name:   header.Name,
			Rrtype: header.Rrtype,
			Class:  header.Class,
			Ttl:    ttl,
		}
		trec.Value = append(rest, hint6)
		return trec
	} else {
		// should never happen
		log.Errorf("toIp6Hint: Not a svcb/https record/2")
		return nil
	}
}

func ip4to6(prefix6 *net.IPNet, ip4 net.IP) net.IP {
	ip6 := make(net.IP, net.IPv6len)
	copy(ip6, prefix6.IP)
	n, _ := prefix6.Mask.Size()
	ipShift := n / 8
	for i := 0; i < net.IPv4len; i++ {
		// skip byte 8, datatracker.ietf.org/doc/html/rfc6052#section-2.2
		if ipShift+i == 8 {
			ipShift++
		}
		ip6[ipShift+i] = ip4[i]
	}
	return ip6
}

func AQuadAUnspecified(msg *dns.Msg) bool {
	ans := msg.Answer
	for _, rr := range ans {
		switch v := rr.(type) {
		case *dns.AAAA:
			if net.IPv6zero.Equal(v.AAAA) {
				return true
			}
		case *dns.A:
			if net.IPv4zero.Equal(v.A) {
				return true
			}
		}
	}
	return false
}

// Servfail returns a SERVFAIL response to the query q.
func Servfail(q []byte) []byte {
	msg := &dns.Msg{}
	if err := msg.Unpack(q); err != nil {
		log.Warnf("Error reading q for servfail: %v", err)
		return nil
	}
	msg.Response = true
	msg.RecursionAvailable = true
	msg.Rcode = dns.RcodeServerFailure
	msg.Extra = nil
	b, err := msg.Pack()
	if err != nil {
		log.Warnf("Error constructing servfail: %v", err)
	}
	return b
}

// GetBlocklistStampHeaderKey returns the http-header key for blocklists stamp
func GetBlocklistStampHeaderKey() string {
	return http.CanonicalHeaderKey(blocklistHeaderKey)
}
