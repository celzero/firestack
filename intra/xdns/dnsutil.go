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
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/miekg/dns"
)

func AsMsg(packet []byte) *dns.Msg {
	msg, err := AsMsg2(packet)
	if err != nil {
		log.W("dnsutil: as msg err: %v", err)
	}
	return msg
}

func AsMsg2(packet []byte) (*dns.Msg, error) {
	if len(packet) < MinDNSPacketSize {
		return nil, errNoPacket
	}
	msg := &dns.Msg{}
	if err := msg.Unpack(packet); err != nil {
		log.D("dnsutil: failed to unpack msg: %v", err)
		return nil, err
	}
	return msg, nil
}

func RequestFromResponse(msg *dns.Msg) *dns.Msg {
	req := &dns.Msg{
		Compress: true,
	}
	req.SetQuestion(QName(msg), QType(msg))
	req.RecursionDesired = true
	req.CheckingDisabled = false
	req.AuthenticatedData = false
	req.Authoritative = false
	req.Id = msg.Id
	return req
}

func Request4FromResponse6(msg6 *dns.Msg) *dns.Msg {
	if !HasAnyQuestion(msg6) {
		return nil
	}
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
	if !HasAnyQuestion(msg6) {
		return nil
	}
	msg4 := msg6.Copy()
	msg4.SetQuestion(QName(msg6), dns.TypeA)
	return msg4
}

func EmptyResponseFromMessage(srcMsg *dns.Msg) *dns.Msg {
	if !HasAnyQuestion(srcMsg) {
		return nil
	}
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
	if len(packet) <= 0 {
		return nil, errNoAns
	}
	srcMsg := &dns.Msg{}
	if err := srcMsg.Unpack(packet); err != nil {
		return nil, err
	}
	dstMsg := EmptyResponseFromMessage(srcMsg) // may be nil
	if dstMsg == nil {
		return nil, errNoAns
	}
	dstMsg.Truncated = true
	return dstMsg.Pack()
}

func HasTCFlag(msg *dns.Msg) bool {
	if msg == nil {
		return false
	}
	return msg.Truncated
}

func HasTCFlag2(packet []byte) bool {
	if len(packet) < 2 {
		return false
	}
	return packet[2]&2 == 2
}

func QName(msg *dns.Msg) string {
	if msg == nil || !HasAnyQuestion(msg) {
		return ""
	}
	q := msg.Question[0]
	return q.Name
}

func AName(ans dns.RR) (string, error) {
	if ans != nil {
		if ah := ans.Header(); ah != nil {
			n := ah.Name
			return NormalizeQName(n)
		}
	}
	return "", errNoAns
}

func QType(msg *dns.Msg) uint16 {
	if HasAnyQuestion(msg) {
		return msg.Question[0].Qtype
	}
	return dns.TypeNone
}

func Rcode(msg *dns.Msg) int {
	if msg != nil {
		return msg.Rcode
	}
	return dns.RcodeFormatError
}

func WithTtl(msg *dns.Msg, secs uint32) (ok bool) {
	if !HasAnyAnswer(msg) {
		return ok
	}
	for _, a := range msg.Answer {
		if a.Header().Ttl > 0 {
			a.Header().Ttl = secs
			ok = true
		}
	}
	return ok
}

func RTtl(msg *dns.Msg) int {
	maxttl := uint32(0)
	if msg == nil || !HasAnyAnswer(msg) {
		return int(maxttl)
	}

	for _, a := range msg.Answer {
		if a.Header().Ttl > 0 {
			ttl := a.Header().Ttl
			if maxttl < ttl {
				maxttl = ttl
			}
		}
	}
	return int(maxttl)
}

func GetInterestingRData(msg *dns.Msg) string {
	if msg == nil {
		return "--"
	}
	var ipcsv string
	ip4s := IPHints(msg, dns.SVCB_IPV4HINT)
	ip6s := IPHints(msg, dns.SVCB_IPV6HINT)
	data := make([]string, 0)
	if len(ip4s) > 0 {
		data = append(data, netips2str(ip4s)...)
	}
	if len(ip6s) > 0 {
		data = append(data, netips2str(ip6s)...)
	}
	if len(data) > 0 {
		ipcsv += strings.Join(data, ",")
		log.D("dnsutil: RData: %s", ipcsv)
	}
	for _, a := range msg.Answer {
		switch r := a.(type) {
		case *dns.A:
			if len(ipcsv) > 0 {
				ipcsv += "," + ip2str(r.A)
			} else {
				ipcsv += ip2str(r.A)
			}
		case *dns.AAAA:
			if len(ipcsv) > 0 {
				ipcsv += "," + ip2str(r.AAAA)
			} else {
				ipcsv += ip2str(r.AAAA)
			}
		case *dns.NS:
			return r.Ns
		case *dns.TXT:
			if len(r.Txt) > 0 {
				return r.Txt[0]
			}
			return r.String()
		case *dns.SOA:
			return r.Mbox
		case *dns.HINFO:
			return r.Os
		case *dns.SRV:
			return r.Target
		case *dns.CAA:
			return r.Value
		case *dns.MX:
			return r.Mx
		case *dns.RP:
			return r.Mbox
		case *dns.DNSKEY:
			return r.PublicKey
		case *dns.DS:
			return r.Digest
		case *dns.RRSIG:
			return r.SignerName
		case *dns.SVCB:
			// if no hints, simply dump the entire kv list
			if len(ip4s) <= 0 && len(ip6s) <= 0 {
				if len(ipcsv) > 0 {
					ipcsv += "," + r.String()
				} else {
					log.V("dnsutil: RData: svcb(%s)", r.String())
					return svcbstr(r)
				}
			} else {
				log.D("dnsutil: RData: ignored svcb(%s) for ipcsv(%s)", r.String(), ipcsv)
			}
			continue
		case *dns.HTTPS:
			// if no hints, simply dump the entire kv list
			if len(ip4s) <= 0 && len(ip6s) <= 0 {
				if len(ipcsv) > 0 {
					ipcsv += "," + r.String()
				} else {
					log.V("dnsutil: RData: https(%s)", r.String())
					return httpsstr(r)
				}
			} else {
				log.D("dnsutil: RData: ignored https(%s) for ipcsv(%s)", r.String(), ipcsv)
			}
			continue
		case *dns.NSEC:
			return r.NextDomain
		case *dns.NSEC3:
			return r.NextDomain
		case *dns.NSEC3PARAM:
			return r.Salt
		case *dns.TLSA:
			return r.Certificate
		case *dns.OPT:
			if len(ipcsv) > 0 {
				ipcsv += "," + r.String()
			} else {
				return r.String()
			}
		case *dns.APL:
			if len(ipcsv) > 0 {
				ipcsv += "," + r.String()
			} else {
				return r.String()
			}
		case *dns.SSHFP:
			return r.FingerPrint
		case *dns.DNAME:
			return r.Target
		case *dns.NAPTR:
			return r.Service
		case *dns.CERT:
			return r.Certificate
		case *dns.DLV:
			return r.Digest
		case *dns.DHCID:
			return r.Digest
		case *dns.SMIMEA:
			return r.Certificate
		case *dns.NINFO:
			var str string
			if len(r.ZSData) > 0 {
				str = r.ZSData[0]
			} else {
				str = r.String()
			}
			if len(ipcsv) > 0 {
				ipcsv += "," + str
			} else {
				return str
			}
		case *dns.RKEY:
			return r.PublicKey
		case *dns.TKEY:
			return r.OtherData
		case *dns.TSIG:
			return r.OtherData
		case *dns.URI:
			return r.Target
		case *dns.HIP:
			return r.PublicKey
		case *dns.CDS:
			return r.Digest
		case *dns.OPENPGPKEY:
			return r.PublicKey
		case *dns.SPF:
			var str string
			if len(r.Txt) > 0 {
				return r.Txt[0]
			} else {
				str = r.String()
			}
			if len(ipcsv) > 0 {
				ipcsv += "," + str
			} else {
				return str
			}
		case *dns.NSAPPTR:
			return r.Ptr
		case *dns.TALINK:
			return r.NextName
		case *dns.CSYNC:
			if len(ipcsv) > 0 {
				ipcsv += "," + r.String()
			} else {
				return r.String()
			}
		case *dns.ZONEMD:
			return r.Digest
		default:
			// no-op
			continue
		}
	}
	if len(ipcsv) > 0 {
		return strings.TrimSuffix(ipcsv, ",")
	} else {
		return "--"
	}
}

func Targets(msg *dns.Msg) (targets []string) {
	if msg == nil {
		return targets
	}
	touched := make(map[string]any)
	if qname, err := NormalizeQName(QName(msg)); err == nil {
		targets = append(targets, qname)
		touched[qname] = struct{}{}
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
		} else if x, err := NormalizeQName(target); err == nil {
			if _, ok := touched[x]; !ok {
				targets = append(targets, x)
				touched[x] = struct{}{}
			}
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
			return str, errNotAscii
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
	if msg == nil {
		return false
	}
	edns0 := msg.IsEdns0()
	if edns0 == nil {
		return false
	}
	edns0.Option = []dns.EDNS0{}
	return true
}

func AddEDNS0PaddingIfNoneFound(msg *dns.Msg, unpaddedPacket []byte, paddingLen int) ([]byte, error) {
	if msg == nil || paddingLen <= 0 {
		return unpaddedPacket, nil
	}
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
		return nil, errNoPacket
	}
	dstMsg = EmptyResponseFromMessage(srcMsg) // may be nil
	if dstMsg == nil {
		return nil, errNoPacket
	}
	dstMsg.Rcode = dns.RcodeSuccess
	ttl := BlockTTL

	questions := srcMsg.Question
	if len(questions) == 0 {
		log.W("dnsutil: no q in msg %s", srcMsg)
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
		rr.A = ip4zero.To4()
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
		rr.AAAA = ip6zero.To16()
		if rr.AAAA != nil {
			dstMsg.Answer = []dns.RR{rr}
			sendHInfoResponse = false
		}
	} else if IsSVCBQuestion(&question) || IsHTTPQuestion(&question) {
		// NODATA datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/11 pg 37
		// prefetch.net/blog/2016/09/28/the-subtleties-between-the-nxdomain-noerror-and-nodata-dns-response-codes/
		dstMsg.Answer = nil
		// NOEXTRA datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/11 pg 16 sec 4.2
		dstMsg.Extra = nil
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

func AQuadAForQuery(q *dns.Msg, ips ...netip.Addr) (a *dns.Msg, err error) {
	if q == nil {
		return nil, errNoPacket
	}
	a = EmptyResponseFromMessage(q) // may be nil
	if a == nil {
		return nil, errNoPacket
	}
	a.Rcode = dns.RcodeSuccess
	ttl := AnsTTL

	questions := q.Question
	if len(questions) == 0 {
		log.W("dnsutil: no q in msg %s", q)
		return
	}

	hasanswers := false
	question := questions[0]

	for _, ip := range ips {
		ipun := ip.Unmap()
		is4 := ipun.Is4()
		is6 := ip.Is6()

		if question.Qtype == dns.TypeA && is4 {
			rr := new(dns.A)
			rr.Hdr = dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			}
			rr.A = ipun.AsSlice()
			if len(rr.A) > 0 {
				hasanswers = true
				a.Answer = append(a.Answer, rr)
			}
		} else if question.Qtype == dns.TypeAAAA && is6 {
			rr := new(dns.AAAA)
			rr.Hdr = dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			}
			rr.AAAA = ip.AsSlice()
			if len(rr.AAAA) > 0 {
				hasanswers = true
				a.Answer = append(a.Answer, rr)
			}
		}
	}
	if !hasanswers {
		log.E("dnsutil: unexpected q %d(%s) for ans(%s)", question.Qtype, question.Name, ips)
		return nil, errNoAns
	}

	return
}

func HasRcodeSuccess(msg *dns.Msg) bool {
	return msg != nil && msg.Rcode == dns.RcodeSuccess
}

func HasAnyAnswer(msg *dns.Msg) bool {
	return msg != nil && len(msg.Answer) > 0
}

func IsNXDomain(msg *dns.Msg) bool {
	return msg != nil && msg.Rcode == dns.RcodeNameError
}

func IsARecord(rr dns.RR) bool {
	return rr != nil && core.IsNotNil(rr) && rr.Header().Rrtype == dns.TypeA
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

func SubstAAAARecords(out *dns.Msg, subip6s []*netip.Addr, ttl int) bool {
	if out == nil || len(subip6s) == 0 {
		return false
	}
	// substitute ips in any a / aaaa records
	touched := make(map[string]any)
	rrs := make([]dns.RR, 0)
	i := 0
	for _, answer := range out.Answer {
		switch rec := answer.(type) {
		case *dns.AAAA:
			// one aaaa rec per name
			if _, ok := touched[rec.Hdr.Name]; !ok {
				name := rec.Hdr.Name
				ip6 := subip6s[i].String() // todo: use different ips for different names
				touched[rec.Hdr.Name] = struct{}{}
				if aaaanew := MakeAAAARecord(name, ip6, ttl); aaaanew != nil {
					rrs = append(rrs, aaaanew)
					i = (i + 1) % len(subip6s)
				} else {
					log.D("dnsutil: subst AAAA rec fail for %s %s %d", name, ip6, ttl)
				}
			}
		default:
			// append cnames and other records as is
			rrs = append(rrs, rec)
		}
	}
	if len(rrs) > 0 {
		out.Answer = rrs
	}
	return len(touched) > 0
}

func SubstARecords(out *dns.Msg, subip4s []*netip.Addr, ttl int) bool {
	if out == nil || len(subip4s) == 0 {
		return false
	}
	// substitute ips in any a / aaaa records
	touched := make(map[string]any)
	rrs := make([]dns.RR, 0)
	i := 0
	for _, answer := range out.Answer {
		switch rec := answer.(type) {
		case *dns.A:
			// one a rec per name
			if _, ok := touched[rec.Hdr.Name]; !ok {
				name := rec.Hdr.Name
				ip4 := subip4s[i].Unmap().String() // todo: use different ips for different names
				touched[rec.Hdr.Name] = struct{}{}
				if anew := MakeARecord(name, ip4, ttl); anew != nil {
					rrs = append(rrs, anew)
					i = (i + 1) % len(subip4s)
				} else {
					log.D("dnsutil: subst A rec fail for %s %s %d", name, ip4, ttl)
				}
			}
		default:
			// append cnames and other records as is
			rrs = append(rrs, rec)
		}
	}
	if len(rrs) > 0 {
		out.Answer = rrs
	}
	return len(touched) > 0
}

func svcbstr(r *dns.SVCB) (s string) {
	if r == nil {
		return
	}
	for _, kv := range r.Value {
		k := kv.Key().String()
		v := kv.String()
		s += fmt.Sprintf("%s=%s ", k, v)
	}
	return s
}

func httpsstr(r *dns.HTTPS) (s string) {
	if r == nil {
		return
	}
	for _, kv := range r.Value {
		k := kv.Key().String()
		v := kv.String()
		s += fmt.Sprintf("%s=%s ", k, v)
	}
	return strings.TrimSpace(s)
}

func SubstSVCBRecordIPs(out *dns.Msg, x dns.SVCBKey, subiphints []*netip.Addr, ttl int) bool {
	if out == nil || len(subiphints) == 0 {
		return false
	}
	// substitute ip hints in https / svcb records
	i := 0
	for _, answer := range out.Answer {
		switch rec := answer.(type) {
		case *dns.SVCB:
			for j, kv := range rec.Value {
				k := kv.Key()
				// replace with a single ip hint
				if k == x && x == dns.SVCB_IPV6HINT {
					rec.Value[j] = &dns.SVCBIPv6Hint{
						Hint: []net.IP{subiphints[i].AsSlice()},
					}
					rec.Hdr.Ttl = uint32(ttl)
					i = (i + 1) % len(subiphints)
				} else if k == x && x == dns.SVCB_IPV4HINT {
					rec.Value[j] = &dns.SVCBIPv4Hint{
						Hint: []net.IP{subiphints[i].AsSlice()},
					}
					rec.Hdr.Ttl = uint32(ttl)
					i = (i + 1) % len(subiphints)
				}
			}
		case *dns.HTTPS:
			if rec.Priority == 0 || len(rec.Target) > 1 {
				// no kv pairs to process for https records when pri is 0
				// datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/ section 1.2
				continue
			}
			for j, kv := range rec.Value {
				k := kv.Key()
				// replace with a single ip hint
				if k == x && x == dns.SVCB_IPV6HINT {
					rec.Value[j] = &dns.SVCBIPv6Hint{
						Hint: []net.IP{subiphints[i].AsSlice()},
					}
					rec.Hdr.Ttl = uint32(ttl)
					i = (i + 1) % len(subiphints)
				} else if k == x && x == dns.SVCB_IPV4HINT {
					rec.Value[j] = &dns.SVCBIPv4Hint{
						Hint: []net.IP{subiphints[i].AsSlice()},
					}
					rec.Hdr.Ttl = uint32(ttl)
					i = (i + 1) % len(subiphints)
				}
			}
		}
	}
	if i > 0 {
		// datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/11 pg 16 sec 4.2
		// remove additional records, as they may further have svcb or a / aaaa records
		out.Extra = nil
	}
	return i > 0
}

func IPHints(msg *dns.Msg, x dns.SVCBKey) []*netip.Addr {
	if msg == nil {
		return nil
	}
	qname, _ := NormalizeQName(QName(msg))
	if !HasSVCBQuestion(msg) && !HasHTTPQuestion(msg) {
		log.N("dnsutil: svcb/https(%s): no record(%d)", qname, len(msg.Answer))
		return nil
	}

	// extract ip hints from https / svcb records
	// tools.ietf.org/html/draft-ietf-dnsop-svcb-https-02#section-8.1
	ips := []*netip.Addr{}
	for _, answer := range msg.Answer {
		if !(answer.Header().Rrtype == dns.TypeHTTPS) && !(answer.Header().Rrtype == dns.TypeSVCB) {
			continue
		}
		switch rec := answer.(type) {
		case *dns.SVCB:
			for _, kv := range rec.Value {
				log.V("dnsutil: svcb(%s): current k(%v)/v(%v)", qname, kv.Key(), kv.String())
				if kv.Key() != x {
					continue
				}
				// ipcsv may be "<nil>" or a csv of ips
				ipcsv := kv.String()
				for _, ipstr := range strings.Split(ipcsv, ",") {
					if v, err := netip.ParseAddr(ipstr); err == nil {
						ips = append(ips, &v)
					} else {
						log.W("dnsutil: svcb(%s): could not parse iphint %v", qname, ipstr)
					}
				}
			}
		case *dns.HTTPS:
			for _, kv := range rec.Value {
				log.V("dnsutil: https(%s): current k(%v)/v(%v)", qname, kv.Key(), kv.String())
				if kv.Key() != x {
					continue
				}
				// ipcsv may be "<nil>" or a csv of ips
				ipcsv := kv.String()
				for _, ipstr := range strings.Split(ipcsv, ",") {
					if v, err := netip.ParseAddr(ipstr); err == nil {
						ips = append(ips, &v)
					} else {
						log.W("dnsutil: https(%s): could not parse iphint %v", qname, ipstr)
					}
				}
			}
		}
	}
	log.D("dnsutil: svcb/https(%s): ip hints %v from %d answers", qname, ips, len(msg.Answer))
	return ips
}

func AAnswer(msg *dns.Msg) []*netip.Addr {
	a4 := []*netip.Addr{}
	if msg == nil {
		return a4
	}
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
	if msg == nil {
		return a6
	}
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

// whether the qtype code is a aaaa qtype
func IsAAAAQType(qtype uint16) bool {
	return qtype == dns.TypeAAAA
}

// whether the qtype code is a A qtype
func IsAQType(qtype uint16) bool {
	return qtype == dns.TypeA
}

// whether the qtype code is a https qtype
func IsHTTPSQType(qtype uint16) bool {
	return qtype == dns.TypeHTTPS
}

// whether the qtype code is a svcb qtype
func IsSVCBQType(qtype uint16) bool {
	return qtype == dns.TypeSVCB
}

func HasAnyQuestion(msg *dns.Msg) bool {
	return !(msg == nil || len(msg.Question) <= 0)
}

// whether the given msg (ans/query) has a AAAA question section
func HasAAAAQuestion(msg *dns.Msg) bool {
	if !HasAnyQuestion(msg) {
		return false
	}
	q := msg.Question[0]
	return q.Qclass == dns.ClassINET && IsAAAAQType(q.Qtype)
}

// whether the given msg (ans/query) has a A question section
func HasAQuestion(msg *dns.Msg) bool {
	if !HasAnyQuestion(msg) {
		return false
	}
	q := msg.Question[0]
	return q.Qclass == dns.ClassINET && IsAQType(q.Qtype)
}

// whether question q is a svcb question
func IsSVCBQuestion(q *dns.Question) bool {
	return q != nil && IsSVCBQType(q.Qtype)
}

// whether question q is a https question
func IsHTTPQuestion(q *dns.Question) bool {
	return q != nil && IsHTTPSQType(q.Qtype)
}

// whether the given msg (ans/query) has a a/aaaa question section
func HasAQuadAQuestion(msg *dns.Msg) bool {
	return HasAAAAQuestion(msg) || HasAQuestion(msg)
}

// whether the given msg (ans/query) has a svcb question section
func HasSVCBQuestion(msg *dns.Msg) (ok bool) {
	if !HasAnyQuestion(msg) {
		return false
	} else {
		q := msg.Question[0]
		ok = IsSVCBQuestion(&q)
		log.N("dnsutil: svcb: %v ok? %t", q, ok)
	}
	return
}

// whether the given msg (ans/query) has a https question section
func HasHTTPQuestion(msg *dns.Msg) (ok bool) {
	if !HasAnyQuestion(msg) {
		return false
	} else {
		q := msg.Question[0]
		ok = IsHTTPQuestion(&q)
		log.N("dnsutil: https: %v ok? %t", q, ok)
	}
	return
}

func MakeARecord(name string, ip4 string, expiry int) *dns.A {
	if len(ip4) <= 0 || len(name) <= 0 {
		return nil
	}
	ttl := uint32(expiry)

	b := net.ParseIP(ip4)
	if len(b) <= 0 {
		return nil
	}

	rec := new(dns.A)
	rec.Hdr = dns.RR_Header{
		Name:   name,
		Rrtype: dns.TypeA,
		Class:  dns.ClassINET,
		Ttl:    ttl,
	}
	rec.A = b
	return rec
}

func MakeAAAARecord(name string, ip6 string, expiry int) *dns.AAAA {
	if len(ip6) <= 0 || len(name) <= 0 {
		return nil
	}
	ttl := uint32(expiry)

	b := net.ParseIP(ip6)
	if len(b) <= 0 {
		return nil
	}

	rec := new(dns.AAAA)
	rec.Hdr = dns.RR_Header{
		Name:   name,
		Rrtype: dns.TypeAAAA,
		Class:  dns.ClassINET,
		Ttl:    ttl,
	}
	rec.AAAA = b
	return rec
}

// MaybeToQuadA translates an A record to a AAAA record if the prefix is not nil.
// The ttl of the new record is the minimum of the original ttl and minttl.
// If the prefix is nil or answer has an empty A record, it returns nil.
func MaybeToQuadA(answer dns.RR, prefix *net.IPNet, minttl uint32) *dns.AAAA {
	header := answer.Header()
	if prefix == nil || header.Rrtype != dns.TypeA {
		return nil
	}
	ipxx, aok := answer.(*dns.A)
	if !aok || ipxx == nil || ipxx.A == nil {
		return nil
	}
	ipv4 := ipxx.A.To4()
	if ipv4 == nil { // TODO: do not translate bogons?
		return nil
	}
	ttl := min(minttl, header.Ttl)

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
	if prefix == nil {
		log.W("dnsutil: toIp6Hint: prefix missing?")
		return nil
	}
	var kv []dns.SVCBKeyValue
	switch header.Rrtype {
	case dns.TypeHTTPS:
		if x, ok := answer.(*dns.HTTPS); ok {
			kv = x.Value
		}
	case dns.TypeSVCB:
		if x, ok := answer.(*dns.SVCB); ok {
			kv = x.Value
		}
	default:
		log.W("dnsutil: toIp6Hint: not a svcb/https record/1")
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
			log.W("dnsutil: invalid https/svcb ipv4hint %s", x)
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
		log.E("dnsutil: toIp6Hint: not a svcb/https record/2")
		return nil
	}
}

func ip4to6(prefix6 *net.IPNet, ip4 net.IP) net.IP {
	ip6 := make(net.IP, net.IPv6len)
	if prefix6 == nil || len(ip4) <= 0 {
		return ip6 // all zeros?
	}
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
	if msg == nil {
		return false
	}
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

func Len(msg *dns.Msg) int {
	if msg == nil {
		return 0
	}
	if msg.Response {
		return len(msg.Answer)
	}
	return len(msg.Question)
}

func Ans(msg *dns.Msg) (s string) {
	if msg != nil {
		a := msg.Answer
		if len(a) > 0 {
			for _, rr := range a {
				if rr != nil {
					s += rr.String() + "  "
				}
			}
		}
	}
	return
}

func IsServFailOrInvalid(msg *dns.Msg) bool {
	if msg == nil {
		return true // invalid
	}
	return msg.Rcode == dns.RcodeServerFailure // servfail
}

// Servfail returns a SERVFAIL response to the query q.
func Servfail(q *dns.Msg) *dns.Msg {
	if q == nil {
		log.W("dnsutil: servfail: error reading q")
		return nil
	}
	msg := q.Copy()
	msg.Response = true
	msg.RecursionAvailable = true
	msg.Rcode = dns.RcodeServerFailure
	msg.Extra = nil
	return msg
}

// GetBlocklistStampHeaderKey returns the http-header key for blocklists stamp
func GetBlocklistStampHeaderKey() string {
	return http.CanonicalHeaderKey(blocklistHeaderKey)
}

// GetBlocklistStampHeaderKey1 returns the http-header key for region set by rdns upstream on Fly
func GetRethinkDNSRegionHeaderKey1() string {
	return http.CanonicalHeaderKey(rethinkdnsRegionHeaderKey)
}

// GetBlocklistStampHeaderKey2 returns the http-header key for region set by rdns upstream on Cloudflare
func GetRethinkDNSRegionHeaderKey2() (r string) {
	return http.CanonicalHeaderKey(cfRayHeaderKey)
}

func IsMDNSQuery(qname string) bool {
	svc, _ := extractMDNSDomain(qname)
	// todo: check if tld is valid (local, arpa4, arpa6)
	return len(svc) > 0
}

func ExtractMDNSDomain(msg *dns.Msg) (svc, tld string) {
	if !HasAnyQuestion(msg) {
		return
	}
	svc, _ = NormalizeQName(QName(msg)) // ex: _http._tcp.local.
	return extractMDNSDomain(svc)
}

func extractMDNSDomain(qname string) (svc, tld string) {
	// ref: go.dev/play/p/kqdF0nbJj2B
	// qname is assumed normalized (lower-case, without fqdn trailing dot)
	// example.local. -> example.local
	// rfc6762 sec 4; 254.169.in-addr.arpa
	tldarpa4 := strings.LastIndex(qname, arpa4suffix)
	tldarpa6 := strings.LastIndex(qname, arpa6suffix)
	tldlocal := strings.LastIndex(qname, localsuffix)
	if tldlocal > 0 && tldlocal == len(qname)-len(localsuffix) {
		svc = qname[:tldlocal-1] // remove trailing dot; example. -> example
		tld = localsuffix
	} else if tldarpa4 > 0 {
		svc = qname[:tldarpa4-1] // remove trailing dot
		tld = arpa4suffix
	} else if tldarpa6 > 0 {
		// 1.1.1.1.a.e.f.ip6.arpa. -> a.e.f.ip6.arpa
		tld = qname[tldarpa6-2:tldarpa6] + arpa6suffix
		// 1.1.1.1.a.e.f.ip6.arpa. -> 1.1.1.1
		svc = qname[:tldarpa6-3]
	}
	return
}

func netips2str(addrs []*netip.Addr) []string {
	var str []string
	for _, x := range addrs {
		str = append(str, x.String())
	}
	return str
}

func ip2str(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
