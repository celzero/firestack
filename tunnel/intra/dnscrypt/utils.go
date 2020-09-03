package dnscrypt

import (
	"encoding/binary"
	"errors"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/miekg/dns"
)

func EmptyResponseFromMessage(srcMsg *dns.Msg) *dns.Msg {
	dstMsg := dns.Msg{MsgHdr: srcMsg.MsgHdr, Compress: true}
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

func TransactionID(packet []byte) uint16 {
	return binary.BigEndian.Uint16(packet[0:2])
}

func SetTransactionID(packet []byte, tid uint16) {
	binary.BigEndian.PutUint16(packet[0:2], tid)
}

func Rcode(packet []byte) uint8 {
	return packet[3] & 0xf
}

func NormalizeRawQName(name *[]byte) {
	for i, c := range *name {
		if c >= 65 && c <= 90 {
			(*name)[i] = c + 32
		}
	}
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

func removeEDNS0Options(msg *dns.Msg) bool {
	edns0 := msg.IsEdns0()
	if edns0 == nil {
		return false
	}
	edns0.Option = []dns.EDNS0{}
	return true
}

func addEDNS0PaddingIfNoneFound(msg *dns.Msg, unpaddedPacket []byte, paddingLen int) ([]byte, error) {
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

// remove removes elements at indices r from a ascii string slice s
func remove(s []string, r []int) []string {
	// TODO: check if the max(r...) is within len(s)
	// FIXME: s shouldn't contain empty string
	for _, x := range(r) {
		s[x] = ""
	}
	// expect sort to group empty strings to the top
	sort.Strings(s)
	// slice out the top-half that's likely to be r
    return s[len(r):]
}

// remove removes elements at indices r from a ascii string slice s
// and returns a slice
func removeOverlap(s []string, r []string) []string {
	// TODO: check if the max(r...) is within len(s)
	// FIXME: s shouldn't contain empty string
	var j int = 0
	for _, x := range(s) {
		var skip bool = false
		for _, y := range(r) {
			if (x == y) {
				skip = true
				break
			}
		}
		if (!skip) {
			s[j] = x
			j++
		}
	}
	// slice out the bottom-half to be removed
    return s[:j]
}

// returns unique strings in n not in s and returns a new array
func findUnique(s []string, n []string) []string {
	if (len(s) == 0) {
		return n
	}
	if (len(n) == 0) {
		return nil
	}

	var u []string
	
	for _, e := range n {
		uniq := true
		for _, x := range s {
        	if e == x {
				uniq = false
            	break
			}
		}
		if uniq {
			u = append(u, e)
		}
	}

    return u
}