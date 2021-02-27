// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

import (
	b64 "encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"runtime"
	"strings"

	"github.com/Jigsaw-Code/outline-go-tun2socks/tunnel/intra/xdns"

	"github.com/celzero/gotrie/trie"
	"github.com/miekg/dns"
)

const (
	blocklistHeaderKey = "x-nile-flags" // "x-bl-fl"
	localBlock         = 0
	remoteBlock        = 1
)

type BraveDNS interface {

	// Mode
	OnDeviceBlock() bool

	SetStamp(string) error

	GetStamp() (string, error)

	// GetBlocklistStampHeaderKey returns the http-header key for blocklists stamp
	GetBlocklistStampHeaderKey() string

	// BlocklistsStampToNames returns csv separated group:names of blocklists in the given stamp
	StampToNames(stamp string) (string, error)

	BlockRequest([]byte) (string, error)

	BlockResponse([]byte) (string, error)
}

type bravedns struct {
	BraveDNS
	trie  *trie.FrozenTrie
	flags []string
	tags  map[string]string
	mode  int
	stamp string
}

func (brave *bravedns) OnDeviceBlock() bool {
	return brave.mode == localBlock
}

func (brave *bravedns) GetStamp() (s string, err error) {
	if len(brave.stamp) <= 0 {
		err = errors.New("no stamp")
		return
	}
	s = brave.stamp
	return
}

func (brave *bravedns) SetStamp(stamp string) error {
	// validate
	if _, err := brave.StampToNames(stamp); err != nil {
		return err
	}
	brave.stamp = stamp
	return nil
}

func (brave *bravedns) GetBlocklistStampHeaderKey() string {
	return http.CanonicalHeaderKey(blocklistHeaderKey)
}

func (brave *bravedns) StampToNames(stamp string) (string, error) {
	if len(stamp) <= 0 {
		errors.New("empty blocklist stamp")
	}

	var blocklists []string
	var err error
	s := strings.Split(stamp, ":")
	if len(s) > 1 {
		blocklists, err = brave.decode(s[1], s[0])
	} else {
		blocklists, err = brave.decode(stamp, "0")
	}

	if err != nil {
		return "", err
	}

	return strings.Join(blocklists[:], ","), nil
}

func (brave *bravedns) keyToNames(list []string) (v []string) {
	for _, l := range list {
		x := brave.tags[l]
		if len(x) > 0 { // TODO: else err?
			v = append(v, x)
		}
	}
	return
}

func (brave *bravedns) BlockRequest(q []byte) (r string, err error) {
	msg := dns.Msg{}
	if err = msg.Unpack(q); err != nil {
		return
	}
	return brave.blockUnpackedRequest(&msg)
}

func (brave *bravedns) blockUnpackedRequest(msg *dns.Msg) (r string, err error) {
	if len(msg.Question) != 1 {
		err = errors.New("one question too many")
		return
	}
	stamp, err := brave.GetStamp()
	if err != nil {
		return
	}
	// err when incoming name != ascii, ignore
	qname, _ := xdns.NormalizeQName(msg.Question[0].Name)
	qtype := msg.Question[0].Qtype
	if qtype != dns.TypeAAAA && qtype != dns.TypeA {
		err = fmt.Errorf("unsupported dns query type %v", qtype)
		return
	}
	block, lists := brave.trie.DNlookup(qname, stamp)
	// TODO: handle empty lists as err?
	if block {
		r = strings.Join(brave.keyToNames(lists), ",")
		return
	}
	err = fmt.Errorf("%v name not in blocklist %s [%s]", qname, stamp, block)
	return
}

func (brave *bravedns) BlockResponse(q []byte) (r string, err error) {
	msg := dns.Msg{}
	if err = msg.Unpack(q); err != nil {
		return
	}
	return brave.blockUnpackedResponse(&msg)
}

func (brave *bravedns) blockUnpackedResponse(msg *dns.Msg) (r string, err error) {
	if len(msg.Answer) <= 1 {
		err = errors.New("req at least two answers")
		return
	}
	stamp, err := brave.GetStamp()
	if err != nil {
		return
	}

	cnamed := false
	anstype := dns.TypeNone
	ansname := ""
	// TODO: SVCB/HTTPS tools.ietf.org/html/draft-ietf-dnsop-svcb-https-01
	for _, a := range msg.Answer {
		switch a.(type) {
		case *dns.CNAME:
			cnamed = true
		case *dns.A:
			anstype = dns.TypeA
			ansname = a.Header().Name
		case *dns.AAAA:
			anstype = dns.TypeAAAA
			ansname = a.Header().Name
		default:
			// nothing to do
		}
	}
	if cnamed == false || len(ansname) <= 0 {
		err = fmt.Errorf("not cnamed")
		return
	}
	if anstype != dns.TypeAAAA && anstype != dns.TypeA {
		err = fmt.Errorf("not a or aaaa")
		return
	}
	// err when incoming name != ascii, ignore
	ansname, _ = xdns.NormalizeQName(ansname)

	block, lists := brave.trie.DNlookup(ansname, stamp)
	// TODO: handle empty lists as err?
	if block {
		r = strings.Join(brave.keyToNames(lists), ",")
		return
	}
	err = fmt.Errorf("%v cloaked domain not in blocklist %s", ansname, stamp)
	return
}

func NewBraveDNSRemote(listinfo string) (BraveDNS, error) {
	flags, tags, err := load(listinfo)
	if err != nil {
		return nil, err
	}
	return &bravedns{
		flags: flags,
		tags:  tags,
		mode:  remoteBlock,
	}, nil
}

func NewBraveDNSLocal(t string, rank string,
	conf string, listinfo string) (BraveDNS, error) {

	if len(t) <= 0 || len(rank) <= 0 || len(conf) <= 0 || len(listinfo) <= 0 {
		return nil, errors.New("missing data, unable to build blocklist")
	}

	err, trie := trie.Build(t, rank, conf, listinfo)

	if err != nil {
		return nil, err
	}

	flags, tags, err := load(listinfo)

	if err != nil {
		return nil, err
	}

	// TODO: find a better place
	runtime.GC()

	// https://docs.pi-hole.net/ftldns/blockingmode/
	return &bravedns{
		trie:  &trie,
		flags: flags,
		tags:  tags,
		mode:  localBlock,
	}, nil
}

func load(blacklistconfigjson string) ([]string, map[string]string, error) {
	data, err := ioutil.ReadFile(blacklistconfigjson)
	if err != nil {
		return nil, nil, err
	}

	var obj map[string]interface{}
	err = json.Unmarshal(data, &obj)
	if err != nil {
		return nil, nil, err
	}

	rflags := make([]string, len(obj))
	fdata := make(map[string]string)
	for key := range obj {
		indata := obj[key].(map[string]interface{})
		index := int(indata["value"].(float64))
		name := indata["vname"].(string)
		subgroup := indata["subg"].(string)
		group := indata["group"].(string)

		if len(subgroup) <= 0 {
			subgroup = group
		}
		if len(name) <= 0 {
			name = subgroup
			subgroup = group
		}
		rflags[index] = subgroup + ":" + name
		fdata[key] = subgroup + ":" + name
	}
	return rflags, fdata, nil
}

func (brave *bravedns) decode(stamp string, ver string) (tags []string, err error) {
	decoder := b64.StdEncoding
	if ver == "0" {
		stamp, err = url.QueryUnescape(stamp)
	} else if ver == "1" {
		stamp, err = url.PathUnescape(stamp)
		decoder = b64.URLEncoding
	} else {
		err = fmt.Errorf("version does not exist", ver)
	}
	if err != nil {
		return nil, err
	}

	buf, err := decoder.DecodeString(stamp)
	if err != nil {
		return
	}

	var u16 []uint16
	if ver == "0" {
		u16 = stringtouint(string(buf))
	} else if ver == "1" {
		u16 = bytestouint(buf)
	} else {
		err = fmt.Errorf("unimplemented header stamp version %v", ver)
		return
	}
	return brave.flagstotag(u16)
}

func (brave *bravedns) flagstotag(flags []uint16) ([]string, error) {
	// flags has to be an array of 16-bit integers.

	// first index always contains the header
	header := uint16(flags[0])
	// store of each big-endian position of set bits in header
	tagIndices := []int{}
	values := []string{}
	var mask uint16

	// b1000,0000,0000,0000
	mask = 0x8000

	// read first 16 header bits from msb to lsb
	// and capture indices of set bits in tagIndices
	for i := 0; i < 16; i++ {
		if (header << i) == 0 {
			break
		}
		if (header & mask) == mask {
			tagIndices = append(tagIndices, i)
		}
		mask = mask >> 1 // shift to read the next msb bit
	}
	// the number of set bits in header must correspond to total
	// blocklist "flags" excluding the header at position 0
	if len(tagIndices) != (len(flags) - 1) {
		err := fmt.Errorf("%v %v flags and header mismatch", tagIndices, flags)
		return nil, err
	}

	// for all blocklist flags excluding the header
	// figure out the blocklist-ids
	for i := 1; i < len(flags); i++ {
		// 16 blocklists are represented by one flag
		// that is, one bit per blocklist
		var flag = uint16(flags[i])
		// get the index of the current flag in the header
		var index = tagIndices[i-1]
		mask = 0x8000
		// for each of the 16 bits in the flag
		// capture the set bits and calculate
		// its actual decimal value, the blocklist-id
		for j := 0; j < 16; j++ {
			if (flag << j) == 0 {
				break
			}
			if (flag & mask) == mask {
				pos := (index * 16) + j
				// from the decimal value which is its
				// blocklist-id, fetch its metadata
				values = append(values, brave.flags[pos])
			}
			mask = mask >> 1
		}
	}
	return values, nil
}

func stringtouint(str string) []uint16 {
	runedata := []rune(str)
	resp := make([]uint16, len(runedata))
	for key, value := range runedata {
		resp[key] = uint16(value)
	}
	return resp
}

func bytestouint(b []byte) []uint16 {
	data := make([]uint16, len(b)/2)
	for i := range data {
		// assuming little endian
		data[i] = binary.LittleEndian.Uint16(b[i*2 : (i+1)*2])
	}
	return data
}
