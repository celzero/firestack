// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package rdns

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

	"github.com/miekg/dns"

	"github.com/celzero/firestack/intra/xdns"

	"github.com/celzero/gotrie/trie"
)

const (
	blocklistHeaderKey = "x-nile-flags"
	localBlock         = 0
	remoteBlock        = 1
)

type RethinkDNS interface {

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

type rethinkdns struct {
	RethinkDNS
	trie  *trie.FrozenTrie
	flags []string
	tags  map[string]string
	mode  int
	stamp string
}

func (rdns *rethinkdns) OnDeviceBlock() bool {
	return rdns.mode == localBlock
}

func (rdns *rethinkdns) GetStamp() (s string, err error) {
	if len(rdns.stamp) <= 0 {
		err = errors.New("no stamp")
		return
	}
	s = rdns.stamp
	return
}

func (rdns *rethinkdns) SetStamp(stamp string) error {
	// validate
	if _, err := rdns.StampToNames(stamp); err != nil {
		return err
	}
	rdns.stamp = stamp
	return nil
}

func (rdns *rethinkdns) GetBlocklistStampHeaderKey() string {
	return http.CanonicalHeaderKey(blocklistHeaderKey)
}

func (rdns *rethinkdns) StampToNames(stamp string) (string, error) {
	if len(stamp) <= 0 {
		return "", errors.New("empty blocklist stamp")
	}

	var blocklists []string
	var err error
	s := strings.Split(stamp, ":")
	if len(s) > 1 {
		blocklists, err = rdns.decode(s[1], s[0])
	} else {
		blocklists, err = rdns.decode(stamp, "0")
	}

	if err != nil {
		return "", err
	}

	return strings.Join(blocklists[:], ","), nil
}

func (rdns *rethinkdns) keyToNames(list []string) (v []string) {
	for _, l := range list {
		x := rdns.tags[l]
		if len(x) > 0 { // TODO: else err?
			v = append(v, x)
		}
	}
	return
}

func (rdns *rethinkdns) BlockRequest(q []byte) (r string, err error) {
	msg := dns.Msg{}
	if err = msg.Unpack(q); err != nil {
		return
	}
	return rdns.blockUnpackedRequest(&msg)
}

func (rdns *rethinkdns) blockUnpackedRequest(msg *dns.Msg) (r string, err error) {
	if len(msg.Question) != 1 {
		err = errors.New("one question too many")
		return
	}
	stamp, err := rdns.GetStamp()
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
	block, lists := rdns.trie.DNlookup(qname, stamp)
	// TODO: handle empty lists as err?
	if block {
		r = strings.Join(rdns.keyToNames(lists), ",")
		return
	}
	err = fmt.Errorf("%v name not in blocklist %s [%t]", qname, stamp, block)
	return
}

func (rdns *rethinkdns) BlockResponse(q []byte) (r string, err error) {
	msg := dns.Msg{}
	if err = msg.Unpack(q); err != nil {
		return
	}
	return rdns.blockUnpackedResponse(&msg)
}

func (rdns *rethinkdns) blockUnpackedResponse(msg *dns.Msg) (r string, err error) {
	if len(msg.Answer) <= 1 {
		err = errors.New("req at least two answers")
		return
	}
	stamp, err := rdns.GetStamp()
	if err != nil {
		return
	}

	// handle cname, https/svcb name cloaking: news.ycombinator.com/item?id=26298339
	// adopted from: github.com/DNSCrypt/dnscrypt-proxy/blob/6e8628f79/dnscrypt-proxy/plugin_block_name.go#L178
	for _, a := range msg.Answer {
		var target string
		switch r := a.(type) {
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
		}

		// err when incoming name != ascii, ignore
		target, _ = xdns.NormalizeQName(target)
		block, lists := rdns.trie.DNlookup(target, stamp)
		if block { // TODO: handle empty lists as err?
			r = strings.Join(rdns.keyToNames(lists), ",")
			return
		}
	}

	err = fmt.Errorf("answers not in blocklist %s", stamp)
	return
}

func NewRethinkDNSRemote(listinfo string) (RethinkDNS, error) {
	flags, tags, err := load(listinfo)
	if err != nil {
		return nil, err
	}
	return &rethinkdns{
		flags: flags,
		tags:  tags,
		mode:  remoteBlock,
	}, nil
}

func NewRethinkDNSLocal(t string, rank string,
	conf string, listinfo string) (RethinkDNS, error) {

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
	return &rethinkdns{
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

func (rdns *rethinkdns) decode(stamp string, ver string) (tags []string, err error) {
	decoder := b64.StdEncoding
	if ver == "0" {
		stamp, err = url.QueryUnescape(stamp)
	} else if ver == "1" {
		stamp, err = url.PathUnescape(stamp)
		decoder = b64.URLEncoding
	} else {
		err = fmt.Errorf("version %s does not exist", ver)
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
	return rdns.flagstotag(u16)
}

func (rdns *rethinkdns) flagstotag(flags []uint16) ([]string, error) {
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
				values = append(values, rdns.flags[pos])
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
