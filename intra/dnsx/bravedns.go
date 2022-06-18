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
	"strconv"
	"strings"

	"github.com/miekg/dns"

	"github.com/celzero/firestack/intra/xdns"

	"github.com/celzero/gotrie/trie"
)

const (
	blocklistHeaderKey = "x-nile-flags" // "x-bl-fl"
	localBlock         = 0
	remoteBlock        = 1
	verseperator       = ":"
)

const (
	ver1 = "1"
	ver0 = "0"
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

	// Returns a blockstamp for given blocklist ids, if valid
	FlagsToStamp(csv string) (string, error)

	// Returns comma-separated blocklist ids given a valid blockstamp
	StampToFlags(s string) (string, error)

	BlockRequest([]byte) (string, error)

	BlockResponse([]byte) (string, error)
}

type bravedns struct {
	BraveDNS
	trie *trie.FrozenTrie
	// value -> group:name
	flags []string
	// uname -> group:name
	tags  map[string]string
	mode  int
	stamp string

	bitsSetTable256 []int
}

type listinfo struct {
	pos  int
	name string
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

// Returns blockstamp given comma-separated blocklist ids
func (brave *bravedns) FlagsToStamp(flagscsv string) (string, error) {
	fstr := strings.Split(flagscsv, ",")
	if len(fstr) <= 0 {
		return "", errors.New("zero comma-separated flags")
	}

	if stamp, err := brave.flagtostamp(fstr); err != nil {
		return "", err
	} else {
		return encode(ver1, stamp)
	}
}

// Returns comma-separated blocklist ids, given a stamp of form version:base64
func (brave *bravedns) StampToFlags(stamp string) (string, error) {
	blocklists, err := brave.stampToBlocklist(stamp)
	if err != nil {
		return "", err
	}

	var blocklistids []string
	for _, x := range blocklists {
		blocklistids = append(blocklistids, fmt.Sprint(x.pos))
	}

	return strings.Join(blocklistids[:], ","), nil
}

func (brave *bravedns) flagstotag(stamp string) (string, error) {
	return brave.StampToNames(stamp)
}

func (brave *bravedns) StampToNames(stamp string) (string, error) {

	blocklists, err := brave.stampToBlocklist(stamp)
	if err != nil {
		return "", err
	}

	var blocklistnames []string
	for _, x := range blocklists {
		blocklistnames = append(blocklistnames, x.name)
	}

	return strings.Join(blocklistnames[:], ","), nil
}

func (brave *bravedns) stampToBlocklist(stamp string) ([]*listinfo, error) {
	if len(stamp) <= 0 {
		return nil, errors.New("empty blocklist stamp")
	}

	s := strings.Split(stamp, verseperator)
	if len(s) > 1 {
		return brave.decode(s[1], s[0])
	} else {
		return brave.decode(stamp, "0")
	}
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

func (brave *bravedns) flagsToNames(flagstr []string) (v []string) {
	for _, entry := range flagstr {
		if i, err := strconv.Atoi(entry); err == nil {
			v = append(v, brave.flags[i])
		} else {
			continue
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
	err = fmt.Errorf("%v name not in blocklist %s [%t]", qname, stamp, block)
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
	if cnamed || len(ansname) <= 0 {
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

func NewBraveDNSRemote(filetagjson string) (BraveDNS, error) {
	flags, tags, err := load(filetagjson)
	if err != nil {
		return nil, err
	}
	b := &bravedns{
		flags: flags,
		tags:  tags,
		mode:  remoteBlock,
	}
	b.initBitSetTable()
	return b, nil
}

func NewBraveDNSLocal(t string, rank string,
	conf string, filetagjson string) (BraveDNS, error) {

	if len(t) <= 0 || len(rank) <= 0 || len(conf) <= 0 || len(filetagjson) <= 0 {
		return nil, errors.New("missing data, unable to build blocklist")
	}

	err, trie := trie.Build(t, rank, conf, filetagjson)

	if err != nil {
		return nil, err
	}

	flags, tags, err := load(filetagjson)

	if err != nil {
		return nil, err
	}

	// TODO: find a better place
	runtime.GC()

	// docs.pi-hole.net/ftldns/blockingmode/
	b := &bravedns{
		trie: &trie,
		// pos/index/value ->subgroup:vname
		flags: flags,
		// uname -> subgroup:vname
		tags: tags,
		mode: localBlock,
	}
	b.initBitSetTable()

	return b, nil
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
	// example:
	// {
	//    "XYZ": {
	//      "value":171,
	//      "uname":"XYZ",
	//      "vname":"1Hosts",
	//      "group":"privacy",
	//      "subg":"",
	//      "url":"badmojr.github.io...",
	//      "show":1,
	//      "entries":511684
	//    }
	//    ...
	// }
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
		// 171 -> privacy:1Hosts
		rflags[index] = subgroup + ":" + name
		// XYZ -> privacy:1Hosts
		fdata[key] = subgroup + ":" + name
	}
	return rflags, fdata, nil
}

func (brave *bravedns) decode(stamp string, ver string) (info []*listinfo, err error) {
	decoder := b64.StdEncoding
	if ver == ver0 {
		stamp, err = url.QueryUnescape(stamp)
	} else if ver == ver1 {
		stamp, err = url.PathUnescape(stamp)
		decoder = b64.URLEncoding
	} else {
		err = fmt.Errorf("version %s unsupported", ver)
	}
	if err != nil {
		return nil, err
	}

	buf, err := decoder.DecodeString(stamp)
	if err != nil {
		return
	}

	var u16 []uint16
	if ver == ver0 {
		u16 = stringtouint(string(buf))
	} else if ver == ver1 {
		u16 = bytestouint(buf)
	} else {
		err = fmt.Errorf("unimplemented header stamp version %v", ver)
		return
	}

	return brave.flagstoinfo(u16)
}

func (brave *bravedns) flagstoinfo(flags []uint16) ([]*listinfo, error) {
	// flags has to be an array of 16-bit integers.

	// first index always contains the header
	header := uint16(flags[0])
	// store of each big-endian position of set bits in header
	tagIndices := []int{}
	values := make([]*listinfo, 0)
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
				values = append(values, &listinfo{pos, brave.flags[pos]})
			}
			mask = mask >> 1
		}
	}
	return values, nil
}

func (brave *bravedns) flagtostamp(fl []string) ([]uint16, error) {
	const header = 0
	const u1 = uint16(1)
	res := []uint16{0}

	for _, flag := range fl {
		val, err := strconv.Atoi(flag)
		if err != nil {
			return nil, err
		}

		hindex := uint16(val / 16)
		pos := uint16(val % 16)

		h := &res[header]
		n := uint16(0)

		// only header present in res, append 'n' to it
		if len(res) == 1 {
			*h |= u1 << (15 - hindex)
			n |= u1 << (15 - pos)
			res = append(res, n)
			continue
		}

		dataindex := brave.countSetBits(*h&maskLsb[16-hindex]) + 1
		datafound := ((*h >> (15 - hindex)) & 0x1) == 1
		if datafound {
			// upsert, as in 'n' is updated in-place
			u := &res[dataindex]
			*u |= 1 << (15 - pos)
		} else {
			// insert 'n' between res[:dataindex] and r[dataindex+1:]
			*h |= 1 << (15 - hindex)
			n |= 1 << (15 - pos)
			tmp := append(res[:dataindex], n)
			if dataindex+1 < len(res) {
				tmp = append(tmp, res[dataindex+1:]...)
			}
			res = tmp
		}
	}

	return res, nil
}

func encode(ver string, bin []uint16) (string, error) {
	if ver != ver1 {
		return "", fmt.Errorf("version %s unsupported / len(input): %d", ver, len(bin))
	}

	bytes := uinttobytes(bin)

	return ver + verseperator + b64.URLEncoding.EncodeToString(bytes), nil
}

func stringtobyte(str string) []byte {
	u16 := stringtouint(str)
	return uinttobytes(u16)
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

func uinttobytes(u16 []uint16) []byte {
	bytes := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(bytes[i*2:(i+1)*2], v)
	}
	fmt.Println(len(bytes), bytes, "\n", len(u16), u16)
	return bytes
}

// return the count of set bits in n
func (b *bravedns) countSetBits(n uint16) int {
	return (b.bitsSetTable256[n&0xff] + b.bitsSetTable256[(n>>8)&0xff])
}

// initialise the lookup table
func (b *bravedns) initBitSetTable() {
	b.bitsSetTable256 = make([]int, 256)
	b.bitsSetTable256[0] = 0
	for i := 0; i < 256; i++ {
		b.bitsSetTable256[i] = (i & 1) + b.bitsSetTable256[(i/2)]
	}
}

var maskLsb = []uint16{
	0xffff,
	0xfffe,
	0xfffc,
	0xfff8,
	0xfff0,
	0xffe0,
	0xffc0,
	0xff80,
	0xff00,
	0xfe00,
	0xfc00,
	0xf800,
	0xf000,
	0xe000,
	0xc000,
	0x8000,
	0x0000,
}
