// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

import (
	b32 "encoding/base32"
	b64 "encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/miekg/dns"

	"github.com/celzero/firestack/intra/backend"
	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/xdns"

	"github.com/celzero/gotrie/trie"
)

const (
	localBlock  = 0
	remoteBlock = 1

	// blocklist stamp separator for base64 encoding
	colonsep = ":"
	// blocklist stamp separator for base32 encoding
	hyphensep = "-"
)

// supported blocklist stamp versions: 0 or 1
const (
	ver1 = "1"
	ver0 = "0"
)

// encoding type, base32 or base64
const (
	EB32 = backend.EB32
	EB64 = backend.EB64
)

var (
	errRemote           = errors.New("op not valid in remote block mode")
	errNoStamps         = errors.New("no stamp set")
	errMissingCsv       = errors.New("zero comma-separated flags")
	errFlagsMismatch    = errors.New("flagcsv does not match loaded flags")
	errNotEnoughAnswers = errors.New("req at least two answers")
	errTrieArgs         = errors.New("missing data, unable to build blocklist")
	errNoBlocklistMatch = errors.New("no blocklist applies")
)

type RdnsResolver interface {
	x.RDNSResolver
	blockQ(Transport, Transport, *dns.Msg) (*dns.Msg, string, error)
	blockA(Transport, Transport, *dns.Msg, *dns.Msg, string) (*dns.Msg, string)
}

type RDNS interface {
	x.RDNS
	OnDeviceBlock() bool // Mode
	blockQuery(*dns.Msg) (string, error)
	blockAnswer(*dns.Msg) (string, error)
}

type rethinkdns struct {
	// value -> group:name
	flags []string
	// uname -> group:name
	tags  map[string]string
	mode  int
	stamp string
}

type rethinkdnslocal struct {
	*rethinkdns
	ftrie *trie.FrozenTrie
}

var _ RDNS = (*rethinkdnslocal)(nil)
var _ RDNS = (*rethinkdns)(nil)

type listinfo struct {
	pos  int
	name string
}

func newRDNSRemote(filetagjson string) (*rethinkdns, error) {
	flags, tags, err := load(filetagjson)
	if err != nil {
		return nil, err
	}
	r := &rethinkdns{
		flags: flags,
		tags:  tags,
		mode:  remoteBlock,
	}
	return r, nil
}

func newRDNSLocal(t string, rank string,
	conf string, filetagjson string) (*rethinkdnslocal, error) {

	if len(t) <= 0 || len(rank) <= 0 || len(conf) <= 0 || len(filetagjson) <= 0 {
		return nil, errTrieArgs
	}

	ft, err := trie.Build(t, rank, conf, filetagjson)
	if err != nil {
		return nil, err
	}

	flags, tags, err := load(filetagjson)
	if err != nil {
		return nil, err
	}

	// TODO: find a better place
	runtime.GC()

	// docs.pi-hole.net/ftldns/blockingmode
	r := &rethinkdns{
		// pos/index/value ->subgroup:vname
		flags: flags,
		// uname -> subgroup:vname
		tags: tags,
		mode: localBlock,
	}
	rlocal := &rethinkdnslocal{
		rethinkdns: r,
		ftrie:      ft,
	}

	return rlocal, nil
}

func (r *rethinkdns) OnDeviceBlock() bool {
	return r.mode == localBlock
}

func (r *rethinkdns) GetStamp() (s string, err error) {
	if !r.OnDeviceBlock() {
		err = errRemote
		return
	}
	if len(r.stamp) <= 0 {
		s = ""
	} else {
		s = r.stamp
	}
	return
}

func (r *rethinkdns) SetStamp(stamp string) error {
	if !r.OnDeviceBlock() {
		return errRemote
	}
	if len(stamp) <= 0 {
		r.stamp = ""
	} else {
		// normalize also validates the stamp
		if nm, err := r.normalizeStamp(stamp); err != nil {
			return err
		} else {
			r.stamp = nm
		}
	}
	return nil
}

// Returns blockstamp given comma-separated blocklist ids
func (r *rethinkdns) FlagsToStamp(flagscsv string, enctyp int) (string, error) {
	fstr := strings.Split(flagscsv, ",")
	if len(fstr) <= 0 {
		return "", errMissingCsv
	}

	flags := make([]uint16, len(fstr))
	for i, s := range fstr {
		val, err := strconv.Atoi(s)
		if err != nil {
			return "", err
		}
		if i >= len(flags) {
			return "", errFlagsMismatch
		}
		flags[i] = uint16(val)
	}

	if stamp, err := r.flagtostamp(flags); err != nil {
		return "", err
	} else {
		return encode(ver1, stamp, enctyp)
	}
}

// Returns comma-separated blocklist ids, given a stamp of form version:base64
func (r *rethinkdns) StampToFlags(stamp string) (string, error) {
	blocklists, err := r.stampToBlocklist(stamp)
	if err != nil {
		return "", err
	}

	var blocklistids []string
	for _, x := range blocklists {
		blocklistids = append(blocklistids, fmt.Sprint(x.pos))
	}

	return strings.Join(blocklistids[:], ","), nil
}

func (r *rethinkdns) StampToNames(stamp string) (string, error) {
	blocklists, err := r.stampToBlocklist(stamp)
	if err != nil {
		return "", err
	}

	var blocklistnames []string
	for _, x := range blocklists {
		blocklistnames = append(blocklistnames, x.name)
	}

	return strings.Join(blocklistnames[:], ","), nil
}

func (r *rethinkdns) stampToBlocklist(stamp string) ([]*listinfo, error) {
	if len(stamp) <= 0 {
		return nil, errNoStamps
	}

	// b64 -> 1:YAYBACABEDAgAA== / b32 -> 1-madacabaaeidaiaa
	colonidx := strings.Index(stamp, colonsep)
	hyphenidx := strings.Index(stamp, hyphensep)
	isb32 := hyphenidx >= 0 && (hyphenidx < colonidx || colonidx < 0)
	versep := colonsep
	enctyp := EB64
	if isb32 {
		versep = hyphensep
		enctyp = EB32
	}
	s := strings.Split(stamp, versep)
	if len(s) > 1 {
		return r.decode(s[1], s[0], enctyp)
	} else {
		return r.decode(stamp, "0", enctyp)
	}
}

func (r *rethinkdns) keyToNames(list []string) (v []string) {
	for _, l := range list {
		x := r.tags[l]
		if len(x) > 0 { // TODO: else err?
			v = append(v, x)
		}
	}
	return
}

func (r *rethinkdns) flagsToNames(flagstr []string) (v []string) {
	for _, entry := range flagstr {
		if i, err := strconv.Atoi(entry); err == nil && i < len(r.flags) {
			v = append(v, r.flags[i])
		} else {
			continue
		}
	}
	return
}

func (r *rethinkdns) blockQuery(*dns.Msg) (b string, err error)  { err = errRemote; return }
func (r *rethinkdns) blockAnswer(*dns.Msg) (b string, err error) { err = errRemote; return }

func (r *rethinkdnslocal) blockQuery(msg *dns.Msg) (blocklists string, err error) {
	if len(msg.Question) <= 0 {
		err = errMissingQueryName
		return
	}

	stamp, err := r.GetStamp()
	if err != nil {
		return
	}
	if len(stamp) <= 0 {
		err = errNoStamps
		return
	}
	for _, quest := range msg.Question {
		// err when incoming name != ascii, ignore
		qname, _ := xdns.NormalizeQName(quest.Name)
		qtype := msg.Question[0].Qtype
		if !(xdns.IsAAAAQType(qtype) || xdns.IsAQType(qtype) || xdns.IsSVCBQType(qtype) || xdns.IsHTTPSQType(qtype)) {
			err = fmt.Errorf("unsupported dns query type %v", qtype)
			return
		}
		block, lists := r.ftrie.DNlookup(qname, stamp)
		// TODO: handle empty lists as err?
		if block {
			blocklists = strings.Join(r.keyToNames(lists), ",")
			return
		}
	}
	err = errNoBlocklistMatch
	return
}

func (r *rethinkdnslocal) blockAnswer(msg *dns.Msg) (blocklists string, err error) {
	if len(msg.Answer) <= 1 {
		err = errNotEnoughAnswers
		return
	}
	stamp, err := r.GetStamp()
	if err != nil {
		return
	}
	if len(stamp) <= 0 {
		err = errNoStamps
		return
	}

	// handle cname, https/svcb name cloaking: news.ycombinator.com/item?id=26298339
	// adopted from: github.com/DNSCrypt/dnscrypt-proxy/blob/6e8628f79/dnscrypt-proxy/plugin_block_name.go#L178
	for _, a := range msg.Answer {
		var target string
		switch rr := a.(type) {
		case *dns.CNAME:
			target = rr.Target
		case *dns.SVCB:
			if rr.Priority == 0 {
				target = rr.Target
			}
		case *dns.HTTPS:
			if rr.Priority == 0 {
				target = rr.Target
			}
		default:
			// no-op
		}

		if len(target) <= 0 {
			continue
		}

		// ignore err when incoming name != ascii
		target, _ = xdns.NormalizeQName(target)
		block, lists := r.ftrie.DNlookup(target, stamp)
		if block { // TODO: handle empty lists as err?
			blocklists = strings.Join(r.keyToNames(lists), ",")
			return
		}
	}

	err = fmt.Errorf("answers not in blocklist %s", stamp)
	return
}

func load(configjson string) ([]string, map[string]string, error) {
	data, err := os.ReadFile(configjson)
	if err != nil {
		return nil, nil, err
	}

	var obj map[string]any
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
		indata, _ := obj[key].(map[string]any)
		if indata == nil { // should not happen
			continue
		}
		findex, _ := indata["value"].(float64)
		index := int(findex)
		name, _ := indata["vname"].(string)
		subgroup, _ := indata["subg"].(string)
		group, _ := indata["group"].(string)

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

func (r *rethinkdns) decode(stamp string, ver string, enctyp int) (info []*listinfo, err error) {
	haspad := strings.Contains(stamp, "=")
	decoder := b64.RawStdEncoding
	decoder32 := b32.StdEncoding.WithPadding(b32.NoPadding)
	if haspad {
		decoder = b64.StdEncoding
		decoder32 = b32.StdEncoding.WithPadding(b32.StdPadding)
	}
	if ver == ver0 {
		stamp, err = url.QueryUnescape(stamp)
	} else if ver == ver1 {
		decoder = b64.RawURLEncoding
		if haspad {
			decoder = b64.URLEncoding
		}
	} else {
		err = fmt.Errorf("version %s unsupported", ver)
	}
	if err != nil {
		return nil, err
	}

	var buf []byte
	if enctyp == EB32 {
		buf, err = decoder32.DecodeString(strings.ToUpper(stamp))
	} else {
		buf, err = decoder.DecodeString(stamp)
	}
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

	return r.flagstoinfo(u16)
}

func (r *rethinkdns) flagstoinfo(flags []uint16) ([]*listinfo, error) {
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
		// 16 blocklists are represented by one flag; ie,
		// one bit per blocklist; flag[0] is the header.
		var flag = uint16(flags[i])
		// get the index of the current flag in the header
		var index = tagIndices[i-1]
		// b1000,0000,0000,0000; 1<<15
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
				if pos >= len(r.flags) {
					// github.com/celzero/firestack/issues/5
					// sliently ignore scenarios where stamp encode many
					// more blocklsts than what's currently loaded
					continue
				}
				// from the decimal value which is its
				// blocklist-id, fetch its metadata
				values = append(values, &listinfo{pos, r.flags[pos]})
			}
			mask = mask >> 1
		}
	}
	return values, nil
}

// convert int flags (blocklist-ids) to a packed uint16 stamp
func (r *rethinkdns) flagtostamp(fl []uint16) ([]uint16, error) {
	const u1 = uint16(1)
	res := []uint16{0}

	w := trie.W
	uw := uint16(w)
	for _, val := range fl {
		hindex := val / uw
		pos := val % uw

		h := &res[0]
		n := uint16(0)

		// only header present in res, append 'n' to it
		if len(res) == 1 {
			*h |= u1 << (15 - hindex)
			n |= u1 << (15 - pos)
			res = append(res, n)
			continue
		}

		mm := int(uw - hindex)
		ww := trie.MaskBottom[w]
		if mm < 0 || len(ww) <= 0 || mm >= len(ww) {
			continue // should not happen
		}
		hmask := *h & ww[mm]
		databit := *h >> (15 - hindex)
		dataindex := r.countSetBits(hmask) + 1
		datafound := (databit & 0x1) == 1
		// if !datafound {
		// log too verbose
		// log.Debugf("!!flag not found: len(res) %d / dataindex %d / found? %t\n", len(res), dataindex, datafound)
		// }
		if datafound {
			// upsert, as in 'n' is updated in-place
			n = res[dataindex]
			n |= u1 << (15 - pos)
			res[dataindex] = n
		} else {
			*h |= u1 << (15 - hindex)
			n |= u1 << (15 - pos)
			// insert 'n' between res[:dataindex] and r[dataindex:]
			nxt := append([]uint16{}, res[:dataindex]...)
			nxt = append(nxt, n)
			if dataindex < len(res) {
				nxt = append(nxt, res[dataindex:]...)
			}
			res = nxt
		}
		// log too verbose
		// log.Debugf("done: %d/%x | %x | n:%x / hidx: %d / mask: %x / databit: %x / didx: %d\n", val, res, *h, n, hindex, hmask, databit, dataindex)
	}

	return res, nil
}

func encode(ver string, u16 []uint16, enctyp int) (string, error) {
	if ver != ver1 {
		return "", fmt.Errorf("version %s unsupported / len(input): %d", ver, len(u16))
	}

	buf := uinttobytes(u16)
	if enctyp == EB32 {
		out := b32.StdEncoding.WithPadding(b32.NoPadding).EncodeToString(buf)
		return ver + hyphensep + strings.ToLower(out), nil
	}
	// decode may recv padded or unpadded stamps, but always encode with pad
	// as FrozenTrie.DNLookup expects only padded b64url for ver1
	return ver + colonsep + b64.URLEncoding.EncodeToString(buf), nil
}

// normalizeStamp stamp to base64url padded format if its base32
func (r *rethinkdns) normalizeStamp(s string) (string, error) {
	// b64 -> 1:YAYBACABEDAgAA== / b32 -> 1-madacabaaeidaiaa
	// b32 -> b64
	flagscsv, err := r.StampToFlags(s) // validate stamp
	if err != nil {
		return "", err
	}
	colonidx := strings.Index(s, colonsep)
	hyphenidx := strings.Index(s, hyphensep)
	isb32 := hyphenidx >= 0 && (hyphenidx < colonidx || colonidx < 0)
	if !isb32 {
		return s, nil
	}
	return r.FlagsToStamp(flagscsv, EB64) // encode as b64
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
	return bytes
}

// return the count of set bits in n
func (r *rethinkdns) countSetBits(n uint16) int {
	return (trie.BitsSetTable256[n&0xff] + trie.BitsSetTable256[(n>>8)&0xff])
}
