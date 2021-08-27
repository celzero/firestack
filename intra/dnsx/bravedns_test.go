// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

import (
	b64 "encoding/base64"
	"encoding/binary"
	"fmt"
	"net/url"
)

type bravelist struct {
	flags []string
	tags  map[string]string
}

func main() {
	fmt.Println("Hello, playground")
	r, f := load2()
	b := &bravelist{
		flags: r,
		tags:  f,
	}
	t, err := b.decode("6b%2Bg67y%2Bz7%2Fvv7%2Fvv7ztlaDvgIDkhIDnhYTogKA%3D")
	t, err = b.decode("77%2Bg77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2Bg")
	fmt.Println(t, err)
	t, err = b.decode("4J8+v/8D///8/2DVAPAAQURxIIA=")
	t, err = b.decode("4P///////////////////////////+D/")
	//m, n := url.PathUnescape("4J8+v/8D///8/2DVAPAAQURxIIA=")
	//x, y := b64.StdEncoding.DecodeString(m)
	fmt.Println(t, err)
	//fmt.Println(m, n)
	//fmt.Println(x, y)
}

func load2() ([]string, map[string]string) {
	obj := map[int]string{
		0:   "MTF",
		1:   "KBI",
		2:   "YAC",
		3:   "HBP",
		4:   "NIM",
		5:   "YWG",
		6:   "SMQ",
		7:   "AQX",
		8:   "BTG",
		9:   "GUN",
		10:  "KSH",
		11:  "WAS",
		12:  "AZY",
		13:  "GWB",
		14:  "YMG",
		15:  "CZM",
		16:  "HYS",
		17:  "XIF",
		18:  "TQN",
		19:  "ZVO",
		20:  "YOM",
		21:  "THR",
		22:  "RPW",
		23:  "AMG",
		24:  "WTJ",
		25:  "ZXU",
		26:  "FJG",
		27:  "NYS",
		28:  "OKG",
		29:  "KNP",
		30:  "FLI",
		31:  "RYX",
		32:  "CIH",
		33:  "PTE",
		34:  "KEA",
		35:  "CMR",
		36:  "DDO",
		37:  "VLM",
		38:  "JEH",
		39:  "XLX",
		40:  "OQW",
		41:  "FXC",
		42:  "HZJ",
		43:  "SWK",
		44:  "VAM",
		45:  "AOS",
		46:  "FAL",
		47:  "CZK",
		48:  "FZB",
		49:  "PYW",
		50:  "JXA",
		51:  "KOR",
		52:  "DEP",
		53:  "RFX",
		54:  "DTT",
		56:  "RAF",
		55:  "VZP",
		57:  "THG",
		58:  "YVH",
		59:  "XQV",
		60:  "PIB",
		61:  "EEN",
		62:  "GDA",
		63:  "MAD",
		64:  "NAK",
		65:  "BPZ",
		66:  "HWO",
		67:  "YUC",
		68:  "IKY",
		69:  "LSS",
		70:  "NOE",
		71:  "PLR",
		72:  "FIT",
		73:  "LHX",
		74:  "FOF",
		75:  "DYA",
		76:  "JAN",
		77:  "FHQ",
		78:  "CMC",
		79:  "RKG",
		80:  "XMK",
		81:  "GAX",
		82:  "RFI",
		83:  "AZR",
		84:  "CEN",
		85:  "SPR",
		86:  "MZT",
		87:  "NHM",
		88:  "GLV",
		89:  "NUY",
		90:  "EDM",
		91:  "ZFC",
		92:  "DOP",
		93:  "XGC",
		94:  "OHE",
		95:  "MYS",
		96:  "IAJ",
		97:  "EAQ",
		98:  "AOC",
		99:  "XAT",
		100: "OSE",
		101: "IBB",
		102: "EGX",
		103: "HZD",
		104: "FLW",
		105: "ULZ",
		106: "OFY",
		107: "MLE",
		108: "YER",
		109: "DMC",
		110: "IJO",
		111: "OWW",
		112: "EMY",
		113: "XKM",
		114: "CQT",
		115: "ANW",
		116: "DGE",
		117: "BBS",
		118: "OKW",
		119: "ONV",
		120: "CDE",
		121: "PAL",
		122: "DBP",
		123: "MHP",
		124: "EPR",
		125: "OUU",
		126: "YXS",
		127: "UQK",
		128: "GVI",
		129: "TXJ",
		130: "DPY",
		131: "DUC",
		132: "WYE",
		133: "CGF",
		134: "JRV",
		135: "EOK",
		136: "HQL",
		137: "NNH",
		138: "KRM",
		139: "QKN",
		140: "MPR",
		141: "EOO",
		142: "MDE",
		143: "WWI",
		144: "TTI",
		145: "GFJ",
		146: "WOD",
		147: "YJR",
		148: "WIB",
		149: "NUI",
		150: "XIO",
		151: "OBW",
		152: "YBO",
		153: "TTW",
		154: "NML",
		155: "MIN",
		156: "IFD",
		157: "AMI",
		158: "TZF",
		159: "VKE",
		160: "PWQ",
		161: "KUA",
		162: "FHW",
		163: "AGZ",
		164: "IVN",
		165: "FIB",
		166: "FGF",
		167: "FLL",
		168: "IVO",
		169: "ALQ",
		170: "FHM",
	}

	rflags := make([]string, len(obj))
	fdata := make(map[string]string)
	for key := range obj {
		val := obj[key]
		rflags[key] = val
		fdata[val] = val
	}
	return rflags, fdata
}

func (brave *bravelist) decode(s string) (tags []string, err error) {
	stamp, err := url.QueryUnescape(s)
	if err != nil {
		return
	}

	buf, err := b64.StdEncoding.DecodeString(stamp)
	if err != nil {
		stamp, err = url.PathUnescape(s)
		buf, err = b64.StdEncoding.DecodeString(stamp)
	}
	if err != nil {
		return
	}

	return brave.flagstotag(stringtouint2(buf))
}

func stringtouint2(b []byte) []uint16 {
	stamp := string(b)
	runedata := []rune(stamp)
	data := make([]uint16, len(b)/2)
	for i := range data {
		// assuming little endian
		data[i] = binary.LittleEndian.Uint16(b[i*2 : (i+1)*2])
	}
	resp := make([]uint16, len(runedata))
	for key, value := range runedata {
		resp[key] = uint16(value)
	}
	fmt.Println(resp, data, len(b))
	return resp
}

func (brave *bravelist) flagstotag(flags []uint16) ([]string, error) {
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
