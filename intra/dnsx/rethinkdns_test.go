// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

import (
	"fmt"
	"testing"
)

const (
	v0case0  = "6b%2Bg67y%2Bz7%2Fvv7%2Fvv7ztlaDvgIDkhIDnhYTogKA%3D"
	v0case1  = "77%2Bg77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2Bg"
	v1case0  = "1:ENz_PwDwfwD___j_YKE=" // same as fcase0
	v1case1  = "1:4J8-v_8D___8_2DVAPAAQURxIIA="
	v1case2  = "1:4P___________________________-D_"
	v1case2a = "1-4d7777777777777777777777777777777776b7y"
	v1case3  = "1:ENz_PwDw_wP___j_YKk="     // same as fcase3
	v1case4  = "1:MNz_PwDw_wP___j_BABgqQ==" // same as fcase4
)

var (
	fcase0 = []uint16{ // same as v1case0
		15, 16, 17, 18, 186, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 176, 183, 3, 4, 185, 2, 19, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 178,
	}
	fcase3 = []uint16{
		57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 178, 15, 16, 17, 18, 186, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 176, 183, 3, 4, 185, 2, 19, 54, 55, 56, 180,
	}
	fcase4 = []uint16{
		57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 178, 15, 16, 17, 18, 186, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 176, 183, 3, 4, 185, 2, 19, 54, 55, 56, 180, 173,
	}
)

func TestGeneric(tester *testing.T) {
	r, f := load1()
	b := &rethinkdns{
		flags: r,
		tags:  f,
	}

	// decode v0 to blocklist-info
	_, err := b.decode(v0case0, ver0, EB64)
	ok("v0case0", err)
	_, err = b.decode(v0case1, ver0, EB64)
	ok("v0case1", err)
	fmt.Println("-------------------------------------------------")

	// blockstamp to flags (csv)
	f0, err := b.StampToFlags(v1case0)
	ko(tester, err)
	s0, err := b.FlagsToStamp(f0, EB64)
	ko(tester, err)
	fmt.Println("case0; ok?", s0 == v1case0, "\t\t", f0, s0)
	fmt.Println("-------------------------------------------------")

	f1, err := b.StampToFlags(v1case1)
	ko(tester, err)
	s1, err := b.FlagsToStamp(f1, EB64)
	ko(tester, err)
	fmt.Println("case1; ok?", s1 == v1case1, "\t\t", f1, s1)
	fmt.Println("-------------------------------------------------")

	f2, err := b.StampToFlags(v1case2)
	ko(tester, err)
	f2a, err := b.StampToFlags(v1case2a)
	ko(tester, err)
	s2, err := b.FlagsToStamp(f2, EB64)
	ko(tester, err)
	s21, err := b.FlagsToStamp(f2, EB32)
	ko(tester, err)
	s2a, err := b.FlagsToStamp(f2a, EB64)
	ko(tester, err)

	fmt.Println("case2/2a; ok?", s2 == v1case2, s21 == v1case2a, s2a == v1case2, "\t\t", f2, s2)
	fmt.Println("-------------------------------------------------")

	f3, err := b.StampToFlags(v1case3)
	ko(tester, err)
	s3, err := b.FlagsToStamp(f3, EB64)
	ko(tester, err)
	fmt.Println("case3; ok?", s3 == v1case3, "\t\t", f3, s3)
	fmt.Println("-------------------------------------------------")

	f4, err := b.StampToFlags(v1case4)
	ko(tester, err)
	s4, err := b.FlagsToStamp(f4, EB64)
	ko(tester, err)
	fmt.Println("case4; ok?", s4 == v1case4, "\t\t", f4, s4)
	fmt.Println("-------------------------------------------------")

	// flag to blockstamp test
	ustamp0, err := b.flagtostamp(fcase0)
	ko(tester, err)
	stamp0, err := encode(ver1, ustamp0, EB64)
	ko(tester, err)
	fmt.Println("fcase0; ok?", stamp0 == v1case0, "\t\t", ustamp0, stamp0)
	fmt.Println("-------------------------------------------------")

	ustamp3, err := b.flagtostamp(fcase3)
	ko(tester, err)
	stamp3, err := encode(ver1, ustamp3, EB64)
	ko(tester, err)
	fmt.Println("fcase3 ok?", stamp3 == v1case3, "\t\t", ustamp3, stamp3)
	fmt.Println("-------------------------------------------------")

	ustamp4, err := b.flagtostamp(fcase4)
	ko(tester, err)
	stamp4, err := encode(ver1, ustamp4, EB64)
	ko(tester, err)
	fmt.Println("fcase4 ok?", stamp4 == v1case4, "\t\t", ustamp4, stamp4)
	fmt.Println("-------------------------------------------------")

	err = b.SetStamp(v1case2a) // v1case2 is its base64 representation
	ko(tester, err)
	gstamp0, err := b.GetStamp() // always returns as base64
	ko(tester, err)
	fmt.Println("gcase0 ok?", gstamp0 == v1case2, "\t\t", gstamp0)
}

func load1() ([]string, map[string]string) {
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
		171: "AA1",
		172: "AA2",
		173: "AA3",
		174: "AA4",
		175: "AA5",
		176: "AA6",
		177: "AA7",
		178: "AA8",
		179: "AA9",
		180: "AB0",
		181: "AB1",
		182: "AB2",
		183: "AB3",
		184: "AB4",
		185: "AB5",
		186: "AB6",
		187: "AB7",
		188: "AB8",
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

func ko(t *testing.T, err error) {
	if err != nil {
		t.Error(err)
	}
}

func ok(tag string, err error) {
	if err != nil {
		fmt.Println(tag, err)
	}
}
