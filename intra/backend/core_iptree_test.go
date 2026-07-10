package backend

import (
	"testing"

	"github.com/celzero/firestack/intra/core"
	ll "github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
)

func Test192(tst *testing.T) {
	log := tst.Log
	t := NewIpTree()
	t.Add("192.0.0.0/8", "app192:443")
	t.Add("192.0.0.0/8", "dup192:443")
	t.Add("192.1.0.0/16", "app192:80")
	t.Add("1.1.1.0/24", "*:80")
	t.Add("192.1.0.0/16", "app1921:80")
	t.Set("192.2.0.0/16", "app1922:0")
	t.Set("192.2.0.0/16", "app1922:unset")
	t.Add("192.1.1.1/32", "app192111:0")
	t.Add("0.0.0.0/0", "test0000")
	t.Add("192.0.0.0/8", "app192:443")
	t.Add("1.1.0.0/16", "app1100:0")

	g8, err := t.Get("192.0.0.0/8")
	ko(tst, err)
	log("g8", g8) // app192:443 dup192:443

	g16, err := t.Get("192.1.0.0/16")
	rmv := t.Esc("1.1.0.0/16", "test16.2") // false
	g16any, err1 := t.GetAny("192.1.0.0/16")
	ko(tst, err)
	ko(tst, err1)
	log("g16", g16, "g16any", g16any, "esc?", rmv)

	g32any, err := t.GetAny("192.1.1.2/32")
	ko(tst, err)
	log("g32any", g32any)

	gall, err := t.GetAll("192.1.1.1/32")
	ko(tst, err)
	log("gall", gall)

	route := t.Routes("192.1.0.0/16")
	rlike := t.RoutesLike("192.1.0.0/16", ":80")
	rlike2 := t.RoutesLike("192.1.0.0/16", "app192:80")
	val := t.Values("192.1.0.0/16")
	vlike := t.ValuesLike("192.1.0.0/16", ":80")
	vlike2 := t.ValuesLike("192.1.0.0/16", "app192:80")
	log("val", val)
	log("route", route)
	log("vlike", vlike, "vlike(1app):", vlike2)
	log("rlike", rlike, "rlike(1app):", rlike2)

	ov1 := t.Values("1.1.1.1")
	o1, err := t.Get("1.1.1.1")
	ko(tst, err)
	log("o1", o1)   // empty
	log("ov1", ov1) // test0000, app1100:0, *:80
}

func TestUn(tst *testing.T) {
	ll.SetLevel(ll.VVERBOSE)
	ll.SetCallerDepth(0)
	settings.Debug = true

	trie := NewRadixTree()
	trie.Add(".fritz.box") // exact domain
	trie.Add(".lan")       // subdomain ending with .lan
	trie.Add(".sub.tld")   // subdomain ending with .sub.tld

	noma1 := trie.HasAny("test.fritz.box") // subdomain matches
	yma1 := trie.HasAny("fritz.box")       // exact match for fritz.box
	yma2 := trie.HasAny("test.lan")        // subdomain match for .lan
	yma3 := trie.HasAny("mu.st.sub.tld")   // subdomain match for sub.tld

	ll.V("no: %t, yes: [%t %t %t]", noma1, yma1, yma2, yma3)
}

func TestGateway(tst *testing.T) {
	ll.SetLevel(ll.VVERBOSE)
	settings.Debug = true

	t := NewIpTree()
	err := t.Add("0.0.0.0/0", "wg")
	ko(tst, err)
	err = t.Add("::/0", "wg")
	ko(tst, err)
	err = t.Add("10.2.0.1/32", "wg")
	ko(tst, err)
	err = t.Add("2a07:b944::2:1/128", "wg")
	ko(tst, err)

	t4, err4 := core.IP2Cidr("0.0.0.0/0")
	t6, err6 := core.IP2Cidr("::/0")
	ko(tst, err4)
	ko(tst, err6)
	tst.Logf("ip2cidr 0.0.0.0/8 => %s; ::/0 => %s", t4, t6)
	t4, err4 = core.IP2Cidr("10.2.0.1/32")
	t6, err6 = core.IP2Cidr("[2600:1901:0:b2bd::]:80")
	ko(tst, err4)
	ko(tst, err6)
	tst.Logf("ip2cidr 10.2.0.1/32 => %s; [2600:1901:0:b2bd::]:80 => %s", t4, t6)

	ipv4 := []string{
		"0.0.0.0",
		"1.2.3.4",
		"10.0.0.1",
		"192.168.1.1",
		"8.8.8.8",
		"1.1.1.1:80",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"0.0.0.0/0",
	}
	ipv6 := []string{
		"::",
		"[2600:1901:0:b2bd::]:80",
		"2001:db8::1",
		"fe80::1",
		"::1",
		"2001:db8::/32",
		"::/0",
	}

	for _, addr := range ipv4 {
		ok, err := t.HasAny(addr)
		ko(tst, err)
		if !ok {
			tst.Errorf("HasAny(%q) = false; want true", addr)
		}
	}
	for _, addr := range ipv6 {
		ok, err := t.HasAny(addr)
		ko(tst, err)
		if !ok {
			tst.Errorf("HasAny(%q) = false; want true", addr)
		}
	}
	tst.Log("gateway test passed")
}

func TestEscLike(tst *testing.T) {
	log := tst.Log
	t := NewIpTree()

	// a. one CIDR with one value
	ko(tst, t.Add("10.1.0.0/16", "one:val"))

	// b. another CIDR with 2 distinct values
	ko(tst, t.Add("10.2.0.0/16", "a:two"))
	ko(tst, t.Add("10.2.0.0/16", "b:two"))

	// c. another CIDR with 3 values with matching prefixes
	ko(tst, t.Add("10.0.0.0/8", "quad:val8"))
	ko(tst, t.Add("10.3.1.0/24", "quad:val24"))
	ko(tst, t.Add("10.3.1.2", "quad:val32"))

	ko(tst, t.Add("10.3.0.0/16", "tri:alpha16"))
	ko(tst, t.Add("10.3.0.0/16", "tri:beta16"))
	ko(tst, t.Add("10.3.0.0/16", "tri:gamma16"))

	// ---- (a) EscLike with non-matching value ----
	n := t.EscLike("10.1.0.0/16", "wrong:val")
	if n != 0 {
		tst.Errorf("(a) EscLike with wrong prefix: got %d, want 0", n)
	}
	// entry (a) should still exist
	if ok, _ := t.Has("10.1.0.0/16"); !ok {
		tst.Error("(a) should still exist after EscLike with wrong prefix")
	}

	// ---- (a) EscLike with correct value ----
	n = t.EscLike("10.1.0.0/16", "one:val")
	if n != 1 {
		tst.Errorf("(a) EscLike with correct prefix: got %d, want 1", n)
	}
	// entry (a) should be removed completely
	if ok, _ := t.Has("10.1.0.0/16"); ok {
		tst.Error("(a) should be removed after EscLike with correct prefix")
	}
	log("(a) removed as expected")

	// ---- (b) EscLike one correct value ----
	n = t.EscLike("10.2.0.0/16", "a:two")
	if n != 1 {
		tst.Errorf("(b) EscLike a:two: got %d, want 1", n)
	}
	// the other value should still exist
	val, err := t.Get("10.2.0.0/16")
	ko(tst, err)
	if val != "b:two" {
		tst.Errorf("(b) Get after removing a:two: got %q, want %q", val, "b:two")
	}
	// add a new distinct value
	ko(tst, t.Add("10.2.0.0/16", "c:two"))
	// Get should now return 2 values
	val, err = t.Get("10.2.0.0/16")
	ko(tst, err)
	if val != "b:two,c:two" {
		tst.Errorf("(b) Get after adding c:two: got %q, want %q", val, "b:two,c:two")
	}
	log("(b) now has 2 values:", val)

	// iterates from most generic rule to most specific
	log("(c) all 10.3.1.1: ", t.Values("10.3.1.1")) // quad:val8,tri:alpha16,tri:beta16,tri:gamma16,quad:val24
	log("(c) all 10.3.1.2: ", t.Values("10.3.1.2")) // quad:val8,tri:alpha16,tri:beta16,tri:gamma16,quad:val24,quad:val32

	// ---- (c) ValuesLike returns 3 values, then EscLike removes all ----
	vals := t.ValuesLike("10.3.0.0/16", "tri")
	if vals != "tri:alpha16,tri:beta16,tri:gamma16" {
		tst.Errorf("(c) ValuesLike: got %q, want %q", vals, "tri:alpha16,tri:beta16,tri:gamma16")
	}

	// EscLike the common prefix for (c) should remove all 3
	n = t.EscLike("10.3.0.0/16", "tri")
	if n != 3 {
		tst.Errorf("(c) EscLike tri: got %d, want 3", n)
	}
	// ValuesLike should now be empty
	vals = t.ValuesLike("10.3.1.1", "tri")
	if vals != "" {
		tst.Errorf("(c) ValuesLike after EscLike: got %q, want empty", vals)
	}
	// Has should return false
	if ok, _ := t.Has("10.3.0.0/16"); ok {
		tst.Error("(c) should be removed after EscLike with common prefix")
	}
	log("(c) removed as expected")

	vals = t.ValuesLike("10.3.1.1", "quad")
	if vals != "quad:val8,quad:val24" {
		tst.Errorf("(d) ValuesLike for quad: got %q, want %q", vals, "quad:val8,quad:val24")
	}
	log("(d) ValuesLike for 10.0.0.0/8 untouched:", vals)
}

func ko(tst *testing.T, err error) {
	if err != nil {
		tst.Fatal(err)
	}
}
