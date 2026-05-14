package backend

import (
	"testing"

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
	val := t.Values("192.1.0.0/16")
	vlike := t.ValuesLike("192.1.0.0/16", ":80")
	vlike2 := t.ValuesLike("192.1.0.0/16", "app192:80")
	log("val", val)
	log("route", route)
	log("vlike", vlike, "vlike(1app):", vlike2)
	log("rlike", rlike)
}

func TestUn(tst *testing.T) {
	ll.SetLevel(ll.VVERBOSE)
	settings.Debug = true

	trie := NewRadixTree()
	trie.Add("fritz.box") // exact domain
	trie.Add(".lan")      // subdomain ending with .lan
	trie.Add(".sub.tld")  // subdomain ending with .sub.tld

	noma1 := trie.HasAny("test.fritz.box") // no subdomain matches
	yma1 := trie.HasAny("fritz.box")       // exact match for fritz.box
	yma2 := trie.HasAny("test.lan")        // subdomain match for .lan
	yma3 := trie.HasAny("mu.st.sub.tld")   // subdomain match for sub.tld

	ll.V("no: %t, yes: [%t %t %t]", noma1, yma1, yma2, yma3)
}

func TestGateway(tst *testing.T) {
	ll.SetLevel(ll.VVERBOSE)
	settings.Debug = true

	t := NewIpTree()
	err := t.Add("0.0.0.0", "gw4")
	ko(tst, err)
	err = t.Add("::", "gw6")
	ko(tst, err)

	ipv4 := []string{
		"0.0.0.0",
		"1.2.3.4",
		"10.0.0.1",
		"192.168.1.1",
		"8.8.8.8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"0.0.0.0/0",
	}
	ipv6 := []string{
		"::",
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

func ko(tst *testing.T, err error) {
	if err != nil {
		tst.Fatal(err)
	}
}
