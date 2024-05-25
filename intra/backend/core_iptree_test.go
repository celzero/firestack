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
	t.Add("192.1.0.0/16", "app192:80")
	t.Add("1.1.1.0/24", "*:80")
	t.Add("192.1.0.0/16", "app1921:80")
	t.Set("192.2.0.0/16", "app1922:0")
	t.Add("192.1.1.1/32", "app192111:0")
	t.Add("0.0.0.0/0", "test0000")

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

	noma1 := trie.HasAny("test.fritz.box") // no subdomain matches
	yma1 := trie.HasAny("fritz.box")       // exact match for fritz.box
	yma2 := trie.HasAny("test.lan")        // subdomain match for .lan

	ll.V("no: %t, yes: [%t %t]", noma1, yma1, yma2)
}

func ko(tst *testing.T, err error) {
	if err != nil {
		tst.Fatal(err)
	}
}
