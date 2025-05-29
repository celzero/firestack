package backend

import (
	"testing"

	ll "github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
)

func Test192(tst *testing.T) {
	log := tst.Log
	t := NewIpTree()
	t.Add(StrOf("192.0.0.0/8"), StrOf("app192:443"))
	t.Add(StrOf("192.0.0.0/8"), StrOf("dup192:443"))
	t.Add(StrOf("192.1.0.0/16"), StrOf("app192:80"))
	t.Add(StrOf("1.1.1.0/24"), StrOf("*:80"))
	t.Add(StrOf("192.1.0.0/16"), StrOf("app1921:80"))
	t.Set(StrOf("192.2.0.0/16"), StrOf("app1922:0"))
	t.Add(StrOf("192.1.1.1/32"), StrOf("app192111:0"))
	t.Add(StrOf("0.0.0.0/0"), StrOf("test0000"))

	g8, err := t.Get(StrOf("192.0.0.0/8"))
	ko(tst, err)
	log("g8", g8.V()) // app192:443 dup192:443

	g16, err := t.Get(StrOf("192.1.0.0/16"))
	rmv := t.Esc(StrOf("1.1.0.0/16"), StrOf("test16.2")) // false
	g16any, err1 := t.GetAny(StrOf("192.1.0.0/16"))
	ko(tst, err)
	ko(tst, err1)
	log("g16", g16.V(), "g16any", g16any.V(), "esc?", rmv)

	g32any, err := t.GetAny(StrOf("192.1.1.2/32"))
	ko(tst, err)
	log("g32any", g32any.V())

	gall, err := t.GetAll(StrOf("192.1.1.1/32"))
	ko(tst, err)
	log("gall", gall.V())

	route := t.Routes(StrOf("192.1.0.0/16"))
	rlike := t.RoutesLike(StrOf("192.1.0.0/16"), StrOf(":80"))
	val := t.Values(StrOf("192.1.0.0/16"))
	vlike := t.ValuesLike(StrOf("192.1.0.0/16"), StrOf(":80"))
	vlike2 := t.ValuesLike(StrOf("192.1.0.0/16"), StrOf("app192:80"))
	log("val", val.V())
	log("route", route.V())
	log("vlike", vlike.V(), "vlike(1app):", vlike2.V())
	log("rlike", rlike.V())
}

func TestUn(tst *testing.T) {
	ll.SetLevel(ll.VVERBOSE)
	settings.Debug = true

	trie := NewRadixTree()
	trie.Add(StrOf("fritz.box")) // exact domain
	trie.Add(StrOf(".lan"))      // subdomain ending with .lan

	noma1 := trie.HasAny(StrOf("test.fritz.box")) // no subdomain matches
	yma1 := trie.HasAny(StrOf("fritz.box"))       // exact match for fritz.box
	yma2 := trie.HasAny(StrOf("test.lan"))        // subdomain match for .lan

	ll.V("no: %t, yes: [%t %t]", noma1, yma1, yma2)
}

func ko(tst *testing.T, err error) {
	if err != nil {
		tst.Fatal(err)
	}
}
