package backend

import (
	"log"
	"testing"
)

func Test192(tst *testing.T) {
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
	log.Println("g16", g16, "g16any", g16any, "esc?", rmv)

	g32any, err := t.GetAny("192.1.1.2/32")
	ko(tst, err)
	log.Println("g32any", g32any)

	gall, err := t.GetAll("192.1.1.1/32")
	ko(tst, err)
	log.Println("gall", gall)

	route := t.Routes("192.1.0.0/16")
	rlike := t.RoutesLike("192.1.0.0/16", ":80")
	val := t.Values("192.1.0.0/16")
	vlike := t.ValuesLike("192.1.0.0/16", ":80")
	log.Println("val", val)
	log.Println("route", route)
	log.Println("vlike", vlike)
	log.Println("rlike", rlike)
}

func ko(tst *testing.T, err error) {
	if err != nil {
		tst.Fatal(err)
	}
}
