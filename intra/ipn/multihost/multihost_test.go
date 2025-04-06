// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package multihost

import (
	"testing"

	ilog "github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
)

func TestMultihostMap(t *testing.T) {
	ilog.SetLevel(0)
	settings.Debug = true

	h1 := New("h1")
	h1ips := []string{
		"1.1.1.1:53",
		"2.2.2.2:23",
		"3.3.3.3:33",
	}
	h1.Add(h1ips)
	h2 := New("h2")
	h2ips := []string{
		"[2000:b:0::5:0]:53",
		"[2000:d:e::a:d]:23",
		"[2000:b:e::e:f]:33",
	}
	h2.Add(h2ips)
	m := NewMap("testmap")
	if !m.Put(h1) {
		t.Fatal("expected to put h1")
	}
	_, xperr1 := m.Get("1.1.1.1") // empty
	_, unerr1 := m.Get("1.1.1.1:53")
	if xperr1 == nil {
		t.Errorf("expected error, got nil")
		t.Fail()
	}
	if unerr1 != nil {
		t.Errorf("expected no error, got %v", unerr1)
		t.Fail()
	}
	_, xperr2 := m.Get("[2000:d:e::a:d]:23") // empty
	if !m.Put(h2) {
		t.Fatal("expected to put h2")
	}
	_, unerr2 := m.Get("[2000:d:e::a:d]:23") // empty
	if xperr2 == nil {
		t.Errorf("expected error, got nil")
		t.Fail()
	}
	if unerr2 != nil {
		t.Errorf("expected no error, got %v", unerr2)
		t.Fail()
	}
	// log.D(m.String())
}
