// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     SPDX-License-Identifier: MIT
//
//     Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.

package backend

import (
	"testing"

	"github.com/celzero/firestack/intra/log"
)

// create a new private key and prints corres pubkey
func TestGenKeypair(t *testing.T) {
	sk, err := NewWgPrivateKey()
	if err != nil {
		t.Error("failed to generate private key: ", err)
	} else {
		pk := sk.Mult()
		t.Log("pub: ", pk.Base64(), "sk: ", sk.Base64())
	}
}

func TestRadixSearch(t *testing.T) {
	log.SetLevel(log.VERBOSE)
	const goog = "google.com"
	const wildgoog = ".google.com"
	const mailgoog = "mail.google.com"
	const dnsgoog = "dns.google.com"
	const pgoog = "prefix" + goog

	r := NewRadixTree()
	r.Set(StrOf(goog), StrOf("goog"))
	r.Set(StrOf(wildgoog), StrOf("wildgoog"))
	r.Set(StrOf(mailgoog), StrOf("mailgoog"))

	v0 := r.Get(StrOf(goog)) // goog if r.Set(goog, "goog") is uncommented; empty otherwise
	v1 := r.Get(StrOf(wildgoog))
	v2 := r.Get(StrOf(mailgoog))
	v3 := r.Get(StrOf(dnsgoog)) // empty
	v4 := r.Get(StrOf(pgoog))   // empty regardless of r.Set(goog, "goog")

	t.Log("v0?: ", v0.V(), "\tv1: ", v1.V(), "\tv2: ", v2.V(), "\tv3?: ", v3.V(), "\tv4?: ", v4.V())

	w0 := r.GetAny(StrOf(goog))     // goog if r.Set(goog, "goog") is uncommented; wildgoog otherwise
	w1 := r.GetAny(StrOf(wildgoog)) // wildgoog
	w2 := r.GetAny(StrOf(mailgoog)) // mailgoog
	w3 := r.GetAny(StrOf(dnsgoog))  // wildgoog
	w4 := r.GetAny(StrOf(pgoog))    // empty regardless of r.Set(goog, "goog")

	t.Log("w0: ", w0.V(), "\tw1: ", w1.V(), "\tw2: ", w2.V(), "\tw3: ", w3.V(), "\tw4: ", w4.V())
}
