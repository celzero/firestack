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

	r := NewRadixTree()
	// r.Set(goog, "goog")
	r.Set(wildgoog, "wildgoog")
	r.Set(mailgoog, "mailgoog")

	v0 := r.Get(goog) // empty
	v1 := r.Get(wildgoog)
	v2 := r.Get(mailgoog)
	v3 := r.Get(dnsgoog) // empty

	t.Log("v0?: ", v0, "\tv1: ", v1, "\tv2: ", v2, "\tv3?: ", v3)

	w0 := r.GetAny(goog)     // goog if r.Set(goog, "goog") is uncommented; wildgoog otherwise
	w1 := r.GetAny(wildgoog) // wildgoog
	w2 := r.GetAny(mailgoog) // mailgoog
	w3 := r.GetAny(dnsgoog)  // wildgoog

	t.Log("w0: ", w0, "\tw1: ", w1, "\tw2: ", w2, "\tw3: ", w3)
}
