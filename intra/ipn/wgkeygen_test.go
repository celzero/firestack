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

package ipn

import (
	"testing"
)

// create a new private key and prints corres pubkey
func TestGenKeypair(t *testing.T) {
	sk, _ := NewPrivateKey()
	pk := sk.Mult()
	t.Log("pub: ", pk.Base64(), "sk: ", sk.Base64())
}
