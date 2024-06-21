// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package intra
import "github.com/celzero/firestack/intra/ipn"
const (
	RetrierStrategy int32 = 0
	DesyncStrategy int32 = 1
)
func SwitchStrategy(s int32){
	ipn.SwitchStrategy(s)
}