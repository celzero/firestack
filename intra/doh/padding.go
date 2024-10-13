// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     Copyright 2019 The Outline Authors
//
//     Licensed under the Apache License, Version 2.0 (the "License");
//     you may not use this file except in compliance with the License.
//     You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
//     Unless required by applicable law or agreed to in writing, software
//     distributed under the License is distributed on an "AS IS" BASIS,
//     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//     See the License for the specific language governing permissions and
//     limitations under the License.

package doh

import (
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

// padQuery adds EDNS padding (RFC7830) to msg.
func padQuery(msg *dns.Msg) *dns.Msg {
	defer core.Recover(core.DontExit, "doh.padQ")
	xdns.AddEDNS0PaddingIfNoneFound(msg)
	return msg
}
