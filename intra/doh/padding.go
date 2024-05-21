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
	"github.com/miekg/dns"
)

const (
	PaddingBlockSize = 128 // RFC8467 recommendation
)

const kOptPaddingHeaderLen int = 2 + // OPTION-CODE
	2 // OPTION-LENGTH

// Compute the number of padding bytes needed, excluding headers.
// Assumes that |msgLen| is the length of a raw DNS message that contains an
// OPT RR with no RFC7830 padding option, and that the message is fully
// label-compressed.
func computePaddingSize(msgLen int, blockSize int) int {
	// always add a new padding header inside the OPT RR's data.
	extraPadding := kOptPaddingHeaderLen

	padSize := blockSize - (msgLen+extraPadding)%blockSize
	return padSize % blockSize
}

// Create an appropriately-sized padding option. Precondition: |msgLen| is the
// length of a message that already contains an OPT RR.
func optPadding(msgLen int) *dns.EDNS0_PADDING {
	return &dns.EDNS0_PADDING{
		Padding: make([]byte, computePaddingSize(msgLen, PaddingBlockSize)),
	}
}

// Add EDNS padding, as defined in RFC7830, to a raw DNS message.
func AddEdnsPadding(msg *dns.Msg) (*dns.Msg, error) {
	var opt *dns.OPT
	for _, addn := range msg.Extra {
		if dns.TypeOPT == addn.Header().Rrtype {
			var ok bool
			if opt, ok = addn.(*dns.OPT); ok {
				break
			}
		}
	}
	if opt != nil {
		for _, option := range opt.Option {
			if option.Option() == dns.EDNS0PADDING {
				return msg, nil // already padded
			}
		} // fallthrough
		msg.Compress = true
	} else { // create opt
		opt = &dns.OPT{
			Hdr: dns.RR_Header{
				Name:   ".", // RFC 6891 section 6.1.2
				Rrtype: dns.TypeOPT,
				Class:  65535,
				Ttl:    dns.RcodeSuccess >> 4 << 24, // todo: TTL for dnssec 32768
			},
			Option: nil,
		}
		msg.Compress = true
		msg.Extra = append(msg.Extra, opt)
	}
	// At this point, |msg| contains an OPT resource, and that OPT resource
	// does not contain a padding option. Add the padding option to |msg| that
	// will round its size on the wire up to the nearest block.
	opt.Option = append(opt.Option, optPadding(msg.Len()))

	return msg, nil
}
