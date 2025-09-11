// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     SPDX-License-Identifier: BSD-3-Clause
//     Copyright (c) Tailscale Inc & AUTHORS

package wire

import (
	"fmt"
)

// Version describes the IP address version.
type Version uint8

// Valid Version values.
const (
	Version4 = 4
	Version6 = 6
)

func (p Version) String() string {
	switch p {
	case Version4:
		return "IPv4"
	case Version6:
		return "IPv6"
	default:
		return fmt.Sprintf("Version-%d", int(p))
	}
}

// Proto is an IP subprotocol as defined by the IANA protocol
// numbers list
// (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml),
// or the special values Unknown or Fragment.
type Proto uint8

const (
	// Unknown represents an unknown or unsupported protocol; it's
	// deliberately the zero value. Strictly speaking the zero
	// value is IPv6 hop-by-hop extensions, but we don't support
	// those, so this is still technically correct.
	UnknownProto Proto = 0x00

	// Values from the IANA registry.
	ICMPv4 Proto = 0x01
	IGMP   Proto = 0x02
	ICMPv6 Proto = 0x3a
	TCP    Proto = 0x06
	UDP    Proto = 0x11
	DCCP   Proto = 0x21
	GRE    Proto = 0x2f
	SCTP   Proto = 0x84

	// TSMP is the Tailscale Message Protocol (our ICMP-ish
	// thing), an IP protocol used only between Tailscale nodes
	// (still encrypted by WireGuard) that communicates why things
	// failed, etc.
	//
	// Proto number 99 is reserved for "any private encryption
	// scheme". We never accept these from the host OS stack nor
	// send them to the host network stack. It's only used between
	// nodes.
	TSMP Proto = 99

	// Fragment represents any non-first IP fragment, for which we
	// don't have the sub-protocol header (and therefore can't
	// figure out what the sub-protocol is).
	//
	// 0xFF is reserved in the IANA registry, so we steal it for
	// internal use.
	Fragment Proto = 0xFF
)

// Deprecated: use MarshalText instead.
func (p Proto) String() string {
	switch p {
	case UnknownProto:
		return "Unknown"
	case Fragment:
		return "Frag"
	case ICMPv4:
		return "ICMPv4"
	case IGMP:
		return "IGMP"
	case ICMPv6:
		return "ICMPv6"
	case UDP:
		return "UDP"
	case TCP:
		return "TCP"
	case SCTP:
		return "SCTP"
	case TSMP:
		return "TSMP"
	case GRE:
		return "GRE"
	case DCCP:
		return "DCCP"
	default:
		return fmt.Sprintf("IPProto-%d", int(p))
	}
}

// Prefer names from
// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
// unless otherwise noted.
var (
	// preferredNames is the set of protocol names that re produced by
	// MarshalText, and are the preferred representation.
	preferredNames = map[Proto]string{
		51:     "ah",
		DCCP:   "dccp",
		8:      "egp",
		50:     "esp",
		47:     "gre",
		ICMPv4: "icmp",
		IGMP:   "igmp",
		9:      "igp",
		4:      "ipv4",
		ICMPv6: "ipv6-icmp",
		SCTP:   "sctp",
		TCP:    "tcp",
		UDP:    "udp",
	}

	// acceptedNames is the set of protocol names that are accepted by
	// UnmarshalText.
	acceptedNames = map[string]Proto{
		"ah":        51,
		"dccp":      DCCP,
		"egp":       8,
		"esp":       50,
		"gre":       47,
		"icmp":      ICMPv4,
		"icmpv4":    ICMPv4,
		"icmpv6":    ICMPv6,
		"igmp":      IGMP,
		"igp":       9,
		"ip-in-ip":  4, // IANA says "ipv4"; Wikipedia/popular use says "ip-in-ip"
		"ipv4":      4,
		"ipv6-icmp": ICMPv6,
		"sctp":      SCTP,
		"tcp":       TCP,
		"tsmp":      TSMP,
		"udp":       UDP,
	}
)
