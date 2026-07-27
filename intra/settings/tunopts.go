// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package settings

import (
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/celzero/firestack/intra/core"
)

// TODO: These modes could be covered by bit-flags instead.

const (
	// DNSModeNone does not redirect DNS queries sent to the tunnel.
	DNSModeNone int32 = 0
	// DNSModeIP redirects DNS requests sent to the IP endpoint set by VPN.
	DNSModeIP int32 = 1
	// DNSModePort redirects all DNS requests on port 53.
	DNSModePort int32 = 2
)

const (
	// BlockModeNone filters no packet.
	BlockModeNone int32 = 0
	// BlockModeFilter filters packets on connection establishment.
	BlockModeFilter int32 = 1
	// BlockModeSink blackholes all packets.
	BlockModeSink int32 = 2
	// BlockModeFilterProc determines owner-uid of a tcp/udp connection
	// from procfs before filtering
	BlockModeFilterProc int32 = 3
)

const (
	// PtModeAuto does not enforce (but may still use) 6to4 protocol translation.
	PtModeAuto int32 = 0
	// PtModeForce64 enforces 6to4 protocol translation.
	PtModeForce64 int32 = 1
	// Android implements 464Xlat out-of-the-box, so this zero userspace impl
	PtModeNone int32 = 2
	// PtModeForce46 enforces 4 via 6 protocol translation.
	PtModeForce46 int32 = 3
	// PtModeForce enforces both PtModeForce64 or PtModeForce46.
	PtModeForce int32 = 4
)

// Converts a given DNS/Block/Pt mode to its string representation.
// typ is one of "dns", "block", "pt"; mode is the value to convert.
func Mode2String(typ string, mode int32) string {
	str := func() string {
		switch strings.ToLower(typ) {
		case "dns":
			switch mode {
			case DNSModeNone:
				return "none"
			case DNSModeIP:
				return "ip"
			case DNSModePort:
				return "port"
			}
		case "block":
			switch mode {
			case BlockModeNone:
				return "none"
			case BlockModeFilter:
				return "filter"
			case BlockModeSink:
				return "sink"
			case BlockModeFilterProc:
				return "filterproc"
			}
		case "pt":
			switch mode {
			case PtModeAuto:
				return "auto"
			case PtModeForce64:
				return "force64"
			case PtModeForce46:
				return "force46"
			case PtModeForce:
				return "force"
			case PtModeNone:
				return "nopt"
			}
		}
		return "unknown"
	}()
	return strings.Join([]string{typ, str, strconv.Itoa(int(mode))}, " ")
}

// DNSMode specifies the kind of DNS traffic to be trapped and routed to DoH servers
var DNSMode atomic.Int32

// BlockMode instructs change in firewall behaviour.
var BlockMode atomic.Int32

// PtMode determines 6to4 translation heuristics.
var PtMode = core.NewForeverFlow(PtModeAuto)

// SetMode re-assigns d to DNSMode, b to BlockMode, pt to PtMode.
func SetTunMode(d, b, pt int32) {
	DNSMode.Store(d)
	BlockMode.Store(b)
	PtMode.Store(pt)
}

// DefaultTunMode returns a new default TunMode with
// IP-only DNS capture and replay (not all DNS traffic but
// only the DNS traffic sent to [tcp/udp]handler.fakedns
// is captured and replayed to the remote DoH server)
// and with firewall disabled.
func DefaultTunMode() {
	SetTunMode(DNSModeIP, BlockModeNone, PtModeNone)
}

// DupTunFd instructs whether the TUN fd should be duplicated
// (netstack to own a clone of the TUN fd, and will not
// assume ownership of the TUN fd shared with it).
func DupTunFd(yn bool) (prev bool) {
	return !OwnTunFd.Swap(!yn)
}

func init() {
	DefaultTunMode()
}
