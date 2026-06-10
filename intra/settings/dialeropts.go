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
)

const defaultBufferSize = 2 * 1024 * 1024 // 1 MiB

// DialerOpts define dialer options.
type DialerOpts struct {
	// Strat is the dialing strategy.
	Strat int32
	// Retry is the retry strategy.
	Retry int32
	// LowerKeepAlive is the flag to enable low TCP keep-alive.
	// Currently, 600s for idle, 5s for interval, and 4 probes.
	LowerKeepAlive bool
	// Read timeout for outgoing tcp & udp connections.
	ReadTimeoutSec int32
	// Write timeout for outgoing tcp & udp connections.
	WriteTimeoutSec int32
	// Write buffer sizes for TCP and UDP
	WriteBufferSize int32
	// Read buffer sizes for TCP and UDP
	ReadBufferSize int32
}

func (d DialerOpts) String() string {
	s := func() string {
		switch d.Strat {
		case SplitAuto:
			return "SplitAuto"
		case SplitTCP:
			return "SplitTCP"
		case SplitTCPOrTLS:
			return "SplitTCPOrTLS"
		case SplitDesync:
			return "SplitDesync"
		case SplitNever:
			return "SplitNever"
		default:
			return "Unknown"
		}
	}()
	r := func() string {
		switch d.Retry {
		case RetryNever:
			return "RetryNever"
		case RetryWithSplit:
			return "RetryWithSplit"
		case RetryAfterSplit:
			return "RetryAfterSplit"
		default:
			return "Unknown"
		}
	}()
	ka := func() string {
		if d.LowerKeepAlive {
			return "LowerKeepAlive"
		}
		return "DefaultKeepAlive"
	}()
	tmo := func() string {
		return strconv.Itoa(int(d.ReadTimeoutSec)) +
			"s," + strconv.Itoa(int(d.WriteTimeoutSec)) +
			"s"
	}()

	return strings.Join([]string{s, r, ka, tmo}, ",")
}

// Dial strategies
const (
	// SplitAuto is the default dial strategy; chosen by the engine.
	SplitAuto int32 = iota
	// SplitTCPOrTLS splits first TCP segment or fragments the TLS SNI header.
	SplitTCPOrTLS
	// SplitTCP splits the first TCP segment.
	SplitTCP
	// SplitDesync splits the first TCP segment after desynchronizing the connection
	// by sending a different, but fixed, first TCP segement to the censor.
	SplitDesync
	// SplitNever doesn't muck; connects as-is.
	SplitNever
)

// Retry strategies
const (
	// RetryAfterSplit retries connection as-is after split fails.
	RetryAfterSplit int32 = iota
	// RetryWithSplit ("auto" mode) connects as-is, but retries with split.
	RetryWithSplit
	// RetryNever never retries.
	RetryNever
)

var dialerOpts atomic.Pointer[DialerOpts]

func init() {
	dialerOpts.Store(&DialerOpts{})
}

// SetDialerOpts sets the dialer options to use.
func SetDialerOpts(strat, retry, sizeBytes, timeoutsec int32, keepalive bool) bool {
	s := new(DialerOpts)
	ok := true
	switch strat {
	case SplitTCP, SplitTCPOrTLS, SplitDesync, SplitAuto, SplitNever:
		s.Strat = strat
	default:
		s.Strat = SplitAuto
		ok = false
	}
	switch retry {
	case RetryNever, RetryWithSplit, RetryAfterSplit:
		s.Retry = retry
	default:
		s.Retry = RetryAfterSplit
		ok = false
	}
	s.LowerKeepAlive = keepalive
	if timeoutsec < 0 {
		timeoutsec = 0
	}
	s.ReadTimeoutSec = timeoutsec
	s.WriteTimeoutSec = timeoutsec
	s.ReadBufferSize = min(sizeBytes, defaultBufferSize)
	s.WriteBufferSize = min(sizeBytes, defaultBufferSize)
	dialerOpts.Store(s)
	return ok
}

// GetDialerOpts returns current dialer options.
func GetDialerOpts() DialerOpts {
	return *dialerOpts.Load()
}
