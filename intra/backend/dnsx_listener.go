// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package backend

import (
	"fmt"

	"github.com/celzero/firestack/intra/core"
)

// DNSSummary is a summary of a DNS transaction, reported when it is complete.
type DNSSummary struct {
	// dnscrypt, dns53, doh, odoh, dot, preset, fixed, etc.
	Type string
	// DNS Transport ID
	ID string
	// owner uid that sent this request. May be empty.
	UID string
	// Response (or failure) latency in seconds
	Latency float64
	// Queried domain name
	QName string
	// Query type: A, AAAA, SVCB, HTTPS, etc. May be 0.
	QType int
	// CSV of all DNS aliases/names in the answer section (ex: CNAMEs)
	Targets string
	// Was this response returned from cache?
	Cached bool
	// DNS Response data, ex: a csv of ips for A, AAAA.
	RData string
	// DNS Response code
	RCode int
	// DNS Response TTL
	RTtl int
	// DNS Server (ip, ip:port, host, host:port)
	Server string
	// Proxy or a relay server address
	PID string
	// Relay server PID hops over, if any
	RPID string
	// Transport status (Start, Complete, SendFailed, NoResponse, BadQuery, BadResponse, etc)
	Status int
	// CSV of Rethink DNS+ blocklists (local or remote) names (if used).
	Blocklists string
	// Actual target (domain name) that was blocked (could be a CNAME or HTTPS/SVCB alias) by Blocklists
	BlockedTarget string
	// True if any among upstream transports (primary or secondary) returned blocked ans.
	// Only valid for A/AAAA queries. Unspecified IPs are considered as "blocked ans".
	UpstreamBlocks bool
	// True if DNSSEC OK bit is set.
	DO bool
	// True if DNSSEC validation was successful.
	AD bool
	// Diag message from Transport, if any. Typically, "no error"
	Msg string
	// Region of the Rethink DNS+ server (if used)
	Region string
}

type DNSOpts struct {
	// uid of the app (or the stub resolver) that sent this query.
	// May be ANDROID, DNS, MDNS etc instead of the actual app.
	UID string
	// csv of proxy ids to use for this query. Not all transports are proxied.
	// For instance, dnsx.System, dnsx.Local, dnsx.Goos, dnsx.Preset, dnsx.Default
	// are never proxied.
	PIDCSV string
	// csv of ips to answer for this query; incl unspecified ips, if any.
	// applicable only for A/AAAA queries.
	// if set, query bypasses on-device blocklists.
	IPCSV string
	// primary transport ids to use for this query.
	// dictated by user preferences (dnsx.Preferred, dnsx.System etc) or
	// or user set rules (dnsx.BlockAll, dnsx.BlockFree, dnsx.Fixed etc)
	TIDCSV string
	// secondary transport ids to use for this query.
	// usually, user-set DNS (dnsx.Preferred or dnsx.System) when primary is
	// dnsx.BlockFree or dnsx.Fixed. Mostly, left unset.
	TIDSECCSV string
	// If set, query bypasses on-device blocklists only, independent of whether TIDCSV
	// has dnsx.BlockFree or not. The difference is, dnsx.BlockFree if pointing to a
	// non-blocking resolver (like one.one.one.one or dns.google)
	// will bypass both on-device & upstream blocklists.
	NOBLOCK bool
}

// String implements fmt.Stringer.
func (s *DNSSummary) String() string {
	if s == nil {
		return "<nil>"
	}
	return fmt.Sprintf("id: %s (%s), t: %s, q: %s (do? %t), a: %s (cache? %t / ad? %t), code: %d, ttl: %d, by: %s / via: %s / relay: %s, status: %d, blocklists: %s / upstreamBlocks? %t, msg: %s, loc: %s",
		s.ID, s.Type, core.FmtSecsFloat(s.Latency), s.QName, s.DO, s.RData, s.Cached, s.AD, s.RCode, s.RTtl, s.Server, s.PID, s.RPID, s.Status, s.Blocklists, s.UpstreamBlocks, s.Msg, s.Region)
}

// DNSListener receives Summaries.
type DNSListener interface {
	ResolverListener
	// OnQuery is called when a DNS query is received. The listener
	// can return a DNSOpts to specify how the query should be handled.
	OnQuery(who, uid, domain string, qtyp int) *DNSOpts
	// OnUpstreamAnswer is called before an upstream DNS answer (not blocked by firestack) is sent to the OS.
	// The listener may return DNSOpts to specify if another upstream should override that answer.
	// Another round of OnQuery is NOT called in this case, and OnResponse is called once after processing
	// DNSOpts returned by OnUpstreamAnswer if it has a non-empty TIDCSV (overriding the original TIDCSV).
	OnUpstreamAnswer(smm *DNSSummary, unmodifiedipcsv string) *DNSOpts
	// OnResponse is called when a DNS response is received. May be called twice for the same query,
	// for instance, when different options are requested through OnUpstreamAnswer.
	OnResponse(*DNSSummary)
}

// args (string, string, int) is OK with cgo?
// github.com/golang/go/issues/46893#issuecomment-868749896
