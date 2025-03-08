// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package backend

import "fmt"

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
	// DNS Response data, ex: a csv of ips for A, AAAA.
	RData string
	// DNS Response code
	RCode int
	// DNS Response TTL
	RTtl int
	// DNS Server (ip, ip:port, host, host:port)
	Server string
	// Hop, if any; proxy or a relay server address
	RelayServer string
	// Transport status (Start, Complete, SendFailed, NoResponse, BadQuery, BadResponse, etc)
	Status int
	// CSV of Rethink DNS+ blocklists (local or remote) names (if used).
	Blocklists string
	// True if any among upstream transports (primary or secondary) returned blocked ans.
	UpstreamBlocks bool
	// Diag message from Transport, if any. Typically, "no error"
	Msg string
	// Region of the Rethink DNS+ server (if used)
	Region string
}

type DNSOpts struct {
	// csv of proxy ids to use for this query.
	PIDCSV string
	// csv of ips to answer for this query; incl unspecified.
	IPCSV string
	// primary csv of transports ids to use for this query.
	TIDCSV string
	// secondary transport ids to use for this query.
	TIDSECCSV string
	// bypass on-device blocklists.
	NOBLOCK bool
}

// String implements fmt.Stringer.
func (s *DNSSummary) String() string {
	if s == nil {
		return "<nil>"
	}
	return fmt.Sprintf("type: %s, id: %s, latency: %f, qname: %s, rdata: %s, rcode: %d, rttl: %d, server: %s, relay: %s, status: %d, blocklists: %s, msg: %s, loc: %s",
		s.Type, s.ID, s.Latency, s.QName, s.RData, s.RCode, s.RTtl, s.Server, s.RelayServer, s.Status, s.Blocklists, s.Msg, s.Region)
}

// DNSListener receives Summaries.
type DNSListener interface {
	ResolverListener
	// OnQuery is called when a DNS query is received. The listener
	// can return a DNSOpts to modify
	OnQuery(uid, domain string, qtyp int) *DNSOpts
	// OnResponse is called when a DNS response is received.
	OnResponse(*DNSSummary)
}
