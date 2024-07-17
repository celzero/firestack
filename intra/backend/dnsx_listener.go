// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package backend

import "fmt"

// DNSSummary is a summary of a DNS transaction, reported when it is complete.
type DNSSummary struct {
	Type           string  // dnscrypt, dns53, doh, odoh, dot
	ID             string  // transport id
	Latency        float64 // Response (or failure) latency in seconds
	QName          string  // query domain
	QType          int     // A, AAAA, SVCB, HTTPS, etc.
	RData          string  // response data, usually a csv of ips
	RCode          int     // response code
	RTtl           int     // response ttl
	Server         string
	RelayServer    string // hop, if any; proxy or a relay server
	Status         int
	Blocklists     string // csv separated list of blocklists names, if any.
	UpstreamBlocks bool   // true if any among upstream transports returned blocked ans.
	Msg            string // final status message, if any
	Region         string // region of the rethinkdns server (if used)
}

type DNSOpts struct {
	// pid is the proxy to use for this query.
	PID string
	// csv of ips to answer for this query; incl unspecified.
	IPCSV string
	// csv of transports ids to use for this query.
	TIDCSV string
	// bypass on-device blocklists.
	NOBLOCK bool
}

func (s *DNSSummary) Str() string {
	return fmt.Sprintf("type: %s, id: %s, latency: %f, qname: %s, rdata: %s, rcode: %d, rttl: %d, server: %s, relay: %s, status: %d, blocklists: %s, msg: %s, loc: %s",
		s.Type, s.ID, s.Latency, s.QName, s.RData, s.RCode, s.RTtl, s.Server, s.RelayServer, s.Status, s.Blocklists, s.Msg, s.Region)
}

// DNSListener receives Summaries.
type DNSListener interface {
	ResolverListener
	// OnQuery is called when a DNS query is received. The listener
	// can return a DNSOpts to modify
	OnQuery(domain string, qtyp int) *DNSOpts
	// OnResponse is called when a DNS response is received.
	OnResponse(*DNSSummary)
}
