// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package backend

const ( // see dnsx/transport.go
	// DNS transport types
	DOH      = "DNS-over-HTTPS"
	DNSCrypt = "DNSCrypt"
	DNS53    = "DNS"
	DOT      = "DNS-over-TLS"
	ODOH     = "Oblivious DNS-over-HTTPS"

	CT = "Cache" // cached transport prefix

	// special singleton DNS transports (IDs)
	Goos      = "Goos"      // Go determined default resolver
	System    = "System"    // network/os provided dns
	Local     = "mdns"      // mdns; never cached!
	Default   = "Default"   // default (fallback) dns
	Preferred = "Preferred" // user preferred dns, primary for alg
	Preset    = "Preset"    // synthesizes answers from presets (ex: IPs)
	BlockFree = "BlockFree" // no local blocks; if not set, default is used
	BlockAll  = "BlockAll"  // all blocks; never cached!
	Bootstrap = "Bootstrap" // bootstrap dns; always encapsulted by Default
	Alg       = "Alg"       // dns application-level gateway
	DcProxy   = "DcProxy"   // dnscrypt.Proxy as a transport
	IpMapper  = "IpMapper"  // dns resolver for dns resolvers

	SummaryProxyLabel = "proxy:"
)

const ( // from dnsx/queryerror.go
	// Start: Transaction started
	Start = iota
	// Complete : Transaction completed successfully
	Complete
	// SendFailed : Failed to send query
	SendFailed
	// NoResponse : Got no response
	NoResponse
	// BadQuery : Malformed input
	BadQuery
	// BadResponse : Response was invalid
	BadResponse
	// InternalError : This should never happen
	InternalError
	// TransportError: Transport has issues
	TransportError
	// ClientError: Client has issues
	ClientError
)

const ( // from: dnsx/rethinkdns.go
	EB32 = iota
	EB64
)

// DNSTransport exports necessary methods from dnsx.Transport
type DNSTransport interface {
	// uniquely identifies this transport
	ID() string
	// one of DNS53, DOH, DNSCrypt, System
	Type() string
	// Median round-trip time for this transport, in millis.
	P50() int64
	// Return the server host address used to initialize this transport.
	GetAddr() string
	// State of the transport after previous query (see: queryerror.go)
	Status() int
}

type DNSTransportMult interface {
	// Add adds a transport to this multi-transport.
	Add(t DNSTransport) bool
	// Remove removes a transport from this multi-transport.
	Remove(id string) bool
	// Get returns a transport from this multi-transport.
	Get(id string) (DNSTransport, error)
	// Stop stops this multi-transport.
	Stop() error
	// Refresh re-registers transports and returns a csv of active ones.
	Refresh() (string, error)
	// LiveTransports returns a csv of active transports.
	LiveTransports() string
}

type RDNS interface {
	// SetStamp sets the rethinkdns blockstamp.
	SetStamp(string) error
	// GetStamp returns the current rethinkdns blockstamp.
	GetStamp() (string, error)
	// StampToNames returns csv group:names of blocklists in the given stamp s.
	StampToNames(s string) (string, error)
	// FlagsToStamp returns a blockstamp for given csv blocklist-ids, if valid.
	FlagsToStamp(csv string, enctyp int) (string, error)
	// StampToFlags retruns csv blocklist-ids given a valid blockstamp s.
	StampToFlags(s string) (string, error)
}

type RDNSResolver interface {
	// SetRdnsLocal sets the local rdns resolver.
	SetRdnsLocal(trie, rank, conf, filetag string) error
	// GetRdnsLocal returns the local rdns resolver.
	GetRdnsLocal() (RDNS, error)
	// SetRdnsRemote sets the remote rdns resolver.
	SetRdnsRemote(filetag string) error
	// GetRdnsRemote returns the remote rdns resolver.
	GetRdnsRemote() (RDNS, error)
	// Translate enables or disables ALG responses
	Translate(bool)
}

type DNSResolver interface {
	DNSTransportMult
	RDNSResolver
}
