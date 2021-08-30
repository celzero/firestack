// Copyright (c) 2021 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package rdns

const (
	// Complete : Transaction completed successfully
	Complete = iota
	// SendFailed : Failed to send query
	SendFailed
	// NoReponse : Got no response
	NoReponse
	// BadQuery : Malformed input
	BadQuery
	// BadResponse : Response was invalid
	BadResponse
	// InternalError : This should never happen
	InternalError
	// TransportError: Transport has issues
	TransportError
)

type QueryError struct {
	Status int
	Err    error
}

func (e *QueryError) Error() string {
	return e.Err.Error()
}

func (e *QueryError) Unwrap() error {
	return e.Err
}

// Summary is a summary of a DNS transaction, reported when it is complete.
type Summary struct {
	Latency     float64 // Response (or failure) latency in seconds
	Query       []byte
	Response    []byte
	Server      string
	RelayServer string
	Status      int    // Zero unless Status is Complete or ProxyError
	Blocklists  string // csv separated list of blocklists names, if any.
}

// Listener receives Summaries.
type Listener interface {
	OnQuery(domain string) string
	OnResponse(*Summary)
}
