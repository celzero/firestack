// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dns53

import "fmt"

const (
	// Complete : Transaction completed successfully
	Complete = iota
	// SendFailed : Failed to send query
	SendFailed
	// ProxyError : Got an error from upstream
	ProxyError
	// BadQuery : Malformed input
	BadQuery
	// BadResponse : Response was invalid
	BadResponse
	// InternalError : This should never happen
	InternalError
)

type queryError struct {
	status int
	err    error
}

func (e *queryError) Error() string {
	return e.err.Error()
}

func (e *queryError) Unwrap() error {
	return e.err
}

type proxyError struct {
	status int
}

func (e *proxyError) Error() string {
	return fmt.Sprintf("proxy request fail: %d", e.status)
}

// Summary is a summary of a DNS transaction, reported when it is complete.
type Summary struct {
	Latency     float64 // Response (or failure) latency in seconds
	Query       []byte
	Response    []byte
	Server      string
	Status      int
	ProxyStatus int    // Zero unless Status is Complete or ProxyError
	Blocklists  string // csv separated list of blocklists names, if any.
}

// A Token is an opaque handle used to match responses to queries.
type Token interface{}

// Listener receives Summaries.
type Listener interface {
	OnDNSProxyQuery(ipport string) Token
	OnDNSProxyResponse(Token, *Summary)
}
