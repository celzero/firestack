// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//    ISC License
//
//    Copyright (c) 2018-2021
//    Frank Denis <j at pureftpd dot org>

package dnscrypt

const (
	// Complete : Transaction completed successfully
	Complete = iota
	// SendFailed : Failed to send query
	SendFailed
	// Error : Got no response
	Error
	// BadQuery : Malformed input
	BadQuery
	// BadResponse : Response was invalid
	BadResponse
	// InternalError : This should never happen
	InternalError
)

type dnscryptError struct {
	status int
	err    error
}

func (e *dnscryptError) Error() string {
	return e.err.Error()
}

func (e *dnscryptError) Unwrap() error {
	return e.err
}

// Summary is a summary of a DNS transaction, reported when it is complete.
type Summary struct {
	Latency     float64 // Response (or failure) latency in seconds
	Query       []byte
	Response    []byte
	Server      string
	RelayServer string
	Status      int
	Blocklists  string
}

// Listener receives Summaries.
type Listener interface {
	OnDNSCryptQuery(url string) bool
	OnDNSCryptResponse(*Summary)
}
